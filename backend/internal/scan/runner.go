package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// logWrite 记录后台 goroutine 中被静默吞掉的 GORM 写错误（不改变控制流，仅让失败可见）。
func logWrite(err error, ctx string) {
	if err != nil {
		log.Printf("scan: %s 失败: %v", ctx, err)
	}
}

// unmarshalTargets 反序列化 ScanJob.Targets(JSON 字符串)。
func unmarshalTargets(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// maxConcurrency 单个扫描任务内的最大并发探测数。
const maxConcurrency = 16

// Runner 执行扫描任务：解析目标、并发探测、落库、建/并资产。
type Runner struct {
	db      *gorm.DB
	scanner Scanner
	retry   RetryPolicy // 瞬态失败退避重试（超时/重置），确定性失败不重试
}

// NewRunner 构造扫描执行器。scanner 可注入以便测试替换。
func NewRunner(db *gorm.DB, scanner Scanner) *Runner {
	if scanner == nil {
		scanner = NewTLSScanner()
	}
	return &Runner{db: db, scanner: scanner, retry: defaultRetryPolicy()}
}

// NewRunnerForJob 据 job.ScannerType 装配扫描器构造执行器（①发现深化）。
func NewRunnerForJob(db *gorm.DB, scannerType string) *Runner {
	return &Runner{db: db, scanner: NewScanner(scannerType), retry: defaultRetryPolicy()}
}

// Run 同步执行一个扫描任务（通常由调用方放入 goroutine）。
//
// 任务状态机：running → done/failed。每个目标的探测结果落 ScanResult，
// 并据此自动建立或合并 CryptoAsset（去重键 Host+Port）。
func (r *Runner) Run(ctx context.Context, jobID uint) {
	var job model.ScanJob
	if err := r.db.First(&job, jobID).Error; err != nil {
		return
	}
	// TargetList 是 gorm:"-" 的非持久字段，从 DB 重新加载后为空，
	// 这里从持久化的 Targets(JSON) 反序列化补回。
	job.TargetList = unmarshalTargets(job.Targets)

	now := time.Now()
	job.Status = model.JobRunning
	job.StartedAt = &now
	job.LastRunAt = &now // 调度器/监测复扫复用此入口，留痕本次执行时间
	logWrite(r.db.Save(&job).Error, fmt.Sprintf("保存任务 %d 运行态", job.ID))

	targets := ParseTargets(job.TargetList)
	if len(targets) == 0 {
		r.finish(&job, model.JobFailed, "无有效目标")
		return
	}

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		count       int
		failed      int
		firstReason string
	)
	sem := make(chan struct{}, maxConcurrency)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()

			res, err := scanWithRetry(ctx, r.scanner, t.Host, t.Port, r.retry)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// 探测失败：记录一条 failed 结果并写明可读原因（不可达/超时/非 TLS），便于排错。
				reason := probeFailReason(err)
				if firstReason == "" {
					firstReason = reason
				}
				logWrite(r.db.Create(&model.ScanResult{
					ScanJobID: job.ID,
					Host:      t.Host,
					Port:      t.Port,
					Method:    r.scanner.Method(),
					Source:    model.SourceScan,
					Status:    "failed",
					Error:     reason,
					Raw:       fmt.Sprintf(`{"error":%q}`, err.Error()),
				}).Error, fmt.Sprintf("记录探测失败结果 %s:%d", t.Host, t.Port))
				failed++
				return
			}
			r.persistResult(&job, res)
			count++
		}(t)
	}
	wg.Wait()

	job.ResultCount = count
	// 即便有失败也置 done（任务本身跑完了），但把失败摘要写进 Error 让前端可见。
	note := ""
	if failed > 0 {
		if count == 0 {
			note = fmt.Sprintf("全部 %d 个目标探测失败，未发现密码学使用点：%s", failed, firstReason)
		} else {
			note = fmt.Sprintf("成功 %d / 失败 %d（%s）", count, failed, firstReason)
		}
	}
	r.finish(&job, model.JobDone, note)
}

// probeFailReason 把底层网络 / TLS 错误归类为人类可读的探测失败原因。
func probeFailReason(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"), strings.Contains(s, "context deadline"):
		return "连接超时（目标不可达，或被防火墙拦截；内网地址需在能路由到它的网络内运行扫描）"
	case strings.Contains(s, "connection refused"):
		return "连接被拒绝（端口未开放或无服务监听）"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return "无法路由到目标（内网/私网地址需在可达网络内扫描）"
	case strings.Contains(s, "no such host"), strings.Contains(s, "server misbehaving"):
		return "域名解析失败（host 无法解析）"
	case strings.Contains(s, "handshake"), strings.Contains(s, "first record"), strings.Contains(s, "tls:"), strings.Contains(s, "eof"):
		return "TLS 握手失败（目标可能未启用 TLS / 非 HTTPS 服务）"
	default:
		return "探测失败：" + err.Error()
	}
}

// persistResult 落库一条探测结果：填发现契约字段 + 命中规则 + 建/并资产。
//
// 增量模式（mode=incremental）下，同 fingerprint 已存在且握手特征无变化时
// 只刷 LastSeen 不新建 result（FR-3.5.5）。
func (r *Runner) persistResult(job *model.ScanJob, res *model.ScanResult) {
	res.ScanJobID = job.ID
	res.Method = r.scanner.Method()
	res.Source = model.SourceScan
	res.AssetFingerprint = AssetFingerprint(res.Host, res.Port, r.scanner.Name(), res.CertFingerprintOrEmpty())

	now := time.Now()
	// 增量：查同 fingerprint 最近一条，特征无变化只更新 LastSeen。
	if job.Mode == model.ModeIncremental && res.AssetFingerprint != "" {
		var prev model.ScanResult
		err := r.db.Where("asset_fingerprint = ?", res.AssetFingerprint).
			Order("id desc").First(&prev).Error
		if err == nil && sameHandshake(&prev, res) {
			prev.LastSeen = &now
			logWrite(r.db.Model(&model.ScanResult{}).Where("id = ?", prev.ID).Update("last_seen", &now).Error,
				fmt.Sprintf("增量刷新结果 %d LastSeen", prev.ID))
			return
		}
	}

	res.FirstSeen = &now
	res.LastSeen = &now
	logWrite(r.db.Create(res).Error, fmt.Sprintf("落库扫描结果 %s:%d", res.Host, res.Port))
	r.recordHits(res)

	asset := r.upsertAsset(res, job.Exposure)
	if asset != nil {
		res.AssetID = asset.ID
		logWrite(r.db.Save(res).Error, fmt.Sprintf("回写结果 %d 资产关联", res.ID))
		r.writeAssetEvidence(asset.ID, res) // ② 证据链：扫描入库顺带挂证据
	}
}

// evidenceSourceFor 据发现方式映射到 AssetEvidence.Source（②建档证据来源）。
func evidenceSourceFor(method string) string {
	switch method {
	case model.MethodM5Cert:
		return model.EvidenceImportPEM
	case model.MethodM4SBOM:
		return model.EvidenceImportSBOM
	case model.MethodM7Manual:
		return model.EvidenceManual
	default:
		return model.EvidenceScan
	}
}

// writeAssetEvidence 为一个资产追加一条来源证据（hash 固化；同 hash 幂等不重复）。
// 取该结果首条命中规则号作 RuleRef，便于证据下钻关联规则库（FR-4.7）。
func (r *Runner) writeAssetEvidence(assetID uint, res *model.ScanResult) {
	if assetID == 0 {
		return
	}
	raw := res.Raw
	if raw == "" {
		raw = fmt.Sprintf(`{"keyAlgo":%q,"keySize":%d,"fingerprint":%q,"method":%q}`,
			res.KeyAlgo, res.KeySize, res.AssetFingerprint, res.Method)
	}
	sum := sha256.Sum256([]byte(raw))
	h := hex.EncodeToString(sum[:])

	var n int64
	r.db.Model(&model.AssetEvidence{}).Where("asset_id = ? AND hash = ?", assetID, h).Count(&n)
	if n > 0 {
		return
	}

	ruleRef := ""
	var firstHit model.RuleHit
	if err := r.db.Where("scan_result_id = ?", res.ID).Order("rule_id asc").First(&firstHit).Error; err == nil {
		ruleRef = firstHit.RuleID
	}
	conf := model.ConfMedium
	if firstHit.Confidence != "" {
		conf = firstHit.Confidence
	}
	now := time.Now()
	logWrite(r.db.Create(&model.AssetEvidence{
		AssetID:    assetID,
		Source:     evidenceSourceFor(res.Method),
		RuleRef:    ruleRef,
		Raw:        raw,
		Hash:       h,
		Confidence: conf,
		ScannedAt:  &now,
		CreatedAt:  now,
	}).Error, fmt.Sprintf("追加资产 %d 证据", assetID))
}

// recordHits 计算并落库本条结果命中的规则（仅 Enabled 规则；FR-3.8.2 只追加）。
func (r *Runner) recordHits(res *model.ScanResult) {
	var candidates []model.RuleHit
	if m, ok := r.scanner.(HitMatcher); ok {
		candidates = m.Hits(res)
	} else {
		candidates = MatchRules(res, r.scanner.Method())
	}
	r.saveHits(res.ID, candidates)
}

// saveHits 过滤掉被禁用的规则后落库 RuleHit（供 runner 与导入路径共用）。
func (r *Runner) saveHits(scanResultID uint, candidates []model.RuleHit) {
	for _, h := range candidates {
		if !r.ruleEnabled(h.RuleID) {
			continue
		}
		h.ScanResultID = scanResultID
		h.CreatedAt = time.Now()
		logWrite(r.db.Create(&h).Error, fmt.Sprintf("落库结果 %d 规则命中 %s", scanResultID, h.RuleID))
	}
}

// ruleEnabled 判定规则当前是否启用（未知规则号视为启用，保证命中不被静默吞掉）。
func (r *Runner) ruleEnabled(ruleID string) bool {
	var rule model.ScanRule
	if err := r.db.Where("rule_id = ?", ruleID).First(&rule).Error; err != nil {
		return true
	}
	return rule.Enabled
}

// sameHandshake 判断两条结果的握手/证书特征是否一致（增量差异基准）。
func sameHandshake(a, b *model.ScanResult) bool {
	return a.TLSVersion == b.TLSVersion && a.CipherSuite == b.CipherSuite &&
		a.KeyAlgo == b.KeyAlgo && a.SigAlgo == b.SigAlgo &&
		a.CertFingerprintOrEmpty() == b.CertFingerprintOrEmpty()
}

// ImportResult 导入路径（PEM/SBOM）落库一条结果 + 命中规则 + 建/并资产。
//
// res 须已填 Method/Source/AssetFingerprint 与解析出的算法/证书字段；
// candidates 为该结果的候选命中规则（导入路径自带，不再走 scanner.Hits）。
// exposure 透传暴露面（导入默认 internal）。返回落库后的 ScanResult 指针。
func (r *Runner) ImportResult(jobID uint, res *model.ScanResult, candidates []model.RuleHit, exposure string) *model.ScanResult {
	res.ScanJobID = jobID
	res.FirstSeen = nowPtr()
	res.LastSeen = nowPtr()
	logWrite(r.db.Create(res).Error, fmt.Sprintf("导入落库结果（任务 %d）", jobID))
	r.saveHits(res.ID, candidates)

	asset := r.upsertImportedAsset(res, exposure)
	if asset != nil {
		res.AssetID = asset.ID
		logWrite(r.db.Save(res).Error, fmt.Sprintf("回写导入结果 %d 资产关联", res.ID))
		r.writeAssetEvidence(asset.ID, res) // ② 证据链：导入入库顺带挂证据
	}
	return res
}

// ImportPassive M2 被动流量路径：落库一条观测 + 建/并资产。
//
// 与 ImportResult 的差异：M2 观测自带 host:port，去重键用 endpoint（同扫描口径，
// 走 upsertAsset 而非按证书指纹的 upsertImportedAsset），命中新增的 idx_ca_endpoint 唯一索引。
func (r *Runner) ImportPassive(jobID uint, res *model.ScanResult, candidates []model.RuleHit, exposure string) *model.ScanResult {
	res.ScanJobID = jobID
	res.FirstSeen = nowPtr()
	res.LastSeen = nowPtr()
	logWrite(r.db.Create(res).Error, fmt.Sprintf("被动导入落库结果（任务 %d）", jobID))
	r.saveHits(res.ID, candidates)

	asset := r.upsertAsset(res, exposure) // 按 endpoint 去重
	if asset != nil {
		res.AssetID = asset.ID
		logWrite(r.db.Save(res).Error, fmt.Sprintf("回写被动结果 %d 资产关联", res.ID))
		r.writeAssetEvidence(asset.ID, res)
	}
	return res
}

// upsertImportedAsset 据导入结果建/并资产。证书类无 host:port，去重键退化为 cert 指纹。
func (r *Runner) upsertImportedAsset(res *model.ScanResult, exposure string) *model.CryptoAsset {
	if exposure == "" {
		exposure = model.ExposureInternal
	}
	// 优先按 fingerprint 找已存在资产（②建档合并锚点）；再退化按证书指纹。
	var asset model.CryptoAsset
	var err error
	if res.CertFingerprint != "" {
		err = r.db.Where("cert_fingerprint = ?", res.CertFingerprint).First(&asset).Error
	} else {
		err = gorm.ErrRecordNotFound
	}

	layer := model.LayerL2 // 证书导入归 L2 协议/传输层（PKI）
	authSafety := cryptoref.AuthSafetyForAlgo(res.KeyAlgo)
	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  res.KeyAlgo,
		KeySize:    res.KeySize,
		TLSVersion: res.TLSVersion,
		Exposure:   exposure,
		Layer:      layer,
		LongLived:  certLongLived(res.CertNotAfter),
		AuthSafety: authSafety,
	})
	result := scoring.Score(dims)

	apply := func(a *model.CryptoAsset) {
		name := res.CertSubject
		if name == "" {
			name = "导入证书"
		}
		a.Name = name
		a.Algorithm = res.KeyAlgo
		a.KeySize = res.KeySize
		a.CertNotAfter = res.CertNotAfter
		a.CertFingerprint = res.CertFingerprint
		a.Source = model.SourceImport
		a.Exposure = exposure
		a.Layer = layer
		a.Confidence = 90 // 证书机读直证
		a.D1, a.D2, a.D3, a.D4, a.D5 = dims.D1, dims.D2, dims.D3, dims.D4, dims.D5
		a.RiskScore = result.Score
		a.RawScore = result.RawScore
		a.RiskLevel = result.Level
		a.RiskLevelText = result.LevelText
		a.AuthSafety = authSafety
		// 证书导入不带 KEX 观测（a.KexSafety 新资产为空→行为不变）；按证书指纹合并到
		// 已有混合 KEX 资产时，沿用资产自身的 KexSafety 保持 HNDL 清除不回退。
		a.HNDL = cryptoref.EffectiveHNDL(result.HNDL, a.KexSafety)
		a.SuggestedAlgo = scoring.SuggestAlgo(res.KeyAlgo)
		a.RiskHint = fmt.Sprintf("%s 综合风险 %d(%s) 建议迁移窗口 %s",
			res.KeyAlgo, result.Score, result.LevelText, result.Window)
	}

	if err == gorm.ErrRecordNotFound {
		asset = model.CryptoAsset{System: "证书导入", Status: model.StatusDiscovered}
		apply(&asset)
		logWrite(r.db.Create(&asset).Error, "新建导入证书资产")
	} else if err == nil {
		apply(&asset)
		logWrite(r.db.Save(&asset).Error, fmt.Sprintf("合并导入证书资产 %d", asset.ID))
	} else {
		return nil
	}
	return &asset
}

// finish 收尾：写终态、完成时间、结果数与错误信息。
func (r *Runner) finish(job *model.ScanJob, status, errMsg string) {
	fin := time.Now()
	job.Status = status
	job.Error = errMsg
	job.FinishedAt = &fin
	logWrite(r.db.Save(job).Error, fmt.Sprintf("保存任务 %d 终态 %s", job.ID, status))
}

// upsertAsset 据扫描结果建立或合并 CryptoAsset（去重键 Host+Port）。
func (r *Runner) upsertAsset(res *model.ScanResult, exposure string) *model.CryptoAsset {
	if exposure == "" {
		exposure = model.ExposureInternal
	}
	endpoint := fmt.Sprintf("%s:%d", res.Host, res.Port)

	// 先加载既有资产：跨源合并要用既有 PQC 观测参与 effective 值解析，再算分（FIX 4）。
	var asset model.CryptoAsset
	err := r.db.Where("endpoint = ?", endpoint).First(&asset).Error

	// effective KEX 字段：本次结果观测到组则用之；未观测（M1 主动扫描器不带组信息）
	// 则保留既有资产的被动/主动发现，避免主动重扫抹除 M2 被动观测（同 CertFingerprint 保护模式）。
	effKexGroup, effKexSafety := res.KexGroup, res.KexSafety
	if effKexGroup == "" && err == nil && asset.KexGroup != "" {
		effKexGroup, effKexSafety = asset.KexGroup, asset.KexSafety
	}
	// 观测层的 KexSafety 判定权威（码点+尺寸兜底在观测处已定），名字反查仅作未提供时的兜底——
	// 否则 "unknown-" 前缀的保守 hybrid 兜底会把观测为 classical 的端点跨 ScanResult 升级成 hybrid。
	if effKexSafety == "" {
		effKexSafety = cryptoref.SafetyForGroupName(effKexGroup) // 空组 → na
	}
	authSafety := cryptoref.AuthSafetyForAlgo(res.KeyAlgo)
	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  res.KeyAlgo,
		KeySize:    res.KeySize,
		TLSVersion: res.TLSVersion,
		Exposure:   exposure,
		Layer:      model.LayerL1, // 扫描发现默认归为 L1 应用/会话层
		LongLived:  certLongLived(res.CertNotAfter),
		KexSafety:  effKexSafety, // D1 与最终写入的 KexSafety 一致
		AuthSafety: authSafety,
	})
	result := scoring.Score(dims)

	apply := func(a *model.CryptoAsset) {
		a.Name = res.CertSubject
		if a.Name == "" {
			a.Name = endpoint
		}
		a.Endpoint = endpoint
		a.Algorithm = res.KeyAlgo
		a.KeySize = res.KeySize
		a.Protocol = res.TLSVersion
		a.CertNotAfter = res.CertNotAfter
		if res.CertFingerprint != "" {
			a.CertFingerprint = res.CertFingerprint
		}
		a.Source = model.SourceScan
		a.Exposure = exposure
		a.Layer = model.LayerL1
		a.Confidence = 90
		a.D1, a.D2, a.D3, a.D4, a.D5 = dims.D1, dims.D2, dims.D3, dims.D4, dims.D5
		a.RiskScore = result.Score
		a.RawScore = result.RawScore
		a.RiskLevel = result.Level
		a.RiskLevelText = result.LevelText
		a.KexGroup = effKexGroup
		a.KexSafety = effKexSafety
		a.AuthSafety = authSafety // 认证维每次按本结果证书算法更新（主动扫描可观测变化）
		a.HNDL = cryptoref.EffectiveHNDL(result.HNDL, effKexSafety) // KEX 已迁移→清 HNDL（共享策略）
		a.SuggestedAlgo = scoring.SuggestAlgo(res.KeyAlgo)
		a.RiskHint = fmt.Sprintf("%s/%s 综合风险 %d(%s) 建议迁移窗口 %s",
			res.KeyAlgo, res.TLSVersion, result.Score, result.LevelText, result.Window)
	}

	if err == gorm.ErrRecordNotFound {
		asset = model.CryptoAsset{System: "扫描发现", Status: model.StatusDiscovered}
		apply(&asset)
		logWrite(r.db.Create(&asset).Error, fmt.Sprintf("新建扫描资产 %s", endpoint))
	} else if err == nil {
		// 已存在：合并刷新探测到的字段（保留人工已确认状态）。
		apply(&asset)
		logWrite(r.db.Save(&asset).Error, fmt.Sprintf("合并扫描资产 %d", asset.ID))
	} else {
		return nil
	}
	return &asset
}
