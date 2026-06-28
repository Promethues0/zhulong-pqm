package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

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
}

// NewRunner 构造扫描执行器。scanner 可注入以便测试替换。
func NewRunner(db *gorm.DB, scanner Scanner) *Runner {
	if scanner == nil {
		scanner = NewTLSScanner()
	}
	return &Runner{db: db, scanner: scanner}
}

// NewRunnerForJob 据 job.ScannerType 装配扫描器构造执行器（①发现深化）。
func NewRunnerForJob(db *gorm.DB, scannerType string) *Runner {
	return &Runner{db: db, scanner: NewScanner(scannerType)}
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
	r.db.Save(&job)

	targets := ParseTargets(job.TargetList)
	if len(targets) == 0 {
		r.finish(&job, model.JobFailed, "无有效目标")
		return
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		count int
	)
	sem := make(chan struct{}, maxConcurrency)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()

			res, err := r.scanner.Scan(ctx, t.Host, t.Port)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// 探测失败的目标也记录一条空结果，便于审计与排错。
				failed := &model.ScanResult{
					ScanJobID: job.ID,
					Host:      t.Host,
					Port:      t.Port,
					Method:    r.scanner.Method(),
					Source:    model.SourceScan,
					Raw:       fmt.Sprintf(`{"error":%q,"simulated":true}`, err.Error()),
				}
				r.db.Create(failed)
				return
			}
			r.persistResult(&job, res)
			count++
		}(t)
	}
	wg.Wait()

	job.ResultCount = count
	r.finish(&job, model.JobDone, "")
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
			r.db.Model(&model.ScanResult{}).Where("id = ?", prev.ID).Update("last_seen", &now)
			return
		}
	}

	res.FirstSeen = &now
	res.LastSeen = &now
	r.db.Create(res)
	r.recordHits(res)

	asset := r.upsertAsset(res, job.Exposure)
	if asset != nil {
		res.AssetID = asset.ID
		r.db.Save(res)
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
	r.db.Create(&model.AssetEvidence{
		AssetID:    assetID,
		Source:     evidenceSourceFor(res.Method),
		RuleRef:    ruleRef,
		Raw:        raw,
		Hash:       h,
		Confidence: conf,
		ScannedAt:  &now,
		CreatedAt:  now,
	})
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
		r.db.Create(&h)
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
	r.db.Create(res)
	r.saveHits(res.ID, candidates)

	asset := r.upsertImportedAsset(res, exposure)
	if asset != nil {
		res.AssetID = asset.ID
		r.db.Save(res)
		r.writeAssetEvidence(asset.ID, res) // ② 证据链：导入入库顺带挂证据
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
	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  res.KeyAlgo,
		KeySize:    res.KeySize,
		TLSVersion: res.TLSVersion,
		Exposure:   exposure,
		Layer:      layer,
		LongLived:  certLongLived(res.CertNotAfter),
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
		a.HNDL = result.HNDL
		a.SuggestedAlgo = scoring.SuggestAlgo(res.KeyAlgo)
		a.RiskHint = fmt.Sprintf("%s 综合风险 %d(%s) 建议迁移窗口 %s",
			res.KeyAlgo, result.Score, result.LevelText, result.Window)
	}

	if err == gorm.ErrRecordNotFound {
		asset = model.CryptoAsset{System: "证书导入", Status: model.StatusDiscovered}
		apply(&asset)
		r.db.Create(&asset)
	} else if err == nil {
		apply(&asset)
		r.db.Save(&asset)
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
	r.db.Save(job)
}

// upsertAsset 据扫描结果建立或合并 CryptoAsset（去重键 Host+Port）。
func (r *Runner) upsertAsset(res *model.ScanResult, exposure string) *model.CryptoAsset {
	if exposure == "" {
		exposure = model.ExposureInternal
	}
	endpoint := fmt.Sprintf("%s:%d", res.Host, res.Port)

	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  res.KeyAlgo,
		KeySize:    res.KeySize,
		TLSVersion: res.TLSVersion,
		Exposure:   exposure,
		Layer:      model.LayerL1, // 扫描发现默认归为 L1 应用/会话层
		LongLived:  certLongLived(res.CertNotAfter),
	})
	result := scoring.Score(dims)

	var asset model.CryptoAsset
	err := r.db.Where("endpoint = ?", endpoint).First(&asset).Error

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
		a.HNDL = result.HNDL
		a.SuggestedAlgo = scoring.SuggestAlgo(res.KeyAlgo)
		a.RiskHint = fmt.Sprintf("%s/%s 综合风险 %d(%s) 建议迁移窗口 %s",
			res.KeyAlgo, res.TLSVersion, result.Score, result.LevelText, result.Window)
	}

	if err == gorm.ErrRecordNotFound {
		asset = model.CryptoAsset{System: "扫描发现", Status: model.StatusDiscovered}
		apply(&asset)
		r.db.Create(&asset)
	} else if err == nil {
		// 已存在：合并刷新探测到的字段（保留人工已确认状态）。
		apply(&asset)
		r.db.Save(&asset)
	} else {
		return nil
	}
	return &asset
}
