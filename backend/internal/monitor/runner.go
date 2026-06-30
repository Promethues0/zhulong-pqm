package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// logWrite 记录后台 goroutine 中被静默吞掉的 GORM 写错误（不改变控制流，仅让失败可见）。
func logWrite(err error, ctx string) {
	if err != nil {
		log.Printf("monitor: %s 失败: %v", ctx, err)
	}
}

// stepPause 复扫资产间的停顿，让前端轮询观察到逐步生成的事件（与 remediate.stepPause 同构）。
const stepPause = 300 * time.Millisecond

// RunSummary 一次复扫的结果摘要（POST /run 返回 + 日志）。
type RunSummary struct {
	PolicyID    uint `json:"policyId"`
	AssetCount  int  `json:"assetCount"`  // 复扫覆盖资产数
	ProbedCount int  `json:"probedCount"` // 真实探测成功数
	EventCount  int  `json:"eventCount"`  // 本次生成事件总数
	P1Count     int  `json:"p1Count"`     // P1 漂移事件数
	CertCount   int  `json:"certCount"`   // 证书到期事件数
	DriftCount  int  `json:"driftCount"`  // 漂移事件数
	ReassessCount int `json:"reassessCount"` // 触发复评数
	SLOPoints   int  `json:"sloPoints"`   // 写入 SLO 时序点数
}

// Runner 监测复扫执行器：照搬 scan.Runner 异步骨架（同步 Run 由 goroutine/调度器调用），
// 复用 scan TLS 探测做漂移检测，逐资产落事件供前端轮询。
type Runner struct {
	db      *gorm.DB
	scanner scan.Scanner
}

// NewRunner 构造监测复扫执行器；scanner 可注入以便测试替换（默认 TLS 探测器）。
func NewRunner(gdb *gorm.DB, scanner scan.Scanner) *Runner {
	if scanner == nil {
		scanner = scan.NewTLSScanner()
	}
	return &Runner{db: gdb, scanner: scanner}
}

// Run 同步执行一次复扫（通常由调用方放入 goroutine 或调度器触发）。
//
// 流程：① 按策略 Scope 取纳管资产 → ② 逐资产复扫（有 endpoint 真实 TLS 探测，否则合成）→
// ③ 漂移判定 + 证书到期分级预警 + SLO 合成点 → ④ 混合回退 P1 立即复评回灌。
// 全程离线/无 endpoint 一律诚实标 synthetic，绝不 5xx。
func (r *Runner) Run(ctx context.Context, policyID uint) RunSummary {
	sum := RunSummary{PolicyID: policyID}

	var p model.MonitorPolicy
	if err := r.db.First(&p, policyID).Error; err != nil {
		return sum
	}

	now := time.Now()
	p.LastRunAt = &now
	p.NextRunAt = nextRunAfter(&p, now)
	logWrite(r.db.Model(&p).Updates(map[string]any{
		"last_run_at": p.LastRunAt,
		"next_run_at": p.NextRunAt,
	}).Error, fmt.Sprintf("刷新策略 %d 运行时刻", p.ID))

	assets := r.scopedAssets(&p)
	sum.AssetCount = len(assets)

	for i := range assets {
		select {
		case <-ctx.Done():
			return sum
		default:
		}
		a := assets[i]
		r.rescanAsset(ctx, &p, &a, &sum)
		time.Sleep(stepPause)
	}
	return sum
}

// scopedAssets 据策略 Scope 取资产；优先纳管态（accepted/monitored/verified/remediated），
// 演示态退化为全量（保证空库/未纳管时仍可复扫出事件）。
func (r *Runner) scopedAssets(p *model.MonitorPolicy) []model.CryptoAsset {
	q := r.db.Model(&model.CryptoAsset{})
	switch p.ScopeKind {
	case model.ScopeLayer:
		if p.ScopeValue != "" {
			q = q.Where("layer = ?", p.ScopeValue)
		}
	case model.ScopeExposure:
		if p.ScopeValue != "" {
			q = q.Where("exposure = ?", p.ScopeValue)
		}
	case model.ScopeAssetIDs:
		var ids []uint
		_ = json.Unmarshal([]byte(p.ScopeValue), &ids)
		if len(ids) > 0 {
			q = q.Where("id IN ?", ids)
		}
	}
	var assets []model.CryptoAsset
	q.Find(&assets)
	return assets
}

// rescanAsset 对单个资产复扫：漂移检测 + 证书预警 + SLO 合成 + P1 复评。
func (r *Runner) rescanAsset(ctx context.Context, p *model.MonitorPolicy, a *model.CryptoAsset, sum *RunSummary) {
	prevAlgo := a.Algorithm
	// 「已迁混合」判定仅看资产当前算法是否为混合（SuggestedAlgo 只是迁移建议，
	// 未迁资产不应误判为漂移回退）——避免对仅有建议的经典资产误报 P1。
	prevWasHybrid := IsHybrid(a.Algorithm)

	// 1) 真实 TLS 探测（有 endpoint 时）；探测失败/无 endpoint → 合成态，沿用已知算法。
	nowAlgo := prevAlgo
	probed := false
	// 快照复扫前的证书到期时间：writeBackAsset 会就地改写 a.CertNotAfter，
	// 故须在回写前留存旧值，否则 certRenewed 永远拿到相等的新值（恒 false）。
	prevCertNotAfter := a.CertNotAfter
	var newCertNotAfter *time.Time = a.CertNotAfter
	if a.Endpoint != "" {
		if host, port, ok := parseEndpoint(a.Endpoint); ok {
			if res, err := r.scanner.Scan(ctx, host, port); err == nil && res != nil {
				probed = true
				sum.ProbedCount++
				if res.KeyAlgo != "" {
					nowAlgo = res.KeyAlgo
				}
				if res.CertNotAfter != nil {
					newCertNotAfter = res.CertNotAfter
				}
				// 复扫回写资产探测字段（CBOM 回写：算法/协议/证书）。
				r.writeBackAsset(a, res)
			}
		}
	}

	// 2) 漂移判定。
	dk := classifyDrift(prevAlgo, nowAlgo, prevWasHybrid)
	switch dk {
	case driftHybridToClassic:
		r.emitDriftP1(p, a, prevAlgo, nowAlgo, probed, sum)
	case driftNewVulnerable:
		r.emitDriftWarning(a, prevAlgo, nowAlgo, probed, sum)
	}

	// 3) 证书续期/更换 → cbom_diff 事件（指纹/到期变化）。
	if certRenewed(prevCertNotAfter, newCertNotAfter, prevAlgo, nowAlgo, dk) {
		r.emitCertRenewed(a, sum)
	}

	// 4) 证书到期分级预警（FR-7.9，读 CertNotAfter）。
	r.checkCertExpiry(p, a, sum)

	// 5) SLO 合成时序点（演示态：基线附近抖动，诚实标 synthetic）。
	r.synthSLO(p, a, sum)
}

// writeBackAsset 复扫结果回写资产探测字段（算法/协议/证书到期），保留人工已确认状态。
func (r *Runner) writeBackAsset(a *model.CryptoAsset, res *model.ScanResult) {
	if res.KeyAlgo != "" {
		a.Algorithm = res.KeyAlgo
	}
	if res.TLSVersion != "" {
		a.Protocol = res.TLSVersion
	}
	if res.KeySize > 0 {
		a.KeySize = res.KeySize
	}
	if res.CertNotAfter != nil {
		a.CertNotAfter = res.CertNotAfter
	}
	logWrite(r.db.Model(a).Updates(map[string]any{
		"algorithm":      a.Algorithm,
		"protocol":       a.Protocol,
		"key_size":       a.KeySize,
		"cert_not_after": a.CertNotAfter,
	}).Error, fmt.Sprintf("回写资产 %d 复扫字段", a.ID))
}

// emitDriftP1 混合→经典回退：P1 漂移事件 + SLO-05 告警，并立即触发复评回灌（C5）。
func (r *Runner) emitDriftP1(p *model.MonitorPolicy, a *model.CryptoAsset, prevAlgo, nowAlgo string, probed bool, sum *RunSummary) {
	ev := r.newEvent(model.EventDrift, model.SevP1, a)
	ev.RuleSLO = model.SLO05Drift
	ev.Title = fmt.Sprintf("密码漂移：已迁混合端点回退为经典算法 %s", nowAlgo)
	ev.Evidence = map[string]string{
		"before":   prevAlgo,
		"after":    nowAlgo,
		"endpoint": a.Endpoint,
		"evidence": evidenceTag(probed),
	}
	ev.Detail = fmt.Sprintf("资产「%s」期望混合算法，复扫得纯经典 %s（%s）。SLO-05 目标=0，检出即 P1 并触发复评。",
		a.Name, nowAlgo, evidenceTag(probed))
	r.saveEvent(ev)
	sum.EventCount++
	sum.DriftCount++
	sum.P1Count++

	// 复评回灌：重评分 + ScoreHistory(reassess) + 资产回退态。
	reassessed, hist, err := Reassess(r.db, a.ID, "system", "drift-p1")
	if err == nil {
		taskID := hist.ID
		ev.ReassessTaskID = &taskID
		ev.Detail += " " + reassessSummary(reassessed, hist)
		logWrite(r.db.Model(ev).Updates(map[string]any{
			"reassess_task_id": ev.ReassessTaskID,
			"detail":           ev.Detail,
		}).Error, fmt.Sprintf("回灌事件 %d 复评结果", ev.ID))
		sum.ReassessCount++
		*a = *reassessed
	}
}

// emitDriftWarning 新增未纳管脆弱使用点 → warning 漂移事件。
func (r *Runner) emitDriftWarning(a *model.CryptoAsset, prevAlgo, nowAlgo string, probed bool, sum *RunSummary) {
	ev := r.newEvent(model.EventDrift, model.SevWarning, a)
	ev.RuleSLO = model.SLO05Drift
	ev.Title = fmt.Sprintf("新增脆弱算法使用点：%s", nowAlgo)
	ev.Evidence = map[string]string{"before": prevAlgo, "after": nowAlgo, "evidence": evidenceTag(probed)}
	ev.Detail = fmt.Sprintf("资产「%s」复扫发现新增经典脆弱算法 %s（%s），建议纳管评估。", a.Name, nowAlgo, evidenceTag(probed))
	r.saveEvent(ev)
	sum.EventCount++
	sum.DriftCount++
}

// emitCertRenewed 证书续期/更换 → cbom_diff 事件（巡检级）。
func (r *Runner) emitCertRenewed(a *model.CryptoAsset, sum *RunSummary) {
	ev := r.newEvent(model.EventCBOMDiff, model.SevInspect, a)
	ev.Title = "证书续期/更换"
	ev.Detail = fmt.Sprintf("资产「%s」证书已续期/更换，CBOM 将随复扫更新。", a.Name)
	if a.CertNotAfter != nil {
		ev.Evidence = map[string]string{"newNotAfter": a.CertNotAfter.Format(time.RFC3339)}
	}
	r.saveEvent(ev)
	sum.EventCount++
}

// checkCertExpiry 证书到期分级预警（FR-7.9，SLO-06）：读 CertNotAfter，按分级提前量生成事件。
func (r *Runner) checkCertExpiry(p *model.MonitorPolicy, a *model.CryptoAsset, sum *RunSummary) {
	if a.CertNotAfter == nil {
		return
	}
	cl := classifyCert(a)
	warnDays := warnDaysFor(cl, p)
	left := daysUntil(*a.CertNotAfter)
	if left > warnDays {
		return
	}

	// 本轮严重度（上移到去重判断前，以便对现存事件做升级判定）。
	sev := model.SevWarning
	if left < 0 || left <= warnDays/3 {
		sev = model.SevP1 // 已过期或临近 1/3 提前量内升级为红
	}

	label := certClassLabel(cl)
	leftDesc := fmt.Sprintf("剩余 %d 天", left)
	if left < 0 {
		leftDesc = fmt.Sprintf("已过期 %d 天", -left)
	}
	title := fmt.Sprintf("%s到期预警（%s）", label, leftDesc)
	detail := fmt.Sprintf("资产「%s」%s，提前量 %d 天，到期 %s。",
		a.Name, leftDesc, warnDays, a.CertNotAfter.Format("2006-01-02"))
	if !hasOTA(a, cl) {
		detail += " 无 OTA 能力，需现场检修替换（关联 R-003）。"
	}
	evidence := map[string]string{
		"certClass": label,
		"daysLeft":  fmt.Sprintf("%d", left),
		"warnDays":  fmt.Sprintf("%d", warnDays),
		"notAfter":  a.CertNotAfter.Format(time.RFC3339),
	}

	// 去重 + 升级：查同资产同类已 open 的 cert_expiry。
	// 不存在则新建；存在但严重度低于本轮（warning<p1）则就地升级，否则跳过。
	var existing model.MonitorEvent
	err := r.db.Where("kind = ? AND asset_id = ? AND status = ?",
		model.EventCertExpiry, a.ID, model.MonOpen).
		Order("occurred_at desc").First(&existing).Error
	if err == nil {
		if certSevRank(sev) > certSevRank(existing.Severity) {
			existing.Severity = sev
			existing.Title = title
			existing.Detail = detail
			existing.Evidence = evidence
			logWrite(r.db.Model(&existing).Updates(map[string]any{
				"severity": existing.Severity,
				"title":    existing.Title,
				"detail":   existing.Detail,
				"evidence": db.MarshalMonEvidence(existing.Evidence),
			}).Error, fmt.Sprintf("升级证书到期事件 %d 严重度", existing.ID))
		}
		return
	}

	ev := r.newEvent(model.EventCertExpiry, sev, a)
	ev.RuleSLO = model.SLO06CertExpiry
	ev.Title = title
	ev.Detail = detail
	ev.Evidence = evidence
	r.saveEvent(ev)
	sum.EventCount++
	sum.CertCount++
}

// certSevRank 证书预警严重度排序（用于升级判定）：inspect<warning<p1。
func certSevRank(sev string) int {
	switch sev {
	case model.SevP1:
		return 2
	case model.SevWarning:
		return 1
	default:
		return 0
	}
}

// synthSLO 合成 SLO-01/02 时序点（演示态：基线附近抖动，诚实标 source=synthetic）。
// 无真实网关遥测时由复扫合成，越阈即生成 slo_breach 事件（连续窗口判定见 slo.go）。
func (r *Runner) synthSLO(p *model.MonitorPolicy, a *model.CryptoAsset, sum *RunSummary) {
	now := time.Now()
	// SLO-02 p99 延迟：基线 39.5ms，抖动 ±3ms（不越 46.2 阈值，演示正常态）。
	p99 := 39.5 + jitter(a.ID, 6.0) - 3.0
	IngestSLO(r.db, model.SLOMetric{
		SLOCode:   model.SLO02LatencyP99,
		AssetID:   &a.ID,
		Value:     round1(p99),
		Threshold: p.LatencyP99CeilMs,
		Baseline:  39.5,
		Unit:      "ms",
		Source:    "synthetic",
		SampledAt: now,
	}, p)
	sum.SLOPoints++

	// SLO-01 握手失败率：基线 0.02%，抖动 0~0.06%（不越 0.1% 阈值）。
	fail := jitter(a.ID+7, 0.06)
	IngestSLO(r.db, model.SLOMetric{
		SLOCode:   model.SLO01HandshakeFail,
		AssetID:   &a.ID,
		Value:     round2(fail),
		Threshold: p.HandshakeFailThreshold,
		Baseline:  0.02,
		Unit:      "pct",
		Source:    "synthetic",
		SampledAt: now,
	}, p)
	sum.SLOPoints++
}

// newEvent 构造一条监测事件骨架（带资产关联与发生时刻）。
func (r *Runner) newEvent(kind, sev string, a *model.CryptoAsset) *model.MonitorEvent {
	ev := &model.MonitorEvent{
		Kind:       kind,
		Severity:   sev,
		Status:     model.MonOpen,
		OccurredAt: time.Now(),
	}
	if a != nil {
		id := a.ID
		ev.AssetID = &id
	}
	return ev
}

// saveEvent 序列化证据并落库。
func (r *Runner) saveEvent(ev *model.MonitorEvent) {
	ev.EvidenceJSON = db.MarshalMonEvidence(ev.Evidence)
	logWrite(r.db.Create(ev).Error, fmt.Sprintf("落库监测事件 %s/%s", ev.Kind, ev.Severity))
}

// ---- 小工具 ----

func parseEndpoint(ep string) (string, int, bool) {
	targets := scan.ParseTargets([]string{ep})
	if len(targets) == 0 {
		return "", 0, false
	}
	return targets[0].Host, targets[0].Port, true
}

func evidenceTag(probed bool) string {
	if probed {
		return "probe"
	}
	return "synthetic"
}

// certRenewed 判定证书是否续期/更换（到期时间变化且非漂移事件，避免与漂移重复报）。
func certRenewed(prev, now *time.Time, prevAlgo, nowAlgo string, dk driftKind) bool {
	if dk != driftNone {
		return false
	}
	if prev == nil || now == nil {
		return false
	}
	return !prev.Equal(*now)
}

// jitter 由 seed 派生一个 [0,scale) 的确定性抖动（无随机依赖，便于复现与测试）。
func jitter(seed uint, scale float64) float64 {
	v := (seed*2654435761 + 12345) % 1000
	return float64(v) / 1000.0 * scale
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }

// algoFamilyMatch 判定资产算法是否命中情报受影响算法族（情报复评用）。
func algoFamilyMatch(assetAlgo string, families []string) bool {
	a := strings.ToUpper(assetAlgo)
	for _, f := range families {
		if f == "" {
			continue
		}
		if strings.Contains(a, strings.ToUpper(f)) {
			return true
		}
	}
	return false
}
