package monitor

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// breachWindow 连续窗口判定的样本数：最近 N 个样本全部越界才告警，避免单点抖动误报
// （PRD「连续窗口 ≥0.1%」「持续超」口径）。
const breachWindow = 3

// BreachWindow 导出版连续窗口样本数（API 层响应回显用）。
const BreachWindow = breachWindow

// IngestSLO 追加一个 SLO 时序点并做越界 + 连续窗口判定。
//
// 写入前据 SLOCode 方向判定 Breached（失败率/延迟/降幅/建立时间均为「越大越坏」，> 阈值即越界）。
// 写入后取该 (SLOCode, AssetID) 最近 breachWindow 个样本，全部 Breached 才生成一条 slo_breach 事件
// （同一 SLO+资产已有 open 的 slo_breach 不重复生成）。
func IngestSLO(gdb *gorm.DB, m model.SLOMetric, p *model.MonitorPolicy) {
	if m.SampledAt.IsZero() {
		m.SampledAt = time.Now()
	}
	if m.Threshold == 0 && p != nil {
		m.Threshold = thresholdFor(m.SLOCode, p)
	}
	m.Breached = m.Value > m.Threshold
	gdb.Create(&m)

	if !m.Breached {
		return
	}
	// 连续窗口判定。
	var recent []model.SLOMetric
	q := gdb.Model(&model.SLOMetric{}).Where("slo_code = ?", m.SLOCode)
	if m.AssetID != nil {
		q = q.Where("asset_id = ?", *m.AssetID)
	} else {
		q = q.Where("asset_id IS NULL")
	}
	q.Order("sampled_at desc").Limit(breachWindow).Find(&recent)
	if len(recent) < breachWindow {
		return
	}
	for _, r := range recent {
		if !r.Breached {
			return
		}
	}

	// 去重：同 SLO+资产已有 open 的 slo_breach 不重复。
	var existing int64
	eq := gdb.Model(&model.MonitorEvent{}).
		Where("kind = ? AND status = ? AND rule_slo = ?", model.EventSLOBreach, model.MonOpen, m.SLOCode)
	if m.AssetID != nil {
		eq = eq.Where("asset_id = ?", *m.AssetID)
	} else {
		eq = eq.Where("asset_id IS NULL")
	}
	eq.Count(&existing)
	if existing > 0 {
		return
	}

	emitSLOBreach(gdb, m)
}

// emitSLOBreach 生成一条 SLO 越界告警（warning 级；可由处置人升级）。
func emitSLOBreach(gdb *gorm.DB, m model.SLOMetric) {
	ev := &model.MonitorEvent{
		Kind:       model.EventSLOBreach,
		Severity:   model.SevWarning,
		Status:     model.MonOpen,
		RuleSLO:    m.SLOCode,
		AssetID:    m.AssetID,
		Title:      fmt.Sprintf("%s 连续越界（%s%s > 阈值 %s%s）", m.SLOCode, fmtVal(m.Value), m.Unit, fmtVal(m.Threshold), m.Unit),
		OccurredAt: time.Now(),
		Evidence: map[string]string{
			"sloCode":   m.SLOCode,
			"value":     fmtVal(m.Value),
			"threshold": fmtVal(m.Threshold),
			"baseline":  fmtVal(m.Baseline),
			"unit":      m.Unit,
			"window":    fmt.Sprintf("%d", breachWindow),
			"source":    m.Source,
		},
		Detail: fmt.Sprintf("SLO %s 连续 %d 个样本越界（实测 %s%s，阈值 %s%s，基线 %s%s，来源 %s）。",
			m.SLOCode, breachWindow, fmtVal(m.Value), m.Unit, fmtVal(m.Threshold), m.Unit, fmtVal(m.Baseline), m.Unit, m.Source),
	}
	ev.EvidenceJSON = db.MarshalMonEvidence(ev.Evidence)
	gdb.Create(ev)
}

// thresholdFor 据 SLOCode 从策略取对应阈值。
func thresholdFor(code string, p *model.MonitorPolicy) float64 {
	switch code {
	case model.SLO01HandshakeFail:
		return p.HandshakeFailThreshold
	case model.SLO02LatencyP99:
		return p.LatencyP99CeilMs
	case model.SLO03Throughput:
		return p.ThroughputDropCeilPct
	case model.SLO04IKEv2:
		return p.IKEv2EstablishCeilMs
	case model.SLO08CBOMFreshness:
		return float64(p.CBOMFreshnessDays)
	default:
		return 0
	}
}

// baselineFor SLO 验收基线值（趋势对照参考线；锚定 PRD 附录基线表）。
func baselineFor(code string) float64 {
	switch code {
	case model.SLO01HandshakeFail:
		return 0.02
	case model.SLO02LatencyP99:
		return 39.5
	case model.SLO03Throughput:
		return 0
	case model.SLO04IKEv2:
		return 412
	default:
		return 0
	}
}

// unitFor SLO 单位。
func unitFor(code string) string {
	switch code {
	case model.SLO01HandshakeFail, model.SLO03Throughput:
		return "pct"
	case model.SLO02LatencyP99, model.SLO04IKEv2:
		return "ms"
	case model.SLO08CBOMFreshness:
		return "days"
	default:
		return ""
	}
}

func fmtVal(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d", int(v))
	}
	return fmt.Sprintf("%.2f", v)
}

// SLOLabel SLO 编号的中文短名（仪表板卡片标题）。
func SLOLabel(code string) string {
	switch code {
	case model.SLO01HandshakeFail:
		return "握手失败率"
	case model.SLO02LatencyP99:
		return "p99 握手延迟"
	case model.SLO03Throughput:
		return "吞吐降幅"
	case model.SLO04IKEv2:
		return "IKEv2 建立时延"
	case model.SLO05Drift:
		return "密码漂移"
	case model.SLO06CertExpiry:
		return "证书到期预警"
	case model.SLO07Coverage:
		return "P1 覆盖率"
	case model.SLO08CBOMFreshness:
		return "CBOM 新鲜度"
	default:
		return code
	}
}

// SLOUnit 导出版单位（API 层 SLO 卡片用）。
func SLOUnit(code string) string { return unitFor(code) }

// SLOBaseline 导出版基线（前端趋势参考线用）。
func SLOBaseline(code string) float64 { return baselineFor(code) }
