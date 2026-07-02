package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/monitor"
)

// ============ SLO 时序（ingest / series / summary）============
//
// 与 monitor.IngestSLO（slo.go）配合：写入为追加式时序，越阈即连续窗口判定（默认 3 点）。
// 无真实网关遥测时，复扫/定时器在基线附近合成抖动值并诚实标 source="synthetic"（见 runner.synthSLO）。

// sloIngestReq 遥测回填请求体（机机接口）。value 必填，其余可空。
type sloIngestReq struct {
	SLOCode       string   `json:"sloCode"`
	AssetID       *uint    `json:"assetId"`
	RemediationID *uint    `json:"remediationId"`
	Value         *float64 `json:"value"`
	Source        string   `json:"source"` // 缺省 measured（真实回填）；离线合成由复扫标 synthetic
}

// ingestSLO POST /monitor/slo/ingest → 追加一个 SLO 时序点并做越界 + 连续窗口判定。
// 落 SLOMetric；连续 N 点越阈即由 monitor.IngestSLO 生成 slo_breach 事件（单点不误报）。
// 写端点：operator/admin + 审计。
func (s *Server) ingestSLO(c *gin.Context) {
	var req sloIngestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validSLOCode(req.SLOCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sloCode 须为 SLO-01..SLO-08"})
		return
	}
	if req.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value 必填"})
		return
	}
	source := req.Source
	if source == "" {
		source = "measured"
	}

	// 取当前生效策略快照阈值（无则用 IngestSLO 内部回退 0，此处尽量带上）。
	p := s.activeMonitorPolicy()

	m := model.SLOMetric{
		SLOCode:       req.SLOCode,
		AssetID:       req.AssetID,
		RemediationID: req.RemediationID,
		Value:         *req.Value,
		Baseline:      monitor.SLOBaseline(req.SLOCode),
		Unit:          monitor.SLOUnit(req.SLOCode),
		Source:        source,
		SampledAt:     time.Now(),
	}
	monitor.IngestSLO(s.db, m, p)

	// 回读最新写入点（含 IngestSLO 计算的 Threshold/Breached）。
	var saved model.SLOMetric
	s.db.Where("slo_code = ?", req.SLOCode).Order("id desc").First(&saved)

	s.audit(c, "monitor", "monitor.slo.ingest",
		auditTargetStr("SLOMetric", fmt.Sprintf("%d", saved.ID), req.SLOCode),
		model.AuditSuccess, fmt.Sprintf("value=%v breached=%v source=%s", saved.Value, saved.Breached, source))
	c.JSON(http.StatusOK, gin.H{
		"metric":   saved,
		"breached": saved.Breached,
		"window":   monitor.BreachWindow,
	})
}

// sloSeries GET /monitor/slo/series?code=&assetId=&from=&to=&limit= → 时序点数组（升序，供趋势图）。
func (s *Server) sloSeries(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		code = c.Query("sloCode")
	}
	if !validSLOCode(code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code 须为 SLO-01..SLO-08"})
		return
	}
	q := s.db.Model(&model.SLOMetric{}).Where("slo_code = ?", code)
	if v := c.Query("assetId"); v != "" {
		q = q.Where("asset_id = ?", v)
	}
	if v := c.Query("from"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("sampled_at >= ?", t)
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("sampled_at < ?", t.Add(24*time.Hour))
		}
	}
	limit, _ := pageLimitOffset(c, 500)
	var points []model.SLOMetric
	if err := q.Order("sampled_at asc").Limit(limit).Find(&points).Error; err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":     code,
		"label":    monitor.SLOLabel(code),
		"unit":     monitor.SLOUnit(code),
		"baseline": monitor.SLOBaseline(code),
		"points":   points,
	})
}

// sloSummaryEndpoint GET /monitor/slo/summary → 每个 SLO 编号最新值 + 阈值 + 基线 + 状态。
// 复用仪表板 sloSummary 聚合（SLO-05/06/07 由事件与资产补齐），即仪表板 SLO 卡数据源。
func (s *Server) sloSummaryEndpoint(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": s.sloSummary()})
}

// validSLOCode 校验 SLO 编号合法。
func validSLOCode(code string) bool {
	switch code {
	case model.SLO01HandshakeFail, model.SLO02LatencyP99, model.SLO03Throughput,
		model.SLO04IKEv2, model.SLO05Drift, model.SLO06CertExpiry,
		model.SLO07Coverage, model.SLO08CBOMFreshness:
		return true
	}
	return false
}

// activeMonitorPolicy 取一条启用中的监测策略作阈值来源（取最早启用项；无则 nil）。
func (s *Server) activeMonitorPolicy() *model.MonitorPolicy {
	var p model.MonitorPolicy
	if err := s.db.Where("enabled = ?", true).Order("id asc").First(&p).Error; err == nil {
		return &p
	}
	return nil
}
