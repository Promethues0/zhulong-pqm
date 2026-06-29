package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/monitor"
)

// ============ 监测策略（MonitorPolicy）============

// withNextRun 计算策略的展示用 nextRunAt（不落库，仅响应填充）。
func withNextRun(p *model.MonitorPolicy) {
	if p.Enabled && p.NextRunAt == nil {
		base := time.Now()
		if p.LastRunAt != nil {
			base = *p.LastRunAt
		}
		p.NextRunAt = monitor.NextRunAfterPublic(p, base)
	}
}

// listMonitorPolicies GET /monitor/policies → []MonitorPolicy（含计算出的 nextRunAt）。
func (s *Server) listMonitorPolicies(c *gin.Context) {
	var policies []model.MonitorPolicy
	if err := s.db.Order("id asc").Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for i := range policies {
		withNextRun(&policies[i])
	}
	c.JSON(http.StatusOK, policies)
}

// validatePolicy 阈值合理性校验（FR-7.8 验收口径 10）：失败率/延迟/天数为正，CA 提前量 ≥ 服务器提前量。
func validatePolicy(p *model.MonitorPolicy) error {
	if p.Name == "" {
		return fmt.Errorf("name 必填")
	}
	if p.HandshakeFailThreshold <= 0 || p.LatencyP99CeilMs <= 0 ||
		p.ThroughputDropCeilPct <= 0 || p.IKEv2EstablishCeilMs <= 0 {
		return fmt.Errorf("失败率/延迟/吞吐降幅/IKEv2 阈值必须为正数")
	}
	if p.CBOMFreshnessDays <= 0 || p.CACertWarnDays <= 0 ||
		p.ServerCertWarnDays <= 0 || p.IoTCertWarnDays <= 0 {
		return fmt.Errorf("新鲜度/证书提前量天数必须为正数")
	}
	if p.CACertWarnDays < p.ServerCertWarnDays {
		return fmt.Errorf("CA 证书提前量须 ≥ 服务器证书提前量")
	}
	return nil
}

// applyPolicyDefaults 为缺省字段补 PRD 默认阈值（部分提交时不丢默认）。
func applyPolicyDefaults(p *model.MonitorPolicy) {
	if p.ScopeKind == "" {
		p.ScopeKind = model.ScopeAll
	}
	if p.RescanCron == "" {
		p.RescanCron = "0 0 3 1 */3 *"
	}
	if p.HandshakeFailThreshold == 0 {
		p.HandshakeFailThreshold = 0.1
	}
	if p.LatencyP99CeilMs == 0 {
		p.LatencyP99CeilMs = 46.2
	}
	if p.ThroughputDropCeilPct == 0 {
		p.ThroughputDropCeilPct = 6.5
	}
	if p.IKEv2EstablishCeilMs == 0 {
		p.IKEv2EstablishCeilMs = 437
	}
	if p.CBOMFreshnessDays == 0 {
		p.CBOMFreshnessDays = 90
	}
	if p.CACertWarnDays == 0 {
		p.CACertWarnDays = 180
	}
	if p.ServerCertWarnDays == 0 {
		p.ServerCertWarnDays = 30
	}
	if p.IoTCertWarnDays == 0 {
		p.IoTCertWarnDays = 365
	}
}

// createMonitorPolicy POST /monitor/policies → 创建策略，校验阈值合理性，注册到调度。
func (s *Server) createMonitorPolicy(c *gin.Context) {
	var p model.MonitorPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = 0
	applyPolicyDefaults(&p)
	if err := validatePolicy(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	monitor.SyncPolicy(s.sched, s.db, &p)
	withNextRun(&p)
	s.audit(c, "monitor", "monitor.policy.create", auditTarget("MonitorPolicy", p.ID, p.Name),
		model.AuditSuccess, fmt.Sprintf("范围=%s cron=%s", p.ScopeKind, p.RescanCron))
	c.JSON(http.StatusCreated, p)
}

// updateMonitorPolicy PUT /monitor/policies/:id → 全量更新（保留主键/创建时间），刷新调度。
func (s *Server) updateMonitorPolicy(c *gin.Context) {
	var existing model.MonitorPolicy
	if err := s.db.First(&existing, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "策略不存在"})
		return
	}
	var in model.MonitorPolicy
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	in.ID = existing.ID
	in.CreatedAt = existing.CreatedAt
	in.LastRunAt = existing.LastRunAt
	in.NextRunAt = nil
	applyPolicyDefaults(&in)
	if err := validatePolicy(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&in).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	monitor.SyncPolicy(s.sched, s.db, &in)
	withNextRun(&in)
	s.audit(c, "monitor", "monitor.policy.update", auditTarget("MonitorPolicy", in.ID, in.Name),
		model.AuditSuccess, fmt.Sprintf("enabled=%v", in.Enabled))
	c.JSON(http.StatusOK, in)
}

// deleteMonitorPolicy DELETE /monitor/policies/:id → 删除并注销调度。
func (s *Server) deleteMonitorPolicy(c *gin.Context) {
	var p model.MonitorPolicy
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "策略不存在"})
		return
	}
	if err := s.db.Delete(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	monitor.UnregisterPolicy(s.sched, p.ID)
	s.audit(c, "monitor", "monitor.policy.delete", auditTarget("MonitorPolicy", p.ID, p.Name),
		model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// runMonitorPolicy POST /monitor/policies/:id/run → 立即触发一次复扫（异步 goroutine，202）。
// 与 createScan 同构：go runner.Run(context.Background(), id)。返回本次将生成事件的提示。
func (s *Server) runMonitorPolicy(c *gin.Context) {
	var p model.MonitorPolicy
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "策略不存在"})
		return
	}
	pid := p.ID
	// 再入保护：同一策略的复扫（手动/周期）互斥，避免并发复扫重复落事件。
	jobName := monitor.PolicyJobName(pid)
	if !s.sched.TryRun(jobName) {
		s.audit(c, "monitor", "monitor.policy.run", auditTarget("MonitorPolicy", p.ID, p.Name),
			model.AuditDenied, "复扫进行中")
		c.JSON(http.StatusConflict, gin.H{"error": "复扫进行中，请等待当前复扫完成后再试"})
		return
	}
	runner := monitor.NewRunner(s.db, nil)
	// 同步跑首段以便立即返回本次摘要？为不阻塞请求，按异步范式起协程。
	go func() {
		defer s.sched.DoneRun(jobName)
		runner.Run(context.Background(), pid)
	}()
	s.audit(c, "monitor", "monitor.policy.run", auditTarget("MonitorPolicy", p.ID, p.Name),
		model.AuditSuccess, "手动触发复扫")
	c.JSON(http.StatusAccepted, gin.H{
		"policyId": p.ID,
		"status":   "running",
		"message":  "复扫已异步启动，请轮询 /monitor/events 查看生成的告警",
	})
}

// ============ 监测事件/告警（MonitorEvent）============

// loadEventJSON 反序列化事件证据，供响应使用。
func loadEventJSON(e *model.MonitorEvent) {
	e.Evidence = db.UnmarshalMonEvidence(e.EvidenceJSON)
}

// listMonitorEvents GET /monitor/events?kind=&severity=&status=&assetId= → 过滤列表（倒序）。
func (s *Server) listMonitorEvents(c *gin.Context) {
	q := s.db.Model(&model.MonitorEvent{})
	if v := c.Query("kind"); v != "" {
		q = q.Where("kind = ?", v)
	}
	if v := c.Query("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("assetId"); v != "" {
		q = q.Where("asset_id = ?", v)
	}
	var total int64
	q.Count(&total)
	limit, offset := pageLimitOffset(c, 50)
	var events []model.MonitorEvent
	if err := q.Order("occurred_at desc").Limit(limit).Offset(offset).Find(&events).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for i := range events {
		loadEventJSON(&events[i])
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": events})
}

// ackMonitorEvent POST /monitor/events/:id/ack → 处置（写 AckedBy=ctx username，状态→acked）。
func (s *Server) ackMonitorEvent(c *gin.Context) {
	var e model.MonitorEvent
	if err := s.db.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
		return
	}
	e.Status = model.MonAcked
	e.AckedBy = actorName(c)
	if err := s.db.Model(&e).Updates(map[string]any{"status": e.Status, "acked_by": e.AckedBy}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadEventJSON(&e)
	s.audit(c, "monitor", "monitor.event.ack", auditTarget("MonitorEvent", e.ID, e.Title),
		model.AuditSuccess, "")
	c.JSON(http.StatusOK, e)
}

// resolveMonitorEvent POST /monitor/events/:id/resolve → 闭合（写 ResolvedAt，状态→resolved）。
func (s *Server) resolveMonitorEvent(c *gin.Context) {
	var e model.MonitorEvent
	if err := s.db.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
		return
	}
	now := time.Now()
	e.Status = model.MonResolved
	e.ResolvedAt = &now
	if e.AckedBy == "" {
		e.AckedBy = actorName(c)
	}
	if err := s.db.Model(&e).Updates(map[string]any{
		"status": e.Status, "resolved_at": e.ResolvedAt, "acked_by": e.AckedBy,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadEventJSON(&e)
	s.audit(c, "monitor", "monitor.event.resolve", auditTarget("MonitorEvent", e.ID, e.Title),
		model.AuditSuccess, "")
	c.JSON(http.StatusOK, e)
}

// reassessMonitorEvent POST /monitor/events/:id/reassess → 一键复评回灌（C5，J5→J2）。
// 对关联资产按当前生效权重重评分 + 写 ScoreHistory(reassess) + 资产经状态机回退态 + 回填 ReassessTaskID。
func (s *Server) reassessMonitorEvent(c *gin.Context) {
	var e model.MonitorEvent
	if err := s.db.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
		return
	}
	if e.AssetID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "事件未关联资产，无法复评"})
		return
	}
	asset, hist, err := monitor.Reassess(s.db, *e.AssetID, actorName(c), "event-reassess")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	taskID := hist.ID
	e.ReassessTaskID = &taskID
	if e.Status == model.MonOpen {
		e.Status = model.MonAcked
		e.AckedBy = actorName(c)
	}
	s.db.Model(&e).Updates(map[string]any{
		"reassess_task_id": e.ReassessTaskID,
		"status":           e.Status,
		"acked_by":         e.AckedBy,
	})
	loadEventJSON(&e)
	s.audit(c, "monitor", "monitor.event.reassess", auditTarget("MonitorEvent", e.ID, e.Title),
		model.AuditSuccess, fmt.Sprintf("资产 #%d 重评分=%d(%s) 复评批次=#%d",
			asset.ID, asset.RiskScore, asset.RiskLevel, hist.ID))
	c.JSON(http.StatusOK, gin.H{
		"event":          e,
		"asset":          asset,
		"reassessTaskId": hist.ID,
		"message":        "已生成复评批次回流评估",
	})
}

// ============ 遗留风险登记（LegacyRisk，R-00x 台账）============

// listLegacyRisks GET /monitor/legacy-risks?level=&status=&recheckBefore= → 台账筛选。
func (s *Server) listLegacyRisks(c *gin.Context) {
	q := s.db.Model(&model.LegacyRisk{})
	if v := c.Query("level"); v != "" {
		q = q.Where("level = ?", v)
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("alwaysOnSlo"); v != "" {
		q = q.Where("always_on_slo = ?", v == "true" || v == "1")
	}
	if v := c.Query("recheckBefore"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("recheck_date <= ?", t)
		}
	}
	var risks []model.LegacyRisk
	// AlwaysOnSLO 常显项置顶，其余按编号。
	if err := q.Order("always_on_slo desc, code asc").Find(&risks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, risks)
}

// createLegacyRisk POST /monitor/legacy-risks → 新建台账项。
func (s *Server) createLegacyRisk(c *gin.Context) {
	var r model.LegacyRisk
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	r.ID = 0
	if strings.TrimSpace(r.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code 必填（R-00x 风格）"})
		return
	}
	if r.Status == "" {
		r.Status = model.RiskTracking
	}
	if err := s.db.Create(&r).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "monitor", "monitor.risk.create", auditTarget("LegacyRisk", r.ID, r.Code),
		model.AuditSuccess, r.Level)
	c.JSON(http.StatusCreated, r)
}

// updateLegacyRisk PUT /monitor/legacy-risks/:id → 全量更新（保留主键/创建时间）。
func (s *Server) updateLegacyRisk(c *gin.Context) {
	var existing model.LegacyRisk
	if err := s.db.First(&existing, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "风险项不存在"})
		return
	}
	var in model.LegacyRisk
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	in.ID = existing.ID
	in.CreatedAt = existing.CreatedAt
	if in.Code == "" {
		in.Code = existing.Code
	}
	if err := s.db.Save(&in).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "monitor", "monitor.risk.update", auditTarget("LegacyRisk", in.ID, in.Code),
		model.AuditSuccess, in.Status)
	c.JSON(http.StatusOK, in)
}

// closeLegacyRiskReq 关闭请求体（evidenceUrl 必填，FR-7.10 完成定义）。
type closeLegacyRiskReq struct {
	EvidenceURL string `json:"evidenceUrl"`
}

// closeLegacyRisk POST /monitor/legacy-risks/:id/close → 闭合（要求 evidenceUrl 非空）。
func (s *Server) closeLegacyRisk(c *gin.Context) {
	var r model.LegacyRisk
	if err := s.db.First(&r, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "风险项不存在"})
		return
	}
	var req closeLegacyRiskReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.EvidenceURL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "闭合遗留风险须上传替换/升级证据（evidenceUrl 非空）"})
		return
	}
	r.Status = model.RiskClosed
	r.EvidenceURL = req.EvidenceURL
	if err := s.db.Model(&r).Updates(map[string]any{
		"status": r.Status, "evidence_url": r.EvidenceURL,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "monitor", "monitor.risk.close", auditTarget("LegacyRisk", r.ID, r.Code),
		model.AuditSuccess, "证据="+req.EvidenceURL)
	c.JSON(http.StatusOK, r)
}

// ============ 监测仪表板聚合（/monitor/dashboard）============

// monitorDashboard GET /monitor/dashboard → 一次返回 SLO 概要 / 按 severity 告警计数 /
// 90 天内临期证书 / 复评队列 / R-00x 常显项（FR-7.13）。离线无数据返回空结构 + 合成标注，绝不 5xx。
func (s *Server) monitorDashboard(c *gin.Context) {
	// 1) 告警按 severity 计数（仅 open/acked 计活跃）。
	sevCount := map[string]int64{model.SevP1: 0, model.SevWarning: 0, model.SevInspect: 0}
	for sev := range sevCount {
		var n int64
		s.db.Model(&model.MonitorEvent{}).
			Where("severity = ? AND status IN ?", sev, []string{model.MonOpen, model.MonAcked}).Count(&n)
		sevCount[sev] = n
	}
	var openTotal int64
	s.db.Model(&model.MonitorEvent{}).Where("status IN ?", []string{model.MonOpen, model.MonAcked}).Count(&openTotal)

	// 2) SLO 概要：每个 SLOCode 取最新时序点 + 状态。
	sloSummary := s.sloSummary()

	// 3) 90 天内临期证书（含已过期），按剩余天数升序。
	now := time.Now()
	horizon := now.AddDate(0, 0, 90)
	var certAssets []model.CryptoAsset
	s.db.Where("cert_not_after IS NOT NULL AND cert_not_after <= ?", horizon).
		Order("cert_not_after asc").Find(&certAssets)
	certExpiring := make([]gin.H, 0, len(certAssets))
	for i := range certAssets {
		a := certAssets[i]
		left := int(time.Until(*a.CertNotAfter).Hours() / 24)
		certExpiring = append(certExpiring, gin.H{
			"assetId":   a.ID,
			"name":      a.Name,
			"layer":     a.Layer,
			"daysLeft":  left,
			"notAfter":  a.CertNotAfter,
			"riskLevel": a.RiskLevel,
		})
	}

	// 4) 复评队列：处于 reassessing 态的资产。
	var reassessQueue []model.CryptoAsset
	s.db.Where("status = ?", model.StatusReassessing).Order("risk_score desc").Find(&reassessQueue)

	// 5) R-00x 常显项（AlwaysOnSLO=true 且未关闭）。
	var alwaysOn []model.LegacyRisk
	s.db.Where("always_on_slo = ? AND status <> ?", true, model.RiskClosed).
		Order("code asc").Find(&alwaysOn)

	// 6) CBOM 新鲜度天数（最近一次复扫=策略 LastRunAt 最大值，无则用最近扫描）。
	freshnessDays := s.cbomFreshnessDays()

	// 7) P1 漂移事件（最近，便于驾驶舱下钻）。
	var recentP1 []model.MonitorEvent
	s.db.Where("severity = ? AND status IN ?", model.SevP1, []string{model.MonOpen, model.MonAcked}).
		Order("occurred_at desc").Limit(10).Find(&recentP1)
	for i := range recentP1 {
		loadEventJSON(&recentP1[i])
	}

	c.JSON(http.StatusOK, gin.H{
		"alertsBySeverity":  sevCount,
		"activeAlerts":      openTotal,
		"sloSummary":        sloSummary,
		"certExpiring":      certExpiring,
		"reassessQueue":     reassessQueue,
		"alwaysOnRisks":     alwaysOn,
		"cbomFreshnessDays": freshnessDays,
		"recentP1Events":    recentP1,
	})
}

// sloSummary 每个 SLO 编号取最新时序点；SLO-05/06/07 由事件与资产聚合补齐。
func (s *Server) sloSummary() []gin.H {
	codes := []string{
		model.SLO01HandshakeFail, model.SLO02LatencyP99, model.SLO03Throughput,
		model.SLO04IKEv2, model.SLO05Drift, model.SLO06CertExpiry,
		model.SLO07Coverage, model.SLO08CBOMFreshness,
	}
	out := make([]gin.H, 0, len(codes))
	for _, code := range codes {
		out = append(out, s.sloCard(code))
	}
	return out
}

// sloCard 构造单个 SLO 卡片数据（状态：normal/breach/warning）。
func (s *Server) sloCard(code string) gin.H {
	card := gin.H{"code": code, "label": monitor.SLOLabel(code), "status": "normal"}
	switch code {
	case model.SLO01HandshakeFail, model.SLO02LatencyP99, model.SLO03Throughput,
		model.SLO04IKEv2, model.SLO08CBOMFreshness:
		var m model.SLOMetric
		if err := s.db.Where("slo_code = ?", code).Order("sampled_at desc").First(&m).Error; err == nil {
			card["value"] = m.Value
			card["threshold"] = m.Threshold
			card["baseline"] = m.Baseline
			card["unit"] = m.Unit
			card["source"] = m.Source
			if m.Breached {
				card["status"] = "breach"
			}
		} else {
			card["value"] = nil
			card["unit"] = monitor.SLOUnit(code)
			card["source"] = "synthetic"
		}
	case model.SLO05Drift:
		// 漂移 SLO：目标=0，活跃 P1 漂移事件数即越界量。
		var n int64
		s.db.Model(&model.MonitorEvent{}).
			Where("kind = ? AND severity = ? AND status IN ?", model.EventDrift, model.SevP1,
				[]string{model.MonOpen, model.MonAcked}).Count(&n)
		card["value"] = n
		card["threshold"] = 0
		card["unit"] = "count"
		if n > 0 {
			card["status"] = "breach"
		}
	case model.SLO06CertExpiry:
		var n int64
		s.db.Model(&model.MonitorEvent{}).
			Where("kind = ? AND status IN ?", model.EventCertExpiry, []string{model.MonOpen, model.MonAcked}).Count(&n)
		card["value"] = n
		card["unit"] = "count"
		if n > 0 {
			card["status"] = "warning"
		}
	case model.SLO07Coverage:
		// P1 覆盖率：P1 资产中已纳管/已验收占比（演示聚合）。
		var p1Total, p1Covered int64
		s.db.Model(&model.CryptoAsset{}).Where("risk_level = ?", model.LevelP1).Count(&p1Total)
		s.db.Model(&model.CryptoAsset{}).
			Where("risk_level = ? AND status IN ?", model.LevelP1,
				[]string{model.StatusVerified, model.StatusMonitored, model.StatusAccepted, model.StatusRemediated}).
			Count(&p1Covered)
		card["value"] = p1Covered
		card["total"] = p1Total
		card["unit"] = "ratio"
		if p1Total > 0 && p1Covered < p1Total {
			card["status"] = "warning"
		}
	}
	return card
}

// cbomFreshnessDays 据最近一次复扫/扫描时刻估算 CBOM 新鲜度天数（无则返回 -1 表示未知）。
func (s *Server) cbomFreshnessDays() int {
	var p model.MonitorPolicy
	if err := s.db.Where("last_run_at IS NOT NULL").Order("last_run_at desc").First(&p).Error; err == nil && p.LastRunAt != nil {
		return int(time.Since(*p.LastRunAt).Hours() / 24)
	}
	var job model.ScanJob
	if err := s.db.Order("created_at desc").First(&job).Error; err == nil {
		return int(time.Since(job.CreatedAt).Hours() / 24)
	}
	return -1
}
