package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/verify"
)

// ============ ④ 验收自动化（Acceptance）============

// listVerifyCases GET /verify/cases?track= → 静态用例库（按 category 分组），支持轨道过滤。
func (s *Server) listVerifyCases(c *gin.Context) {
	track := c.Query("track")
	cs := verify.CasesForTrack(track)
	// 按 category 分组返回，前端预览用例集。
	grouped := map[string][]verify.Case{}
	order := []string{model.CatProto, model.CatCompat, model.CatPerf, model.CatSec, model.CatKeymat}
	for _, cat := range order {
		grouped[cat] = []verify.Case{}
	}
	for _, item := range cs {
		grouped[item.Category] = append(grouped[item.Category], item)
	}
	c.JSON(http.StatusOK, gin.H{
		"total":    len(cs),
		"baseline": verify.BaselineTotal,
		"order":    order,
		"groups":   grouped,
		"cases":    cs,
	})
}

// createVerifyRunReq 建验收请求体。
type createVerifyRunReq struct {
	TaskID  *uint  `json:"taskId"`
	AssetID *uint  `json:"assetId"`
	Track   string `json:"track"`
	Target  string `json:"target"`
	Mode    string `json:"mode"` // probe/simulate；缺省按可达性预判
}

// createVerifyRun POST /verify/runs → 建并异步启动一次验收（与 createScan/executeRemediation 同构）。
func (s *Server) createVerifyRun(c *gin.Context) {
	var req createVerifyRunReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	run := model.AcceptanceRun{
		TaskID:  req.TaskID,
		AssetID: req.AssetID,
		Track:   strings.TrimSpace(req.Track),
		Target:  strings.TrimSpace(req.Target),
		Status:  model.RunPending,
	}

	// 缺 track 时若给 taskId 则从工单快照取 track/asset/target。
	if req.TaskID != nil {
		var task model.RemediationTask
		if err := s.db.First(&task, *req.TaskID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "工单不存在"})
			return
		}
		if run.Track == "" {
			run.Track = task.Track
		}
		run.TrackName = task.TrackName
		if run.AssetID == nil {
			run.AssetID = task.AssetID
		}
		run.AssetName = task.AssetName
		if run.Target == "" {
			run.Target = deviceEndpointForTask(s, &task)
		}
	}

	// 资产快照（补 AssetName/Target）。
	if run.AssetID != nil {
		var asset model.CryptoAsset
		if err := s.db.First(&asset, *run.AssetID).Error; err == nil {
			if run.AssetName == "" {
				run.AssetName = asset.Name
			}
			if run.Target == "" {
				run.Target = asset.Endpoint
			}
		}
	}

	if run.TrackName == "" {
		run.TrackName = trackNameOf(run.Track)
	}

	// 模式缺省：probe（真实探测目标可达）/ simulate。给了显式 mode 则尊重。
	switch req.Mode {
	case model.ModeProbe, model.ModeSimulate:
		run.Mode = req.Mode
	default:
		if run.Target != "" {
			run.Mode = model.ModeProbe
		} else {
			run.Mode = model.ModeSimulate
		}
	}

	run.Total = len(verify.CasesForTrack(run.Track))

	if err := s.db.Create(&run).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 异步执行（独立 context，避免随请求结束被取消，与扫描/改造一致）。
	go verify.NewRunner(s.db, nil).Run(context.Background(), run.ID)

	s.audit(c, "acceptance", "acceptance.run.create", auditTarget("AcceptanceRun", run.ID, run.AssetName),
		model.AuditSuccess, fmt.Sprintf("轨道=%s 模式=%s 目标=%s", run.Track, run.Mode, run.Target))
	c.JSON(http.StatusAccepted, run)
}

// listVerifyRuns GET /verify/runs → 列表（倒序，不含逐项），含四态计数与 GatePass。
func (s *Server) listVerifyRuns(c *gin.Context) {
	var runs []model.AcceptanceRun
	if err := s.db.Order("created_at desc").Find(&runs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, runs)
}

// getVerifyRun GET /verify/runs/:id → Run + []TestResult（前端轮询看逐项推进）。
func (s *Server) getVerifyRun(c *gin.Context) {
	var run model.AcceptanceRun
	if err := s.db.First(&run, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "验收记录不存在"})
		return
	}
	var results []model.TestResult
	s.db.Where("run_id = ?", run.ID).Order("id asc").Find(&results)
	c.JSON(http.StatusOK, gin.H{"run": run, "results": results})
}

// createVerifyReport POST /verify/runs/:id/report → 一键生成验收报告（DRAFT），落库。
func (s *Server) createVerifyReport(c *gin.Context) {
	var run model.AcceptanceRun
	if err := s.db.First(&run, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "验收记录不存在"})
		return
	}
	if run.Status != model.RunDone {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验收尚未完成，无法生成报告"})
		return
	}
	var results []model.TestResult
	s.db.Where("run_id = ?", run.ID).Order("id asc").Find(&results)
	var risks []model.LegacyRisk
	s.db.Order("code asc").Find(&risks)

	title, md, hash := verify.GenerateReport(run, results, risks)
	rep := model.AcceptanceReport{
		RunID:     run.ID,
		Title:     title,
		Markdown:  md,
		SignState: model.SignDraft,
		Hash:      hash,
		GatePass:  run.GatePass,
	}
	if err := s.db.Create(&rep).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	run.ReportID = &rep.ID
	s.db.Model(&run).Update("report_id", rep.ID)

	s.audit(c, "acceptance", "acceptance.report.create", auditTarget("AcceptanceReport", rep.ID, rep.Title),
		model.AuditSuccess, fmt.Sprintf("gatePass=%v hash=%s", rep.GatePass, hash[:12]))
	c.JSON(http.StatusCreated, rep)
}

// listVerifyReports GET /verify/reports → 报告列表（不含正文）。
func (s *Server) listVerifyReports(c *gin.Context) {
	var reports []model.AcceptanceReport
	s.db.Select("id", "run_id", "title", "sign_state", "hash", "gate_pass", "reviewer", "signer", "created_at", "signed_at").
		Order("created_at desc").Find(&reports)
	c.JSON(http.StatusOK, reports)
}

// getVerifyReport GET /verify/reports/:id → 报告全文。
func (s *Server) getVerifyReport(c *gin.Context) {
	var rep model.AcceptanceReport
	if err := s.db.First(&rep, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "报告不存在"})
		return
	}
	c.JSON(http.StatusOK, rep)
}

// signVerifyReportReq 签署流转请求体。
type signVerifyReportReq struct {
	Action string `json:"action"` // submit/approve/reject/sign
}

// signVerifyReport POST /verify/reports/:id/sign → 驱动签署状态机（FR-7.6）。
//
// 流转：DRAFT --submit--> UNDER_REVIEW --approve--> UNDER_REVIEW --sign--> SIGNED
//
//	任意可签态 --reject--> REJECTED
//
// sign 仅当 GatePass 且全部 conditional 已挂 RiskRef 时允许；SIGNED 后把关联资产
// 经状态机白名单置 verified，并写 Hash+Signer+审计。
func (s *Server) signVerifyReport(c *gin.Context) {
	var rep model.AcceptanceReport
	if err := s.db.First(&rep, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "报告不存在"})
		return
	}
	var req signVerifyReportReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	actor := actorName(c)

	switch req.Action {
	case "submit":
		if rep.SignState != model.SignDraft && rep.SignState != model.SignRejected {
			c.JSON(http.StatusConflict, gin.H{"error": "仅 DRAFT/REJECTED 可提交评审"})
			return
		}
		rep.SignState = model.SignUnderReview
		rep.Reviewer = actor
	case "approve":
		if rep.SignState != model.SignUnderReview {
			c.JSON(http.StatusConflict, gin.H{"error": "仅 UNDER_REVIEW 可通过评审"})
			return
		}
		rep.SignState = model.SignUnderReview // 通过评审仍在评审态，待签署人 sign
		rep.Reviewer = actor
	case "reject":
		if rep.SignState == model.SignSigned {
			c.JSON(http.StatusConflict, gin.H{"error": "已签署报告不可退回"})
			return
		}
		rep.SignState = model.SignRejected
		rep.Reviewer = actor
	case "sign":
		if rep.SignState != model.SignUnderReview {
			c.JSON(http.StatusConflict, gin.H{"error": "仅 UNDER_REVIEW 可签署"})
			return
		}
		if !rep.GatePass {
			s.audit(c, "acceptance", "acceptance.report.sign", auditTarget("AcceptanceReport", rep.ID, rep.Title),
				model.AuditDenied, "Gate 未达标，拒绝签署")
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Gate 未达标（存在未通过项或有条件项未挂遗留风险），拒绝签署"})
			return
		}
		// 二次确认：全部 conditional 已挂 RiskRef（防止报告生成后逐项被改）。
		if !s.conditionalsAllReffed(rep.RunID) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "存在未挂遗留风险的有条件项，拒绝签署"})
			return
		}
		now := time.Now()
		rep.SignState = model.SignSigned
		rep.Signer = actor
		rep.SignedAt = &now
		// SIGNED 后把关联资产经状态机白名单置 verified。
		s.markAssetVerified(c, rep.RunID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action 须为 submit/approve/reject/sign"})
		return
	}

	if err := s.db.Save(&rep).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "acceptance", "acceptance.report.sign", auditTarget("AcceptanceReport", rep.ID, rep.Title),
		model.AuditSuccess, "action="+req.Action+" → "+rep.SignState)
	c.JSON(http.StatusOK, rep)
}

// conditionalsAllReffed 校验某次验收的全部有条件项均已挂 RiskRef。
func (s *Server) conditionalsAllReffed(runID uint) bool {
	var n int64
	s.db.Model(&model.TestResult{}).
		Where("run_id = ? AND verdict = ? AND (risk_ref IS NULL OR risk_ref = '')", runID, model.VerdictConditional).
		Count(&n)
	return n == 0
}

// markAssetVerified 报告签署后，把验收记录关联资产经状态机白名单置 verified。
// 非法迁移（资产不在 remediated/verified 前态）则不强改，仅审计留痕，绝不破坏状态机。
func (s *Server) markAssetVerified(c *gin.Context, runID uint) {
	var run model.AcceptanceRun
	if err := s.db.First(&run, runID).Error; err != nil || run.AssetID == nil {
		return
	}
	var asset model.CryptoAsset
	if err := s.db.First(&asset, *run.AssetID).Error; err != nil {
		return
	}
	if asset.Status == model.StatusVerified {
		return
	}
	if !model.AssetTransitionAllowed(asset.Status, model.StatusVerified) {
		s.audit(c, "acceptance", "acceptance.asset.verify", auditTarget("CryptoAsset", asset.ID, asset.Name),
			model.AuditFailure, fmt.Sprintf("状态 %s 不可迁移至 verified，跳过（不破坏状态机）", asset.Status))
		return
	}
	old := asset.Status
	asset.Status = model.StatusVerified
	s.db.Model(&asset).Update("status", model.StatusVerified)
	s.audit(c, "acceptance", "acceptance.asset.verify", auditTarget("CryptoAsset", asset.ID, asset.Name),
		model.AuditSuccess, fmt.Sprintf("%s→verified（验收签署）", old))
}

// verifyRemediation POST /remediations/:id/verify → 改造 done 后一键跑验收的接缝。
// 从工单取 track/asset/device endpoint 建 Run 并启动，返回 runId。
func (s *Server) verifyRemediation(c *gin.Context) {
	var task model.RemediationTask
	if err := s.db.First(&task, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	if task.Status != model.RemDone {
		c.JSON(http.StatusBadRequest, gin.H{"error": "仅 done 工单可发起验收"})
		return
	}

	target := deviceEndpointForTask(s, &task)
	run := model.AcceptanceRun{
		TaskID:    &task.ID,
		AssetID:   task.AssetID,
		AssetName: task.AssetName,
		Track:     task.Track,
		TrackName: task.TrackName,
		Target:    target,
		Status:    model.RunPending,
	}
	if target != "" {
		run.Mode = model.ModeProbe
	} else {
		run.Mode = model.ModeSimulate
	}
	run.Total = len(verify.CasesForTrack(run.Track))

	if err := s.db.Create(&run).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	go verify.NewRunner(s.db, nil).Run(context.Background(), run.ID)

	s.audit(c, "acceptance", "acceptance.run.fromRemediation",
		auditTarget("AcceptanceRun", run.ID, run.AssetName), model.AuditSuccess,
		fmt.Sprintf("工单 #%d 轨道=%s 模式=%s", task.ID, run.Track, run.Mode))
	c.JSON(http.StatusAccepted, gin.H{"runId": run.ID, "run": run})
}

// listVerifyRisks GET /verify/risks → 遗留风险登记台账（R-001…），供有条件项挂接复用。
func (s *Server) listVerifyRisks(c *gin.Context) {
	var risks []model.LegacyRisk
	if err := s.db.Order("always_on_slo desc, code asc").Find(&risks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, risks)
}

// ---- 内部小工具 ----

// deviceEndpointForTask 取工单执行设备的管理面 endpoint 作为探测落点（缺设备则空）。
func deviceEndpointForTask(s *Server, task *model.RemediationTask) string {
	if task.DeviceID == nil {
		return ""
	}
	var dev model.Device
	if err := s.db.First(&dev, *task.DeviceID).Error; err != nil {
		return ""
	}
	// 仅取 host:port 形态的 endpoint 作 TLS 探测目标；http(s):// 前缀去掉。
	ep := dev.Endpoint
	ep = strings.TrimPrefix(ep, "https://")
	ep = strings.TrimPrefix(ep, "http://")
	return ep
}

// trackNameOf 据轨道键给出中文名（无匹配返回原键）。
func trackNameOf(track string) string {
	switch track {
	case verify.TrackTLS:
		return "对外 TLS 混合 KEM"
	case verify.TrackVPN:
		return "SSL VPN 混合 KEM"
	case verify.TrackRootCA:
		return "根 CA 混合双签名"
	case verify.TrackCode:
		return "代码签名双签名"
	case verify.TrackGM:
		return "国密混合(SM2+ML-KEM)"
	default:
		return track
	}
}
