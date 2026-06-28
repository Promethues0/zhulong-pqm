package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/remediate"
	"zhulong-pqm/internal/scoring"
)

// listPlaybooks 返回静态改造剧本库。
func (s *Server) listPlaybooks(c *gin.Context) {
	c.JSON(http.StatusOK, remediate.Playbooks())
}

// loadTaskJSON 反序列化工单的 Steps/Evidence，供响应使用。
func loadTaskJSON(t *model.RemediationTask) {
	t.Steps = db.UnmarshalSteps(t.StepsJSON)
	t.Evidence = db.UnmarshalEvidence(t.EvidenceJSON)
}

// listRemediations 列出全部改造工单（倒序）。
func (s *Server) listRemediations(c *gin.Context) {
	var tasks []model.RemediationTask
	if err := s.db.Order("created_at desc").Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for i := range tasks {
		loadTaskJSON(&tasks[i])
	}
	c.JSON(http.StatusOK, tasks)
}

// getRemediation 返回单个改造工单。
func (s *Server) getRemediation(c *gin.Context) {
	var task model.RemediationTask
	if err := s.db.First(&task, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	loadTaskJSON(&task)
	c.JSON(http.StatusOK, task)
}

// createRemediationReq 建单请求体。
type createRemediationReq struct {
	AssetID    *uint  `json:"assetId"`
	AssetName  string `json:"assetName"`
	Track      string `json:"track" binding:"required"`
	TargetAlgo string `json:"targetAlgo"`
	DeviceID   *uint  `json:"deviceId"`
}

// createRemediation 按剧本快照建立一条 planned 工单。
//
// 规则：按 track 取剧本，快照其 Deliverable/Acceptance/Steps（全部 pending）；
// 给了 assetId 则从库取资产并以其 Name 作快照、targetAlgo 缺省取剧本默认或
// scoring.SuggestAlgo(asset.Algorithm)；给了 deviceId 则快照设备名与类型。
func (s *Server) createRemediation(c *gin.Context) {
	var req createRemediationReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track 必填"})
		return
	}

	pb, ok := remediate.PlaybookByKey(req.Track)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未知改造轨道 track"})
		return
	}

	task := model.RemediationTask{
		Track:       pb.Key,
		TrackName:   pb.Name,
		AssetName:   req.AssetName,
		Deliverable: pb.Deliverable,
		Acceptance:  pb.Acceptance,
		Status:      model.RemPlanned,
		Progress:    0,
	}

	// 资产快照：给了 assetId 则从 DB 取，用资产名覆盖快照，并据算法补默认目标算法。
	var assetAlgo string
	if req.AssetID != nil {
		var asset model.CryptoAsset
		if err := s.db.First(&asset, *req.AssetID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "资产不存在"})
			return
		}
		task.AssetID = req.AssetID
		task.AssetName = asset.Name
		assetAlgo = asset.Algorithm
	}

	// 目标算法：显式传 > 剧本默认 > 据资产算法推导。
	switch {
	case req.TargetAlgo != "":
		task.TargetAlgo = req.TargetAlgo
	case pb.TargetAlgo != "":
		task.TargetAlgo = pb.TargetAlgo
	case assetAlgo != "":
		task.TargetAlgo = scoring.SuggestAlgo(assetAlgo)
	}

	// 设备快照。
	if req.DeviceID != nil {
		var device model.Device
		if err := s.db.First(&device, *req.DeviceID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "设备不存在"})
			return
		}
		task.DeviceID = req.DeviceID
		task.DeviceName = device.Name
		task.DeviceType = device.Type
	}

	// 步骤快照：剧本步骤名 → 全部 pending。
	steps := make([]model.Step, 0, len(pb.Steps))
	for _, name := range pb.Steps {
		steps = append(steps, model.Step{Name: name, Status: model.StepPending})
	}
	task.StepsJSON = db.MarshalSteps(steps)
	task.EvidenceJSON = db.MarshalEvidence(nil)

	if err := s.db.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadTaskJSON(&task)
	s.audit(c, "remediation", "remediation.create", auditTarget("RemediationTask", task.ID, task.AssetName), model.AuditSuccess,
		"轨道="+task.Track)
	c.JSON(http.StatusCreated, task)
}

// executeRemediation 启动改造编排器异步执行工单。
func (s *Server) executeRemediation(c *gin.Context) {
	var task model.RemediationTask
	if err := s.db.First(&task, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	if task.Status == model.RemRunning {
		c.JSON(http.StatusConflict, gin.H{"error": "工单正在执行中"})
		return
	}

	// 异步执行；任务在独立上下文运行，避免随请求结束被取消（与扫描器一致）。
	orch := remediate.NewOrchestrator(s.db)
	go orch.Run(context.Background(), task.ID)

	loadTaskJSON(&task)
	s.audit(c, "remediation", "remediation.execute", auditTarget("RemediationTask", task.ID, task.AssetName), model.AuditSuccess, "")
	c.JSON(http.StatusAccepted, task)
}

// rollbackRemediation 把工单置为 rolledback，并追加一步“回滚至迁移前状态”。
func (s *Server) rollbackRemediation(c *gin.Context) {
	var task model.RemediationTask
	if err := s.db.First(&task, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}

	steps := db.UnmarshalSteps(task.StepsJSON)
	now := time.Now()
	steps = append(steps, model.Step{
		Name:   "回滚至迁移前状态",
		Status: model.StepDone,
		Detail: "已回滚设备配置至迁移前状态",
		At:     &now,
	})
	task.StepsJSON = db.MarshalSteps(steps)
	task.Status = model.RemRolledback
	task.FinishedAt = &now
	if err := s.db.Save(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadTaskJSON(&task)
	s.audit(c, "remediation", "remediation.rollback", auditTarget("RemediationTask", task.ID, task.AssetName), model.AuditSuccess, "")
	c.JSON(http.StatusOK, task)
}

// remediationSummary 返回工单状态聚合 {planned,running,done,failed,total}。
func (s *Server) remediationSummary(c *gin.Context) {
	type row struct {
		Status string
		Count  int
	}
	var rows []row
	s.db.Model(&model.RemediationTask{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&rows)

	out := gin.H{
		"planned": 0,
		"running": 0,
		"done":    0,
		"failed":  0,
		"total":   0,
	}
	total := 0
	for _, r := range rows {
		total += r.Count
		if _, ok := out[r.Status]; ok {
			out[r.Status] = r.Count
		}
	}
	out["total"] = total
	c.JSON(http.StatusOK, out)
}
