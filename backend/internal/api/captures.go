package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// leaseDuration 任务租约时长：max(时长×2, 120s)，够抓包+上传+心跳间隙。
func leaseDuration(t *model.CaptureTask) time.Duration {
	d := time.Duration(t.Duration*2) * time.Second
	if d < 120*time.Second {
		d = 120 * time.Second
	}
	return d
}

// leaseTask 为探针原子领取一个标签匹配的 pending 任务。返回 (任务, 是否领到)。
// 拉取候选 pending 任务，Go 侧过滤标签子集，逐个尝试条件 UPDATE 抢占（RowsAffected==1 即领到）。
func (s *Server) leaseTask(agentID string, agentLabels []string) (*model.CaptureTask, bool) {
	var pend []model.CaptureTask
	s.db.Where("status = ?", model.CapturePending).Order("created_at asc").Find(&pend)
	for i := range pend {
		t := &pend[i]
		if !model.SubsetOf(db.UnmarshalStrings(t.LabelSelectorJSON), agentLabels) {
			continue
		}
		now := time.Now()
		exp := now.Add(leaseDuration(t))
		res := s.db.Model(&model.CaptureTask{}).
			Where("id = ? AND status = ?", t.ID, model.CapturePending).
			Updates(map[string]interface{}{
				"status": model.CaptureLeased, "leased_by": agentID,
				"lease_expires_at": &exp, "started_at": &now,
			})
		if res.Error == nil && res.RowsAffected == 1 {
			var out model.CaptureTask
			s.db.First(&out, t.ID)
			out.LabelSelector = db.UnmarshalStrings(out.LabelSelectorJSON)
			return &out, true
		}
	}
	return nil, false
}

// ---- 管理面 CRUD（用户 JWT）----

type captureReq struct {
	Name            string   `json:"name"`
	LabelSelector   []string `json:"labelSelector"`
	Iface           string   `json:"iface"`
	BPF             string   `json:"bpf"`
	Duration        int      `json:"duration"`
	MaxPackets      int      `json:"maxPackets"`
	Schedule        string   `json:"schedule"`
	ScheduleEnabled bool     `json:"scheduleEnabled"`
}

func (s *Server) createCapture(c *gin.Context) {
	var req captureReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name 必填"})
		return
	}
	t := model.CaptureTask{
		Name: req.Name, LabelSelectorJSON: db.MarshalStrings(req.LabelSelector),
		Iface: req.Iface, BPF: firstNonEmpty(req.BPF, "tcp"),
		Duration: orDefault(req.Duration, 30), MaxPackets: orDefault(req.MaxPackets, 100000),
		Status: model.CapturePending, Schedule: req.Schedule, ScheduleEnabled: req.ScheduleEnabled,
	}
	if req.ScheduleEnabled && req.Schedule != "" {
		t.NextRunAt = scan.NextCronRun(req.Schedule)
	}
	if v, ok := c.Get("username"); ok {
		t.CreatedBy, _ = v.(string)
	}
	if err := s.db.Create(&t).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "capture", "capture.create", auditTarget("CaptureTask", t.ID, t.Name), model.AuditSuccess, "抓包任务")
	t.LabelSelector = req.LabelSelector
	c.JSON(http.StatusCreated, t)
}

func (s *Server) listCaptures(c *gin.Context) {
	var tasks []model.CaptureTask
	if err := s.db.Order("id desc").Find(&tasks).Error; err != nil {
		serverError(c, err)
		return
	}
	for i := range tasks {
		tasks[i].LabelSelector = db.UnmarshalStrings(tasks[i].LabelSelectorJSON)
	}
	c.JSON(http.StatusOK, gin.H{"captures": tasks})
}

func (s *Server) getCapture(c *gin.Context) {
	var t model.CaptureTask
	if err := s.db.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	t.LabelSelector = db.UnmarshalStrings(t.LabelSelectorJSON)
	c.JSON(http.StatusOK, t)
}

func (s *Server) cancelCapture(c *gin.Context) {
	var t model.CaptureTask
	if err := s.db.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	t.Status = model.CaptureCancelled
	t.ScheduleEnabled = false
	if err := s.db.Save(&t).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "capture", "capture.cancel", auditTarget("CaptureTask", t.ID, t.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) deleteCapture(c *gin.Context) {
	if err := s.db.Delete(&model.CaptureTask{}, c.Param("id")).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "capture", "capture.delete", auditTarget("CaptureTask", 0, c.Param("id")), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// ---- 探针面租约端点（agentAuth，X-Agent-Key）----

// agentLabelsCtx 从上下文取探针标签（agentAuth 设）。
func agentLabelsCtx(c *gin.Context) []string {
	if v, ok := c.Get("agentLabels"); ok {
		if ls, ok := v.([]string); ok {
			return ls
		}
	}
	return nil
}

// agentLeaseTask 探针领任务：GET /agent/tasks。无匹配返回 204。
func (s *Server) agentLeaseTask(c *gin.Context) {
	agentID := reportedByCtx(c)
	task, ok := s.leaseTask(agentID, agentLabelsCtx(c))
	if !ok {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(http.StatusOK, task)
}

// agentHeartbeat 探针续租：POST /agent/tasks/:id/heartbeat。校验 LeasedBy==本探针。
func (s *Server) agentHeartbeat(c *gin.Context) {
	agentID := reportedByCtx(c)
	var t model.CaptureTask
	if err := s.db.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	if t.LeasedBy != agentID || t.Status != model.CaptureLeased {
		c.JSON(http.StatusConflict, gin.H{"error": "任务非本探针持有或已终态", "status": t.Status})
		return
	}
	exp := time.Now().Add(leaseDuration(&t))
	s.db.Model(&t).Update("lease_expires_at", &exp)
	c.JSON(http.StatusOK, gin.H{"ok": true, "leaseExpiresAt": exp})
}

// agentCompleteTask 探针报完成：POST /agent/tasks/:id/complete {resultCount}。
func (s *Server) agentCompleteTask(c *gin.Context) {
	agentID := reportedByCtx(c)
	var req struct {
		ResultCount int    `json:"resultCount"`
		Error       string `json:"error"`
	}
	_ = c.ShouldBindJSON(&req)
	var t model.CaptureTask
	if err := s.db.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	if t.LeasedBy != agentID || t.Status != model.CaptureLeased {
		c.JSON(http.StatusConflict, gin.H{"error": "任务非本探针持有或已终态", "status": t.Status})
		return
	}
	if req.Error != "" {
		t.Status = model.CaptureFailed
		t.Error = req.Error
		s.db.Save(&t)
		c.JSON(http.StatusOK, gin.H{"ok": true, "status": t.Status})
		return
	}
	s.applyComplete(&t, agentID, req.ResultCount)
	s.db.Save(&t)
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": t.Status})
}

// applyComplete 完成态流转：一次性→done；周期性→回 pending+NextRunAt。就地改 t，不落库（调用方 Save）。
func (s *Server) applyComplete(t *model.CaptureTask, agentID string, resultCount int) {
	now := time.Now()
	t.ResultCount = resultCount
	t.RunCount++
	t.LastRunAt = &now
	t.Error = ""
	if t.ScheduleEnabled && t.Schedule != "" {
		t.Status = model.CapturePending
		t.LeasedBy = ""
		t.LeaseExpiresAt = nil
		t.NextRunAt = scan.NextCronRun(t.Schedule)
	} else {
		t.Status = model.CaptureDone
		t.FinishedAt = &now
	}
}

// ---- 周期调度 + 租约回收（复用 scan.Scheduler）----

// reclaimAndReschedule 回收过期租约 + 周期任务到点重入队。调度器周期调用；也可单测。
func reclaimAndReschedule(gdb *gorm.DB) {
	now := time.Now()
	// 1) 过期租约 → pending（清 LeasedBy）
	gdb.Model(&model.CaptureTask{}).
		Where("status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?", model.CaptureLeased, now).
		Updates(map[string]interface{}{"status": model.CapturePending, "leased_by": "", "lease_expires_at": nil})
	// 2) 周期 done 到点 → pending
	gdb.Model(&model.CaptureTask{}).
		Where("schedule_enabled = ? AND status = ? AND next_run_at IS NOT NULL AND next_run_at < ?", true, model.CaptureDone, now).
		Updates(map[string]interface{}{"status": model.CapturePending})
}

// RegisterCaptureScheduler 注册抓包任务调度：周期回收过期租约 + 周期任务重入队。
func RegisterCaptureScheduler(sched *scan.Scheduler, gdb *gorm.DB) {
	sched.Register("capture-dispatch", 30*time.Second, func(ctx context.Context) {
		reclaimAndReschedule(gdb)
	})
}
