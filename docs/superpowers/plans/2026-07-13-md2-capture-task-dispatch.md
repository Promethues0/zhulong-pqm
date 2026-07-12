# M-D2 抓包任务下发 + Agent/探针 UI 管理 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 控制台一处建抓包任务，按标签选择器自动分发给一类探针（拉取式租约），探针 managed 模式领任务→抓包→上报；支持一次性与周期性；并把 Agent/探针的注册·列表·撤销集成进控制台 UI。

**Architecture:** 新增 `CaptureTask` 模型 + 管理面 CRUD（用户 JWT）+ 探针面租约端点（复用 M-B `agentAuth`）。原子租约（条件 UPDATE），标签子集匹配。周期调度复用 `scan.Scheduler` 回收过期租约 + 周期任务重入队。探针复用 M-D1 `Capture` + M-B `/agent/assets/batch`。前端两页（Agent 管理 + 抓包任务）。

**Tech Stack:** Go 1.24 纯 Go 免 CGO；GORM + glebarez SQLite；Gin；`scan.Scheduler`/`scan.NextCronRun`；Vue3 + Arco + TS。

## Global Constraints

- **纯 Go 免 CGO**；探针抓包复用 M-D1 `Capture`（AF_PACKET/tcpdump）。
- **拉取式**：探针只出不入，不引入探针入站连接。
- 结果上报复用 `POST /agent/assets/batch`（M-B，后端上报层零改动）。
- **原子租约**：领任务用条件 UPDATE（`WHERE id=? AND status='pending'`，RowsAffected==1 才算领到），防两探针领同一任务。
- **标签子集匹配**：任务 LabelSelector ⊆ 探针 Labels（空选择器任意探针可领）。
- 状态机：pending→leased→done；周期性 done→pending；leased 过期→pending；cancel→cancelled。**不设 running 态**（leased 即抓包中，heartbeat 保活）。
- 前端字节跳动蓝 #165DFF，**严禁覆写 Arco --color-***；api 层加到现有 `frontend/src/api/index.ts`（非新建 per-feature 文件）。
- commit 前缀 `feat(scope):`，中文提交信息。工作分支 `feat/md2-capture-dispatch`。

## 已确认的既有签名（勿改）

- `agentAuth()` 中间件设 `c.Set("reportedBy", ag.AgentID)`、`c.Set("agentKind", ag.Kind)`（本计划 T3 补设 `agentLabels`）。
- `reportedByCtx(c *gin.Context) string`（agents.go）。
- `db.MarshalStrings([]string) string` / `db.UnmarshalStrings(string) []string`。
- `scan.Scheduler.Register(name string, every time.Duration, run scan.JobFunc)`；`JobFunc func(ctx context.Context)`；`srv.Scheduler() *scan.Scheduler`。
- `scan.NextCronRun(cron string) *time.Time`（cron→下次时间，空/非法返回 nil）。
- `model.Agent{AgentID, Hostname, Kind, Labels []string, LabelsJSON, Status, LastSeenAt...}`；`model.AgentActive`。
- `s.audit(c, module, action, auditTarget("T", id, name), model.AuditSuccess, detail)`；`serverError(c, err)`。
- 管理路由挂 `writer`（operator/admin）/`auth`（任意登录）；探针路由挂 `agentGrp`（`agentAuth`）。前端 router `frontend/src/router/index.ts`、菜单 `frontend/src/layout/MainLayout.vue`、api `frontend/src/api/index.ts`、类型 `types.ts`。

---

## File Structure

- **Create** `backend/internal/model/capture_task.go` — `CaptureTask` 模型 + 状态常量 + `subsetOf` 帮助函数。
- **Create** `backend/internal/api/captures.go` — 管理面 CRUD + `leaseTask` + 探针面 lease/heartbeat/complete + `RegisterCaptureScheduler`。
- **Create** `backend/internal/api/captures_test.go` — 租约原子性/标签匹配/complete/回收测试。
- **Create** `backend/cmd/agent/probe_managed.go` — `runManagedProbe` 轮询领任务循环。
- **Create** `backend/cmd/agent/probe_managed_test.go` — httptest mock 一轮领取→抓→上报→完成。
- **Modify** `backend/internal/db/db.go`（AutoMigrate + CaptureTask）、`backend/internal/api/agents.go`（agentAuth 补 agentLabels）、`backend/internal/api/router.go`（管理+探针路由）、`backend/cmd/zhulong-pqm/main.go`（RegisterCaptureScheduler）、`backend/cmd/agent/config.go`（--managed/--task-poll）、`backend/cmd/agent/main.go`（managed 分派）。
- **Create** `frontend/src/views/Agents.vue`、`frontend/src/views/CaptureTasks.vue`。
- **Modify** `frontend/src/api/index.ts`、`frontend/src/api/types.ts`、`frontend/src/router/index.ts`、`frontend/src/layout/MainLayout.vue`。

---

## Task 1: CaptureTask 模型 + subsetOf

**Files:**
- Create: `backend/internal/model/capture_task.go`
- Modify: `backend/internal/db/db.go`（AutoMigrate 加 `&model.CaptureTask{}`）
- Test: `backend/internal/model/capture_task_test.go`

**Interfaces:**
- Produces: `model.CaptureTask` 结构；状态常量 `CapturePending/Leased/Done/Failed/Cancelled`；`model.SubsetOf(sel, labels []string) bool`

- [ ] **Step 1: Write the failing test**

Create `backend/internal/model/capture_task_test.go`:

```go
package model

import "testing"

func TestSubsetOf(t *testing.T) {
	cases := []struct {
		sel, labels []string
		want        bool
	}{
		{nil, []string{"机房A"}, true},                       // 空选择器任意命中
		{[]string{}, []string{"机房A"}, true},                // 同上
		{[]string{"机房A"}, []string{"机房A", "核心"}, true},  // 子集命中
		{[]string{"机房A", "核心"}, []string{"机房A", "核心"}, true},
		{[]string{"机房B"}, []string{"机房A", "核心"}, false}, // 不命中
		{[]string{"机房A"}, nil, false},                      // 探针无标签，非空选择器不命中
	}
	for _, c := range cases {
		if got := SubsetOf(c.sel, c.labels); got != c.want {
			t.Errorf("SubsetOf(%v,%v)=%v want %v", c.sel, c.labels, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/model/ -run TestSubsetOf -v`
Expected: FAIL — `SubsetOf`/`CaptureTask` 未定义。

- [ ] **Step 3: Implement model + subsetOf**

Create `backend/internal/model/capture_task.go`:

```go
package model

import "time"

// CaptureTask 分布式抓包任务（M-D2）：控制台建任务，按标签选择器分发给探针，拉取式租约领取。
type CaptureTask struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	Name              string     `gorm:"not null" json:"name"`
	LabelSelectorJSON string     `gorm:"column:label_selector;type:text" json:"-"`
	LabelSelector     []string   `gorm:"-" json:"labelSelector"` // 空=任意探针可领
	Iface             string     `json:"iface"`
	BPF               string     `gorm:"default:tcp" json:"bpf"`
	Duration          int        `gorm:"default:30" json:"duration"`
	MaxPackets        int        `gorm:"default:100000" json:"maxPackets"`
	Status            string     `gorm:"default:pending" json:"status"`
	LeasedBy          string     `json:"leasedBy"`
	LeaseExpiresAt    *time.Time `json:"leaseExpiresAt"`
	StartedAt         *time.Time `json:"startedAt"`
	FinishedAt        *time.Time `json:"finishedAt"`
	ResultCount       int        `json:"resultCount"`
	RunCount          int        `json:"runCount"`
	Error             string     `json:"error"`
	Schedule          string     `json:"schedule"` // cron，空=一次性
	ScheduleEnabled   bool       `json:"scheduleEnabled"`
	NextRunAt         *time.Time `json:"nextRunAt"`
	LastRunAt         *time.Time `json:"lastRunAt"`
	CreatedBy         string     `json:"createdBy"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

// 抓包任务状态。
const (
	CapturePending   = "pending"
	CaptureLeased    = "leased"
	CaptureDone      = "done"
	CaptureFailed    = "failed"
	CaptureCancelled = "cancelled"
)

// SubsetOf 判 sel 是否是 labels 的子集（sel 每个标签都在 labels 里）。空 sel 恒真（任意探针可领）。
func SubsetOf(sel, labels []string) bool {
	if len(sel) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		set[l] = struct{}{}
	}
	for _, s := range sel {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
```

在 `backend/internal/db/db.go` 的 `AutoMigrate(...)` 清单里，`&model.Agent{},` 之后加：

```go
		&model.CaptureTask{},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/model/ -run TestSubsetOf -v && go build ./...`
Expected: PASS + 编译过。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/model/capture_task.go internal/model/capture_task_test.go internal/db/db.go
git commit -m "feat(model): CaptureTask 抓包任务模型 + SubsetOf 标签子集匹配 + AutoMigrate"
```

---

## Task 2: 管理面 CRUD + leaseTask 原子租约

**Files:**
- Create: `backend/internal/api/captures.go`
- Modify: `backend/internal/api/router.go`（管理路由）
- Test: `backend/internal/api/captures_test.go`

**Interfaces:**
- Consumes: `model.CaptureTask`、`model.SubsetOf`、`db.Marshal/UnmarshalStrings`、`scan.NextCronRun`
- Produces: `createCapture/listCaptures/getCapture/cancelCapture/deleteCapture` 处理器；`func (s *Server) leaseTask(agentID string, agentLabels []string) (*model.CaptureTask, bool)`；`leaseDuration(t) time.Duration`

- [ ] **Step 1: Write the failing test**

Create `backend/internal/api/captures_test.go`:

```go
package api

import (
	"testing"
	"time"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

func newCaptureTask(gdb, name string, sel []string) *model.CaptureTask { return nil } // placeholder replaced below

func TestLeaseTask_AtomicAndLabelMatch(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	s := &Server{db: gdb}
	mk := func(name string, sel []string) {
		gdb.Create(&model.CaptureTask{Name: name, LabelSelectorJSON: db.MarshalStrings(sel),
			Status: model.CapturePending, Duration: 10})
	}
	mk("任意", nil)
	mk("机房A专用", []string{"机房A"})
	mk("机房B专用", []string{"机房B"})

	// 探针 labels=[机房A] → 可领 "任意" 或 "机房A专用"，不可领 "机房B专用"
	got, ok := s.leaseTask("agent-1", []string{"机房A"})
	if !ok || (got.Name != "任意" && got.Name != "机房A专用") {
		t.Fatalf("机房A 探针领到 %+v ok=%v", got, ok)
	}
	if got.Status != model.CaptureLeased || got.LeasedBy != "agent-1" {
		t.Errorf("租约状态错: %+v", got)
	}

	// 原子性：把剩下的 pending 都标签设为 [机房B]，机房A 探针应领不到（返回 false）
	gdb.Model(&model.CaptureTask{}).Where("status = ?", model.CapturePending).
		Update("label_selector", db.MarshalStrings([]string{"机房B"}))
	if _, ok := s.leaseTask("agent-1", []string{"机房A"}); ok {
		t.Error("机房A 探针不应领到 机房B 任务")
	}
	// 机房B 探针可领
	if _, ok := s.leaseTask("agent-2", []string{"机房B"}); !ok {
		t.Error("机房B 探针应能领到")
	}
}

func TestLeaseTask_LeaseDuration(t *testing.T) {
	if d := leaseDuration(&model.CaptureTask{Duration: 10}); d < 120*time.Second {
		t.Errorf("短任务租约应≥120s，得 %v", d)
	}
	if d := leaseDuration(&model.CaptureTask{Duration: 300}); d < 600*time.Second {
		t.Errorf("长任务租约应≥2×时长，得 %v", d)
	}
}
```

（删除占位 `newCaptureTask` 行——写实现时不需要它。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestLeaseTask -v`
Expected: FAIL — `leaseTask`/`leaseDuration` 未定义。

- [ ] **Step 3: Implement captures.go 管理面 + leaseTask**

Create `backend/internal/api/captures.go`:

```go
package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

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
```

在 `router.go` 的 `writer`/`auth` 组里（devices 路由附近）加：

```go
		auth.GET("/captures", s.listCaptures)
		auth.GET("/captures/:id", s.getCapture)
		writer.POST("/captures", s.createCapture)
		writer.POST("/captures/:id/cancel", s.cancelCapture)
		writer.DELETE("/captures/:id", s.deleteCapture)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd backend && go test ./internal/api/ -run TestLeaseTask -v`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/api/captures.go internal/api/captures_test.go internal/api/router.go
git commit -m "feat(capture): 抓包任务管理面 CRUD + leaseTask 原子租约(标签子集匹配)"
```

---

## Task 3: 探针面租约端点 + agentAuth 标签

**Files:**
- Modify: `backend/internal/api/agents.go`（agentAuth 补 `c.Set("agentLabels", ...)`）
- Modify: `backend/internal/api/captures.go`（加 leaseTaskHandler/heartbeat/complete）
- Modify: `backend/internal/api/router.go`（agent 任务路由）
- Test: `backend/internal/api/captures_test.go`（追加）

**Interfaces:**
- Consumes: `leaseTask`、`agentLabels` context、`scan.NextCronRun`
- Produces: `agentLeaseTask/agentHeartbeat/agentCompleteTask` 处理器；context key `agentLabels []string`

- [ ] **Step 1: Write the failing test**

在 `captures_test.go` 追加（直接测 complete 的状态流转，不走 HTTP）：

```go
func TestCompleteTask_OneShotAndRecurring(t *testing.T) {
	gdb, _ := db.Open(":memory:")
	s := &Server{db: gdb}

	// 一次性：complete → done
	one := model.CaptureTask{Name: "一次性", Status: model.CaptureLeased, LeasedBy: "a1"}
	gdb.Create(&one)
	s.applyComplete(&one, "a1", 7)
	if one.Status != model.CaptureDone || one.ResultCount != 7 || one.RunCount != 1 {
		t.Errorf("一次性完成态错: %+v", one)
	}

	// 周期性：complete → pending + NextRunAt 非空
	rec := model.CaptureTask{Name: "周期", Status: model.CaptureLeased, LeasedBy: "a1",
		ScheduleEnabled: true, Schedule: "0 * * * *"}
	gdb.Create(&rec)
	s.applyComplete(&rec, "a1", 3)
	if rec.Status != model.CapturePending || rec.NextRunAt == nil || rec.LeasedBy != "" {
		t.Errorf("周期完成应回 pending+NextRunAt+清 LeasedBy: %+v", rec)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestCompleteTask -v`
Expected: FAIL — `applyComplete` 未定义。

- [ ] **Step 3: agentAuth 补 agentLabels**

在 `agents.go` 的 `agentAuth()` 里，`c.Set("agentKind", ag.Kind)` 之后加：

```go
		c.Set("agentLabels", db.UnmarshalStrings(ag.LabelsJSON))
```

（`agents.go` 顶部 import 加 `"zhulong-pqm/internal/db"` 若未有。）

- [ ] **Step 4: Implement 探针面端点 + applyComplete**

在 `captures.go` 追加：

```go
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
```

在 `router.go` 的 `agentGrp` 组里加：

```go
	agentGrp.GET("/tasks", s.agentLeaseTask)
	agentGrp.POST("/tasks/:id/heartbeat", s.agentHeartbeat)
	agentGrp.POST("/tasks/:id/complete", s.agentCompleteTask)
```

- [ ] **Step 5: Run tests + build**

Run: `cd backend && go test ./internal/api/ -run 'TestLeaseTask|TestCompleteTask' -v && go build ./...`
Expected: PASS + 编译过。

- [ ] **Step 6: Commit**

```bash
cd backend && git add internal/api/captures.go internal/api/agents.go internal/api/router.go internal/api/captures_test.go
git commit -m "feat(capture): 探针面租约端点(GET tasks/heartbeat/complete) + agentAuth 补标签 + 完成态流转"
```

---

## Task 4: 周期调度 + 租约回收

**Files:**
- Modify: `backend/internal/api/captures.go`（加 `RegisterCaptureScheduler`）
- Modify: `backend/cmd/zhulong-pqm/main.go`（注册）
- Test: `backend/internal/api/captures_test.go`（追加）

**Interfaces:**
- Consumes: `scan.Scheduler.Register`、`model.CaptureTask`
- Produces: `func RegisterCaptureScheduler(sched *scan.Scheduler, gdb *gorm.DB)`；`func reclaimAndReschedule(gdb *gorm.DB)`（可测的核心逻辑）

- [ ] **Step 1: Write the failing test**

在 `captures_test.go` 追加：

```go
func TestReclaimAndReschedule(t *testing.T) {
	gdb, _ := db.Open(":memory:")
	past := time.Now().Add(-time.Hour)
	// 过期租约 → 应回 pending
	expired := model.CaptureTask{Name: "过期", Status: model.CaptureLeased, LeasedBy: "a1", LeaseExpiresAt: &past}
	gdb.Create(&expired)
	// 周期 done 到点 → 应回 pending
	due := model.CaptureTask{Name: "到点", Status: model.CaptureDone, ScheduleEnabled: true, Schedule: "0 * * * *", NextRunAt: &past}
	gdb.Create(&due)
	// 未到点周期 done → 不动
	future := time.Now().Add(time.Hour)
	notdue := model.CaptureTask{Name: "未到", Status: model.CaptureDone, ScheduleEnabled: true, Schedule: "0 * * * *", NextRunAt: &future}
	gdb.Create(&notdue)

	reclaimAndReschedule(gdb)

	var e, d, n model.CaptureTask
	gdb.First(&e, expired.ID); gdb.First(&d, due.ID); gdb.First(&n, notdue.ID)
	if e.Status != model.CapturePending || e.LeasedBy != "" {
		t.Errorf("过期租约应回 pending 清 LeasedBy: %+v", e)
	}
	if d.Status != model.CapturePending {
		t.Errorf("到点周期任务应回 pending: %+v", d)
	}
	if n.Status != model.CaptureDone {
		t.Errorf("未到点周期任务不应动: %+v", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestReclaimAndReschedule -v`
Expected: FAIL — `reclaimAndReschedule` 未定义。

- [ ] **Step 3: Implement**

在 `captures.go` 追加（顶部 import 加 `"context"`、`"gorm.io/gorm"`）：

```go
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
```

在 `cmd/zhulong-pqm/main.go` 的 `api.RegisterDailySnapshot(...)` 之后、`srv.Scheduler().Start(...)` 之前加：

```go
	api.RegisterCaptureScheduler(srv.Scheduler(), database)
```

- [ ] **Step 4: Run test + build**

Run: `cd backend && go test ./internal/api/ -run TestReclaim -v && go build ./...`
Expected: PASS + 编译过。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/api/captures.go cmd/zhulong-pqm/main.go internal/api/captures_test.go
git commit -m "feat(capture): 周期调度(过期租约回收+周期任务重入队) 复用 scan.Scheduler"
```

---

## Task 5: 探针 managed 轮询模式

**Files:**
- Modify: `backend/cmd/agent/config.go`（--managed/--task-poll）
- Create: `backend/cmd/agent/probe_managed.go`
- Modify: `backend/cmd/agent/main.go`（managed 分派）
- Test: `backend/cmd/agent/probe_managed_test.go`

**Interfaces:**
- Consumes: `Config`、`Capture`、`assetsFromPcap`、`reportAssets`、`wrapPcap`（测试）
- Produces: `Config.Managed bool`、`Config.TaskPoll int`；`func runManagedProbe(cfg Config) error`；`func pollAndRunOne(cfg Config) (bool, error)`（单轮，可测）

- [ ] **Step 1: Write the failing test**

Create `backend/cmd/agent/probe_managed_test.go`:

```go
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPollAndRunOne_LeaseCaptureReportComplete(t *testing.T) {
	var completed atomic.Bool
	var reported atomic.Int32

	mux := http.NewServeMux()
	// 领任务：返一个 duration=1 的任务
	mux.HandleFunc("/api/v1/agent/tasks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "iface": "", "bpf": "tcp", "duration": 1, "maxPackets": 100})
	})
	// 上报观测
	mux.HandleFunc("/api/v1/agent/assets/batch", func(w http.ResponseWriter, r *http.Request) {
		reported.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"created": 0, "updated": 0})
	})
	// 报完成
	mux.HandleFunc("/api/v1/agent/tasks/42/complete", func(w http.ResponseWriter, r *http.Request) {
		completed.Store(true)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "done"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 注入假抓包：返回一个含 ServerHello(0x11EC) 的 pcap 字节流
	captureFn = func(cfg *Config) ([]byte, error) {
		return wrapPcap([][]byte{tlsFrame(serverHelloKeyShare(0x11EC), [4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 9}, 443, 40000)}), nil
	}
	defer func() { captureFn = Capture }()

	cfg := Config{Server: srv.URL, Key: "k", Role: "probe", Managed: true}
	got, err := pollAndRunOne(cfg)
	if err != nil {
		t.Fatalf("pollAndRunOne err: %v", err)
	}
	if !got {
		t.Fatal("应领到并执行一个任务")
	}
	if reported.Load() == 0 || !completed.Load() {
		t.Errorf("应上报观测且报完成: reported=%d completed=%v", reported.Load(), completed.Load())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./cmd/agent/ -run TestPollAndRunOne -v`
Expected: FAIL — `captureFn`/`pollAndRunOne`/`Config.Managed` 未定义。

- [ ] **Step 3: config 加字段**

在 `config.go` 的 `Config` 结构 `CaptureMode string` 之后加：

```go
	Managed  bool // 探针 managed 模式：轮询领服务端下发的抓包任务
	TaskPoll int  // managed 轮询间隔（秒）
```

在 `loadConfig` 的 capture-mode flag 之后加：

```go
	fs.BoolVar(&cfg.Managed, "managed", envBoolOr("ZPQM_AGENT_MANAGED", false), "探针 managed 模式：轮询领服务端下发的抓包任务")
	fs.IntVar(&cfg.TaskPoll, "task-poll", envIntOr("ZPQM_AGENT_TASK_POLL", 15), "managed 轮询间隔（秒）")
```

- [ ] **Step 4: Implement probe_managed.go**

Create `backend/cmd/agent/probe_managed.go`:

```go
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// agentHTTPClient 构造上报用 http 客户端（--insecure 时跳过 TLS 校验），与 report.go 同口径。
func agentHTTPClient(cfg Config) *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg.Insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- 用户显式 --insecure
	}
	return client
}

// captureFn 抓包函数（默认 Capture；测试可注入假实现）。
var captureFn = Capture

// leasedTask 服务端下发的抓包任务（GET /agent/tasks 的响应子集）。
type leasedTask struct {
	ID         uint   `json:"id"`
	Iface      string `json:"iface"`
	BPF        string `json:"bpf"`
	Duration   int    `json:"duration"`
	MaxPackets int    `json:"maxPackets"`
}

// runManagedProbe managed 探针主循环：轮询领任务→抓→上报→报完成；无任务则 sleep 再轮询。
func runManagedProbe(cfg Config) error {
	poll := cfg.TaskPoll
	if poll <= 0 {
		poll = 15
	}
	fmt.Printf("探针 managed 模式启动，每 %ds 轮询领任务\n", poll)
	for {
		ran, err := pollAndRunOne(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "本轮出错:", err)
		}
		if !ran {
			time.Sleep(time.Duration(poll) * time.Second)
		}
	}
}

// pollAndRunOne 领并执行一个任务。领到并跑完返回 (true,nil)；无任务返回 (false,nil)。
func pollAndRunOne(cfg Config) (bool, error) {
	task, ok, err := leaseTaskHTTP(cfg)
	if err != nil || !ok {
		return false, err
	}
	fmt.Printf("领到抓包任务 #%d（iface=%s bpf=%s dur=%ds）\n", task.ID, task.Iface, task.BPF, task.Duration)
	// 用任务参数覆盖抓包配置
	tcfg := cfg
	tcfg.Iface, tcfg.BPF, tcfg.Duration, tcfg.MaxPackets = task.Iface, task.BPF, task.Duration, task.MaxPackets
	// 心跳保活
	stop := make(chan struct{})
	go heartbeatLoop(cfg, task.ID, stop)

	pcapBytes, cerr := captureFn(&tcfg)
	close(stop)
	if cerr != nil {
		completeTaskHTTP(cfg, task.ID, 0, cerr.Error())
		return true, cerr
	}
	assets, stats, perr := assetsFromPcap(pcapBytes)
	if perr != nil {
		completeTaskHTTP(cfg, task.ID, 0, perr.Error())
		return true, perr
	}
	fmt.Printf("任务 #%d 抓包：%d 包 / %d 握手 → %d 观测\n", task.ID, stats.Packets, stats.Handshakes, len(assets))
	if rerr := reportAssets(cfg, assets); rerr != nil {
		completeTaskHTTP(cfg, task.ID, 0, rerr.Error())
		return true, rerr
	}
	return true, completeTaskHTTP(cfg, task.ID, len(assets), "")
}

func leaseTaskHTTP(cfg Config) (leasedTask, bool, error) {
	var t leasedTask
	req, _ := http.NewRequest(http.MethodGet, apiURL(cfg, "/api/v1/agent/tasks"), nil)
	req.Header.Set("X-Agent-Key", cfg.Key)
	resp, err := agentHTTPClient(cfg).Do(req)
	if err != nil {
		return t, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return t, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return t, false, fmt.Errorf("领任务 HTTP %d: %s", resp.StatusCode, string(b))
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return t, false, err
	}
	return t, true, nil
}

func heartbeatLoop(cfg Config, id uint, stop chan struct{}) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			req, _ := http.NewRequest(http.MethodPost, apiURL(cfg, fmt.Sprintf("/api/v1/agent/tasks/%d/heartbeat", id)), nil)
			req.Header.Set("X-Agent-Key", cfg.Key)
			if resp, err := agentHTTPClient(cfg).Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
}

func completeTaskHTTP(cfg Config, id uint, resultCount int, errMsg string) error {
	body, _ := json.Marshal(map[string]any{"resultCount": resultCount, "error": errMsg})
	req, _ := http.NewRequest(http.MethodPost, apiURL(cfg, fmt.Sprintf("/api/v1/agent/tasks/%d/complete", id)), bytes.NewReader(body))
	req.Header.Set("X-Agent-Key", cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := agentHTTPClient(cfg).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func apiURL(cfg Config, path string) string { return strings.TrimRight(cfg.Server, "/") + path }
```

> 说明：本文件自带 `agentHTTPClient(cfg)`（与 report.go 同口径的 client 构造，含 --insecure 处理），日志用 `os.Stderr`——均不依赖 report.go 未导出的名字，直接可编译。

- [ ] **Step 5: main.go managed 分派**

在 `main.go` 的 `runOnce` 里，`if cfg.Role == model.AgentKindProbe {` 分支改为：

```go
		if cfg.Role == model.AgentKindProbe {
			if cfg.Managed {
				return runManagedProbe(cfg) // 常驻轮询领任务，不返回
			}
			return runProbe(cfg) // M-D1 配置驱动一次性抓
		}
```

- [ ] **Step 6: Run test + build + 交叉编译**

Run:
```bash
cd backend && go test ./cmd/agent/ -run TestPollAndRunOne -v && go build ./... && \
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/m1 ./cmd/agent && \
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/m2 ./cmd/agent && echo OK
```
Expected: PASS + 双架构编译过。

- [ ] **Step 7: Commit**

```bash
cd backend && git add cmd/agent/config.go cmd/agent/probe_managed.go cmd/agent/main.go cmd/agent/probe_managed_test.go
git commit -m "feat(agent): 探针 managed 模式(轮询领任务→抓→上报→报完成，心跳保活)"
```

---

## Task 6: 前端 Agent/探针管理页

**Files:**
- Create: `frontend/src/views/Agents.vue`
- Modify: `frontend/src/api/index.ts`、`frontend/src/api/types.ts`、`frontend/src/router/index.ts`、`frontend/src/layout/MainLayout.vue`

**Interfaces:**
- Consumes: `GET/POST /agents`、`POST /agents/:id/revoke`

- [ ] **Step 1: 读现有结构**

先读 `frontend/src/api/index.ts`（看 axios 封装与 `xxxApi` 导出模式）、一个现有 CRUD view（如 `RuleLibrary.vue`）、`router/index.ts`、`layout/MainLayout.vue`（菜单结构）。**按现有模式** mirror，勿另起风格。

- [ ] **Step 2: types.ts 加 Agent**

在 `frontend/src/api/types.ts` 加：

```ts
export interface Agent {
  id: number
  agentId: string
  hostname: string
  kind: 'host' | 'probe' | 'both'
  labels?: string[]
  status: 'active' | 'revoked'
  version?: string
  os?: string
  lastSeenAt?: string | null
  enrolledAt?: string
}
```

- [ ] **Step 3: api/index.ts 加 agentApi**

按现有 `xxxApi` 模式，在 `frontend/src/api/index.ts` 加：

```ts
export const agentApi = {
  list: () => client.get('/agents').then(r => r.data.agents as Agent[]),
  create: (body: { hostname: string; kind: string; labels: string[]; os?: string }) =>
    client.post('/agents', body).then(r => r.data as { agent: Agent; apiKey: string }),
  revoke: (id: number) => client.post(`/agents/${id}/revoke`).then(r => r.data),
}
```

（`Agent` 类型 import 按文件现有方式；`client` 为现有 axios 实例。）

- [ ] **Step 4: Agents.vue（mirror 现有 CRUD view 风格）**

Create `frontend/src/views/Agents.vue`：列表（agentId/hostname/kind/status/labels/lastSeenAt）+ 「注册 Agent」按钮开抽屉（hostname/kind 下拉/labels 标签输入）→ 调 `agentApi.create` → **弹窗显示一次性 apiKey**（`a-modal` + `a-typography-text copyable` + 「仅显示一次，请立即保存」红字警示）→ 关闭后刷新列表。每行「撤销」按钮（`a-popconfirm` 二次确认 → `agentApi.revoke`）。用 Arco `a-table`/`a-tag`（kind/status 着色）/`a-drawer`/`a-modal`，`onMounted` 加载 + 操作后刷新。**只用 Arco 组件与现有 --brand-* token，不碰 --color-***。

关键片段（apiKey 一次性弹窗）：

```vue
<a-modal v-model:visible="keyModal" title="Agent 已注册" :footer="false">
  <a-alert type="warning" style="margin-bottom:12px">apiKey 仅显示一次，平台只存哈希，请立即保存</a-alert>
  <a-typography-text copyable :copy-text="newKey">{{ newKey }}</a-typography-text>
</a-modal>
```

- [ ] **Step 5: 路由 + 菜单**

`router/index.ts` 加路由 `{ path: 'agents', name: 'agents', component: () => import('@/views/Agents.vue') }`（按现有子路由格式）。`layout/MainLayout.vue` 菜单加「探针管理 → Agent 管理」项（图标用 Arco 现有如 `IconRobot`/`IconDesktop`）。

- [ ] **Step 6: 构建验证**

Run: `cd frontend && npm run build`
Expected: `vue-tsc --noEmit` 无错 + vite 构建成功。

- [ ] **Step 7: Commit**

```bash
cd frontend && git add src/views/Agents.vue src/api/index.ts src/api/types.ts src/router/index.ts src/layout/MainLayout.vue
git commit -m "feat(ui): Agent/探针管理页(注册→一次性apiKey弹窗/列表/撤销)"
```

---

## Task 7: 前端抓包任务页

**Files:**
- Create: `frontend/src/views/CaptureTasks.vue`
- Modify: `frontend/src/api/index.ts`、`frontend/src/api/types.ts`、`frontend/src/router/index.ts`、`frontend/src/layout/MainLayout.vue`

**Interfaces:**
- Consumes: `GET/POST /captures`、`POST /captures/:id/cancel`、`DELETE /captures/:id`、`agentApi.list`（取标签选项）

- [ ] **Step 1: types.ts 加 CaptureTask**

```ts
export interface CaptureTask {
  id: number
  name: string
  labelSelector?: string[]
  iface?: string
  bpf?: string
  duration?: number
  maxPackets?: number
  status: 'pending' | 'leased' | 'done' | 'failed' | 'cancelled'
  leasedBy?: string
  resultCount?: number
  runCount?: number
  schedule?: string
  scheduleEnabled?: boolean
  nextRunAt?: string | null
  createdAt?: string
}
```

- [ ] **Step 2: api/index.ts 加 captureApi**

```ts
export const captureApi = {
  list: () => client.get('/captures').then(r => r.data.captures as CaptureTask[]),
  create: (body: Partial<CaptureTask>) => client.post('/captures', body).then(r => r.data as CaptureTask),
  cancel: (id: number) => client.post(`/captures/${id}/cancel`).then(r => r.data),
  remove: (id: number) => client.delete(`/captures/${id}`).then(r => r.data),
}
```

- [ ] **Step 3: CaptureTasks.vue（mirror 现有 CRUD view）**

Create `frontend/src/views/CaptureTasks.vue`：列表（名称/标签选择器/状态着色/领取探针 leasedBy/结果数 resultCount/下次运行 nextRunAt）+「新建任务」抽屉（名称、标签多选[选项 = `agentApi.list()` 里所有 agent 的 labels 并集]、网卡、BPF[默认 tcp]、时长[默认 30]、包数上限、周期开关 + cron 输入）→ `captureApi.create` → 刷新。每行「取消」（对 pending/leased）/「删除」（`a-popconfirm`）。状态着色：pending=灰/leased=蓝(arcoblue)/done=绿/failed=红/cancelled=灰。**~2s 自动轮询刷新列表**（`setInterval`，`onUnmounted` 清）。用 Arco 组件 + 现有 token。

- [ ] **Step 4: 路由 + 菜单**

`router/index.ts` 加 `{ path: 'captures', name: 'captures', component: () => import('@/views/CaptureTasks.vue') }`；菜单「探针管理」组下加「抓包任务」项。

- [ ] **Step 5: 构建验证**

Run: `cd frontend && npm run build`
Expected: vue-tsc + vite 成功。

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/views/CaptureTasks.vue src/api/index.ts src/api/types.ts src/router/index.ts src/layout/MainLayout.vue
git commit -m "feat(ui): 抓包任务页(建任务/标签多选/状态轮询/取消删除)"
```

---

## Task 8: 文档 + 全量验证

**Files:**
- Modify: `docs/主机Agent安装手册.md`、`CLAUDE.md`

- [ ] **Step 1: 安装手册加 managed 一节**

在 `docs/主机Agent安装手册.md` §8 探针模式后追加：

```markdown
### 8.1 managed 模式（控制台下发任务）

探针不写死本地抓包参数，而是**轮询领取控制台下发的抓包任务**（拉取式，探针只出不入）：

​```bash
sudo ZPQM_AGENT_SERVER=http://<平台>:8099 ZPQM_AGENT_KEY=zpqm-agent-.... \
  ./zhulong-pqm-agent --role=probe --managed --task-poll=15
​```

在控制台「探针管理 → 抓包任务」建任务，用**标签选择器**分发：任务的标签是探针注册时 Labels 的子集即被该探针领取（空选择器任意探针可领）。支持周期性（cron）。任务领取/心跳/完成全自动，结果按来源=agent 落清单。
```

在 `CLAUDE.md` 架构地图补：`captures.go(M-D2 抓包任务下发:标签选择器+拉取式租约+周期调度)` 与前端 `Agents.vue/CaptureTasks.vue(探针管理)`。

- [ ] **Step 2: 全量验证**

Run:
```bash
cd backend && go build ./... && go vet ./... && go test ./... 2>&1 | grep -E "FAIL|ok " && \
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/v1 ./cmd/agent && \
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/v2 ./cmd/zhulong-pqm && echo "BACKEND OK"
cd ../frontend && npm run build 2>&1 | tail -3
```
Expected: 后端全绿 + 双架构编译过；前端构建成功。

- [ ] **Step 3: Commit**

```bash
cd /Users/prometheus/Projects/zhulong-pqm && git add docs/主机Agent安装手册.md CLAUDE.md
git commit -m "docs: M-D2 managed 模式 + Agent/探针管理 UI 说明"
```

---

## Self-Review

**1. Spec coverage（对照 spec §1-§9）：**
- §1 CaptureTask 模型 → T1 ✓
- §2 拉取式租约 + 原子租约 + 标签匹配 → T2(leaseTask) ✓
- §3 API 端点（管理面 + 探针面）→ T2 + T3 ✓
- §4 探针 managed → T5 ✓
- §5 周期调度 + 租约回收 → T4 ✓
- §6 控制台两页（Agent 管理 + 抓包任务）→ T6 + T7 ✓
- §7 错误处理（租约回收/LeasedBy 校验/cancel）→ T2/T3/T4 ✓
- §8 测试 → 每任务 TDD + T8 全量 ✓
- §9 文件清单 → 全覆盖 ✓

**2. Placeholder scan：** 无 TBD/TODO。T2 测试有一处占位 `newCaptureTask` 函数明确标注「写实现时删除」；T5 自带 `agentHTTPClient` 助手（不依赖 report.go 未导出名），无外部未定义引用。

**3. Type consistency：** `leaseTask(agentID string, agentLabels []string)(*model.CaptureTask,bool)`、`applyComplete(*model.CaptureTask,string,int)`、`reclaimAndReschedule(*gorm.DB)`、`RegisterCaptureScheduler(*scan.Scheduler,*gorm.DB)`、`pollAndRunOne(Config)(bool,error)`、`captureFn=Capture`、状态常量 `model.Capture*` 全链一致。前端 `Agent`/`CaptureTask` 类型字段与后端 JSON tag 对齐（agentId/labelSelector/leasedBy/nextRunAt 驼峰）。`scan.NextCronRun` 返回 `*time.Time` 直接赋 `NextRunAt`。

**执行时注意（非阻塞）：** 前端 T6/T7 按实际 `api/index.ts`/router/menu 结构 mirror（结构以现有文件为准）。已核实：report.go 无共享 client 助手，故 T5 自带 `agentHTTPClient`。
