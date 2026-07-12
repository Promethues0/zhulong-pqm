# 设计：M-D2 服务端抓包任务下发 + Agent/探针 UI 管理

- 状态：草案（brainstorm 已批准，用户已批"进实现计划"）
- 日期：2026-07-13
- 里程碑：M-D 的第二步（完结分布式探针）。M-D1 拓包引擎已交付并入 main。
- 依赖：M-B（Agent 身份 + `agentAuth` + `/agent/assets/batch`）、M-D1（探针 `--role=probe` + `Capture` 抓包引擎）、`scan.Scheduler`（进程内调度框架）均已在 main。

## 0. 背景与目标

M-D1 探针是**配置驱动**（本地参数指定网卡/时长），"分派多个探针"=运维手动在各旁路点各起一个实例。M-D2 让**控制台一处建抓包任务，按标签自动分发给一类探针**，探针**拉取式**领任务（只出不入、防火墙友好），抓完上报，支持一次性与周期性。

**并入用户追加要求**：Agent 与探针的控制尽量集成进平台 UI——M-B 的注册/列表/撤销端点已有但无 UI，本轮补上「Agent/探针管理」控制台页，加上「抓包任务」页，让整个探针舰队在控制台可管可控。

**本轮目标**：① 服务端 CaptureTask 模型 + 拉取式租约分发 + 周期调度；② 探针 managed 轮询模式；③ 控制台两页：Agent/探针管理 + 抓包任务管理。
**非目标**：探针到平台的双向长连（保持拉取式）；跨平台探针 fleet 编排 UI 的高级可视化（拓扑图等）。

## 1. 数据模型：CaptureTask

新增 `backend/internal/model` 的 `CaptureTask`（进 `db.Open` AutoMigrate）：

```go
type CaptureTask struct {
    ID             uint
    Name           string
    LabelSelector  []string   // gorm:"-" 镜像；空=任意探针可领
    LabelSelectorJSON string  // gorm:"column:label_selector;type:text"
    Iface          string     // 抓包网卡（空=探针默认/any）
    BPF            string     // 过滤表达式，默认 tcp
    Duration       int        // 抓包时长（秒）
    MaxPackets     int        // 抓包数上限
    Status         string     // pending/leased/done/failed/cancelled（leased=已领取并抓包中，heartbeat 保活）
    LeasedBy       string     // 领取探针的 agentId
    LeaseExpiresAt *time.Time
    StartedAt      *time.Time
    FinishedAt     *time.Time
    ResultCount    int        // 最近一轮上报观测数
    RunCount       int        // 累计执行次数
    Error          string
    Schedule       string     // cron 表达式，空=一次性
    ScheduleEnabled bool
    NextRunAt      *time.Time
    LastRunAt      *time.Time
    CreatedBy      string
    CreatedAt      time.Time
    UpdatedAt      time.Time
}
```

状态机：`pending →(探针领,原子租约)→ leased →(complete)→ done`；`done` 且周期性 →(调度器到点)→ `pending`；`leased` 租约过期 →(调度器回收)→ `pending`；`cancel` → `cancelled`（终态）。leased 即「已领取并抓包中」，靠 heartbeat 保活，不设独立 running 态。

## 2. 拉取式租约分发（探针只出不入）

```
1. 探针(managed)轮询 GET /api/v1/agent/tasks(agentAuth)
   服务端 leaseTask(agentId, agentLabels)：
     - 找 status=pending 且 LabelSelector ⊆ agentLabels（空选择器任意命中）的最早一条
     - 原子租约：UPDATE capture_tasks SET status='leased', leased_by=?, lease_expires_at=? WHERE id=? AND status='pending'
       仅 RowsAffected==1 才算领到（防两探针领同一个）
     - 命中 → 200 返回任务参数；无 → 204
2. 探针按参数抓包（复用 M-D1 Capture）；抓/传期间 POST /agent/tasks/:id/heartbeat 续租（LeaseExpiresAt+=租约TTL）
3. 抓完解析 → 观测 POST /agent/assets/batch(盖 ReportedBy) → POST /agent/tasks/:id/complete{resultCount}
   服务端：一次性→done+FinishedAt；周期性(ScheduleEnabled)→回 pending + NextRunAt=cron 顺延，RunCount++
```

**标签匹配** `subsetOf(selector, agentLabels)`：selector 每个标签都在 agentLabels 里即命中。**租约 TTL** 默认 `max(Duration*2, 120s)`，够抓包+上传+心跳间隙。心跳把 LeaseExpiresAt 前移，避免长抓包被误回收。

## 3. API 端点

**管理面**（用户 JWT，writer=operator/admin；`GET` 任意已登录）：
- `POST /api/v1/captures` 建任务（name/labelSelector/iface/bpf/duration/maxPackets/schedule）
- `GET /api/v1/captures` 列表（含状态/领取探针/结果/下次运行）；`GET /api/v1/captures/:id`
- `POST /api/v1/captures/:id/cancel`；`DELETE /api/v1/captures/:id`

**探针面**（`agentAuth`，X-Agent-Key，挂现有 `/agent` 组）：
- `GET /api/v1/agent/tasks` 领任务（租约）
- `POST /api/v1/agent/tasks/:id/heartbeat` 续租（校验 LeasedBy==本探针）
- `POST /api/v1/agent/tasks/:id/complete` 报完成（校验 LeasedBy==本探针；带 resultCount）

结果上报仍走 `POST /agent/assets/batch`（M-B，零改动）。

## 4. 探针 managed 模式（`backend/cmd/agent/`）

`--role=probe` 增 `--managed`（+ `--task-poll` 轮询间隔，默认 15s）。新增 `probe_managed.go`：
```
runManagedProbe(cfg)：循环 {
  task := pollTask()           // GET /agent/tasks；204 → sleep(task-poll) 继续
  go heartbeatLoop(task.ID)    // 抓包期间周期续租（保持 leased 不被回收）
  pcap := Capture(taskCfg)     // 复用 M-D1，参数来自 task
  assets := assetsFromPcap(pcap)
  reportAssets(assets)         // /agent/assets/batch
  completeTask(task.ID, len(assets))
}
```
非 managed 仍是 M-D1 的本地配置驱动一次性抓（保留）。managed 模式下本地 `--iface/--bpf/--duration` 作为任务未指定时的兜底默认。

## 5. 周期调度 + 租约回收（复用 scan.Scheduler）

`backend/internal/scan` 或 `internal/api` 加 `RegisterCaptureScheduler(sched *scan.Scheduler, db *gorm.DB)`，注册一个周期 job（默认 30s）：
1. **回收过期租约**：`status = 'leased' AND lease_expires_at < now` → 打回 pending（清 LeasedBy）。
2. **周期任务到点**：`schedule_enabled AND status=done AND next_run_at < now` → 回 pending + NextRunAt 顺延（cron→间隔用现有 `scan/cron.go`）。

挂进 `cmd/zhulong-pqm/main.go`（与 `monitor.RegisterPolicies`/`api.RegisterDailySnapshot` 并列）。

## 6. 控制台：Agent/探针管理 + 抓包任务（用户追加要求）

**新增两页 + 菜单 + 路由**：

### 6.1 `frontend/src/views/Agents.vue`（Agent/探针管理，补 M-B 端点的 UI）
- 列表：agentId / hostname / kind(host/probe/both) / status / labels / lastSeenAt / version。
- **注册**（admin）：填 hostname/kind/labels → 调 `POST /agents` → **弹窗显示一次性 apiKey + 复制按钮 + 「仅显示一次」警示**。
- **撤销**（admin）：`POST /agents/:id/revoke`，二次确认。
- `api/agents.ts` + `types.ts` 加 `Agent` 镜像。

### 6.2 `frontend/src/views/CaptureTasks.vue`（抓包任务）
- 列表：名称 / 标签选择器 / 状态（pending/leased/done/failed/cancelled 着色）/ 领取探针 / 结果数 / 下次运行。
- **新建抽屉**：名称、标签多选（选项取自现有 Agent 的 labels 并集）、网卡、BPF、时长、包数上限、周期开关+cron。
- 取消 / 删除；状态自动轮询（~2s，沿用现有模式）。
- `api/captures.ts` + `types.ts` 加 `CaptureTask` 镜像。

菜单加「探针管理」分组（Agent 管理 + 抓包任务）。主题沿用字节跳动蓝 #165DFF，勿覆写 Arco --color-*。

## 7. 错误处理

- 探针领任务后崩溃/网断 → 租约过期被调度器回收，任务回 pending 可被别的探针重领（不丢任务）。
- 周期任务无匹配探针 → 停在 pending，列表可见，不报错（诚实）。
- heartbeat/complete 校验 `LeasedBy==调用探针`，否则 403（防越权改别人的任务）。
- cancel 对 leased 任务：置 cancelled，探针下次 heartbeat/complete 收到任务已终态(4xx)则丢弃本轮结果。

## 8. 测试

- **后端** `internal/api/captures_test.go`（内存 DB，直接调 Server 方法或 leaseTask 逻辑）：
  - `leaseTask` 原子性：并发两 agentLabels 领同一 pending，只 1 个 RowsAffected==1 拿到。
  - 标签子集匹配：`["机房A"]⊆["机房A","核心"]` 命中；`["机房B"]` 不命中；空选择器任意命中。
  - complete：一次性→done；周期性→回 pending + NextRunAt 非空 + RunCount++。
  - 过期租约回收：leased + LeaseExpiresAt 过去 → 回收 job 后 pending。
- **探针** `backend/cmd/agent/probe_managed_test.go`：`httptest.Server` mock `/agent/tasks`(返任务)+`/assets/batch`+`/tasks/:id/complete`，注入假 `Capture`（返合成 pcap 字节），断言 managed 一轮：领到→抓→上报→报完成。
- 全模块 `go build/vet/test` + 双架构交叉编译；前端 `npm run build`（vue-tsc）。
- 真机验收（101.43.125.131，若 ControlMaster 可重建）：控制台建任务→探针 `--role=probe --managed` 领取→抓包→结果回控制台。

## 9. 受影响文件清单

- 新增：`internal/model/capture_task.go`、`internal/api/captures.go`（管理面 CRUD + leaseTask/heartbeat/complete + RegisterCaptureScheduler）、`internal/api/captures_test.go`；`backend/cmd/agent/probe_managed.go`、`probe_managed_test.go`。
- 改：`internal/db/db.go`（AutoMigrate + CaptureTask）、`internal/api/router.go`（管理路由 + agent 任务路由）、`cmd/zhulong-pqm/main.go`（RegisterCaptureScheduler）、`cmd/agent/config.go`（--managed/--task-poll）、`cmd/agent/main.go`（managed 分派）。
- 前端新增：`views/Agents.vue`、`views/CaptureTasks.vue`、`api/agents.ts`、`api/captures.ts` + `types.ts` 镜像 + 路由 + 菜单。
- 文档：`主机Agent安装手册.md` 加「managed 模式」；`CLAUDE.md` 补。

## 10. 约束

- 纯 Go 免 CGO；探针抓包复用 M-D1 `Capture`（AF_PACKET/tcpdump）。
- 拉取式（探针只出不入），不引入探针入站连接。
- 结果上报复用 `/agent/assets/batch`（零改后端上报层）。
- 前端字节跳动蓝 #165DFF，勿覆写 Arco --color-*。commit 前缀 `feat(scope):`，中文。
