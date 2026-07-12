// Package model 定义烛龙 PQM 的领域模型（GORM 实体）。
package model

import (
	"fmt"
	"time"
)

// Role 用户角色。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// 资产层级 L1~L4：应用/会话层、协议/传输层、数据存储层、硬件/根信任层。
const (
	LayerL1 = "L1"
	LayerL2 = "L2"
	LayerL3 = "L3"
	LayerL4 = "L4"
)

// 资产来源。
const (
	SourceScan   = "scan"
	SourceManual = "manual"
	SourceImport = "import"
)

// 资产状态。
//
// 全局状态机白名单见 AllowedAssetTransition（B0-4），所有域改资产状态须经其校验。
// discovered/confirmed/archived/merged 为 R1/② 既有态；verified 为 ④ 验收签署出口；
// remediating/remediated 为 R2 改造态；accepted/monitored 为 ⑤ 纳管态；
// reassessing 为 ⑤ 复评回退态（漂移/情报触发，回灌 ③ 重评分）。
const (
	StatusDiscovered  = "discovered"
	StatusConfirmed   = "confirmed"
	StatusArchived    = "archived"
	StatusMerged      = "merged"
	StatusVerified    = "verified"    // ④ 验收签署后置
	StatusRemediating = "remediating" // R2 改造进行中
	StatusRemediated  = "remediated"  // R2 改造完成（待验收）
	StatusAccepted    = "accepted"    // ⑤ 纳管/已接受残余风险
	StatusMonitored   = "monitored"   // ⑤ 监测中
	StatusReassessing = "reassessing" // ⑤ 复评回退态（漂移/情报触发复评）
)

// 暴露面。
const (
	ExposureInternal = "internal"
	ExposureDMZ      = "dmz"
	ExposurePublic   = "public"
)

// 量子安全态（KexSafety/AuthSafety 取值）：纯 PQC / 经典+PQC 混合 / 纯经典 / 不适用。
const (
	KexSafetySafe      = "safe"
	KexSafetyHybrid    = "hybrid"
	KexSafetyClassical = "classical"
	KexSafetyNA        = "na"
)

// ---- ① 发现深化（Wave B-1）常量 ----

// 发现方式 M1-M7（FR-3.2/3.3，覆盖度矩阵列维）。
const (
	MethodM1ActiveTLS = "M1" // 主动 TLS/协议握手探测
	MethodM2Passive   = "M2" // 被动流量/旁路镜像
	MethodM3Agent     = "M3" // 主机 Agent/配置审计
	MethodM4SBOM      = "M4" // SBOM/依赖清单导入
	MethodM5Cert      = "M5" // 证书/PEM 导入
	MethodM6Config    = "M6" // 配置/中间件解析
	MethodM7Manual    = "M7" // 人工申报/手录
)

// 量子风险综合提示等级（非最终 D1，发现层参考）。
const (
	RiskHintCritical = "极高"
	RiskHintHigh     = "高"
	RiskHintMedium   = "中"
)

// 规则/命中置信度（FR-3.4.2）。
const (
	ConfHigh   = "高" // 机读直证（握手 KEX/证书签名 OID/库版本号）
	ConfMedium = "中" // 上下文推断（mTLS 状态/SSE 算法等）
	ConfLow    = "低" // 仅人工申报（M7）
)

// 扫描器类型（active 扫描时按此选具体扫描器）。
const (
	ScannerTLS = "tls"
	ScannerSSH = "ssh"
	ScannerIKE = "ike" // 占位（元数据可见，未实现）
	ScannerRDP = "rdp" // 占位（元数据可见，未实现）
)

// 扫描模式（FR-3.5.5）。
const (
	ModeFull        = "full"
	ModeIncremental = "incremental"
)

// 七条极高规则号（FR-3.4.1 验收硬编码校验用）。
var CriticalRuleIDs = []string{
	"R-L2-01", "R-L2-03", "R-L2-04", "R-L2-08", "R-L3-03", "R-L3-07", "R-L4-03",
}

// ScanRule 内置规则库（30 条 seed + 可扩展自定义，FR-3.4）。
// 内置规则只可禁用不可删（Builtin=true）；自定义规则 Builtin=false 可全字段改/删。
type ScanRule struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	RuleID         string    `gorm:"uniqueIndex" json:"ruleId"`         // 业务主键 R-L1-01…R-L4-06
	CheckItem      string    `json:"checkItem"`                         // 检查项名
	Layer          string    `gorm:"index" json:"layer"`                // L1/L2/L3/L4
	AlgoFeature    string    `json:"algoFeature"`                       // 目标算法特征
	Tools          string    `json:"tools"`                             // 推荐工具
	RiskHint       string    `gorm:"index" json:"riskHint"`             // 极高/高/中
	BaseConfidence string    `json:"baseConfidence"`                    // 默认置信度 高/中/低
	MethodsJSON    string    `gorm:"column:methods;type:text" json:"-"` // JSON []string
	Methods        []string  `gorm:"-" json:"methods"`                  // 默认发现方式 ["M1","M2"]
	Priority       string    `gorm:"index" json:"priority"`             // P1/P2/P3
	Builtin        bool      `gorm:"default:true" json:"builtin"`       // 内置=true，只禁不删
	Enabled        bool      `gorm:"default:true" json:"enabled"`       // 禁用开关
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// RuleHit 扫描结果→命中规则映射（一条 ScanResult 可命中多条规则，FR-3.8.2 只追加不篡改）。
type RuleHit struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	ScanResultID uint      `gorm:"index" json:"scanResultId"`
	RuleID       string    `gorm:"index" json:"ruleId"`       // R-L1-02
	Layer        string    `gorm:"index" json:"layer"`        // 冗余存便于按层聚合
	Confidence   string    `json:"confidence"`                // 本次命中置信度
	Evidence     string    `gorm:"type:text" json:"evidence"` // 可复核佐证串
	RiskHint     string    `json:"riskHint"`                  // 命中快照综合风险等级
	Method       string    `json:"method"`                    // 命中来源发现方式 M1-M7
	CreatedAt    time.Time `json:"createdAt"`
}

// 风险等级。
const (
	LevelP1 = "P1"
	LevelP2 = "P2"
	LevelP3 = "P3"
	LevelP4 = "P4"
)

// 扫描任务状态。
const (
	JobPending = "pending"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// 改造执行设备类型。
const (
	DeviceGateway = "gateway"
	DeviceHSM     = "hsm" // 安恒服务器密码机 REST openApi(9090/9443)：SM 全家桶 + PQC(Aigis-sig)
	DeviceCA      = "ca"
	DeviceProxy   = "proxy"
	// DeviceSignServer 安恒签名验签(+时间戳二合一)服务器：SM2/RSA + 标准 PQC(ML-DSA/FN-DSA/SLH-DSA)。
	// 信封 {respond:{respValue,data,message}}（respValue==0 成功），全 POST，无 GET，路径前缀 /tsvsopenapi。
	DeviceSignServer = "sign-server"
	// DeviceCryptoPlatform 密码服务管理平台：多台密码机/签名机的集中纳管父节点（占位，暂不实现独立适配器）。
	DeviceCryptoPlatform = "crypto-platform"
)

// 设备在线状态。
const (
	DeviceStatusUnknown = "unknown"
	DeviceStatusOnline  = "online"
	DeviceStatusOffline = "offline"
)

// 改造工单状态。
const (
	RemPlanned    = "planned"
	RemRunning    = "running"
	RemDone       = "done"
	RemFailed     = "failed"
	RemRolledback = "rolledback"
)

// 改造步骤状态。
const (
	StepPending   = "pending"
	StepRunning   = "running"
	StepDone      = "done"
	StepSimulated = "simulated"
	StepFailed    = "failed"
)

// 用户生命周期状态。
const (
	UserActive   = "active"
	UserDisabled = "disabled"
)

// 审计结果。
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
	AuditDenied  = "denied"
)

// 评分快照触发原因。
const (
	ReasonManual        = "manual"         // 手工调维评分
	ReasonRescore       = "rescore"        // 批量复算
	ReasonProfileSwitch = "profile-switch" // 权重方案切换复算
	ReasonScanImport    = "scan-import"    // 扫描入册
	ReasonReassess      = "reassess"       // ⑤ 复评回灌
)

// ---- ⑤ 持续监测（Monitor）常量 ----

// 监测策略范围类型。
const (
	ScopeAll      = "all"       // 全量纳管资产
	ScopeLayer    = "layer"     // 按资产层级（ScopeValue=L1..L4）
	ScopeExposure = "exposure"  // 按暴露面（ScopeValue=internal/dmz/public）
	ScopeAssetIDs = "asset_ids" // 显式资产 ID 列表（ScopeValue=JSON 数组）
)

// 监测事件类型。
const (
	EventDrift      = "drift"       // 密码漂移（混合回退/新增脆弱）
	EventCertExpiry = "cert_expiry" // 证书到期分级预警
	EventSLOBreach  = "slo_breach"  // SLO 越界
	EventIntel      = "intel"       // 威胁情报触发
	EventCBOMDiff   = "cbom_diff"   // CBOM 变更（证书续期等）
)

// 监测事件严重度（对齐 FR-7.13 三级：红/橙/黄）。
const (
	SevP1      = "p1"      // 红：立即处置 + 复评
	SevWarning = "warning" // 橙：预警
	SevInspect = "inspect" // 黄：巡检
)

// 监测事件状态。
const (
	MonOpen     = "open"     // 待处置
	MonAcked    = "acked"    // 已确认
	MonResolved = "resolved" // 已闭合
	MonMuted    = "muted"    // 已静默
)

// 遗留风险状态（R-00x 台账）。
const (
	RiskTracking   = "tracking"   // 跟踪中
	RiskMitigating = "mitigating" // 缓解中
	RiskClosed     = "closed"     // 已关闭
)

// SLO 编号（PRD SLO 表）。
const (
	SLO01HandshakeFail = "SLO-01" // 握手失败率 ≤0.1%
	SLO02LatencyP99    = "SLO-02" // p99 延迟 ≤46.2ms
	SLO03Throughput    = "SLO-03" // 吞吐降幅 ≤6.5%
	SLO04IKEv2         = "SLO-04" // IKEv2 建立时间 ≤437ms
	SLO05Drift         = "SLO-05" // 密码漂移 = 0
	SLO06CertExpiry    = "SLO-06" // 证书到期分级预警
	SLO07Coverage      = "SLO-07" // P1 覆盖率
	SLO08CBOMFreshness = "SLO-08" // CBOM 新鲜度 ≤90 天
)

// MonitorPolicy 监测策略：周期/范围/阈值（FR-7.7/7.8/7.12）。
// 阈值默认值锚定 PRD SLO 表，管理员可改但有合理性约束（CA 提前量 ≥ 服务器提前量等）。
type MonitorPolicy struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Name       string `gorm:"not null" json:"name"`
	Enabled    bool   `gorm:"default:true" json:"enabled"`
	ScopeKind  string `gorm:"default:all" json:"scopeKind"` // all/layer/exposure/asset_ids
	ScopeValue string `json:"scopeValue"`                   // layer=L4 / exposure=public / 资产 ID 列表 JSON
	RescanCron string `json:"rescanCron"`                   // 复扫周期 cron；默认季度 0 0 3 1 */3 *

	HandshakeFailThreshold float64 `gorm:"default:0.1" json:"handshakeFailThreshold"` // SLO-01 失败率% 默认 0.1
	LatencyP99CeilMs       float64 `gorm:"default:46.2" json:"latencyP99CeilMs"`      // SLO-02 p99 上限 默认 46.2
	ThroughputDropCeilPct  float64 `gorm:"default:6.5" json:"throughputDropCeilPct"`  // SLO-03 吞吐降幅上限 默认 6.5
	IKEv2EstablishCeilMs   float64 `gorm:"default:437" json:"ikev2EstablishCeilMs"`   // SLO-04 IKEv2 建立上限 默认 437
	CBOMFreshnessDays      int     `gorm:"default:90" json:"cbomFreshnessDays"`       // SLO-08 新鲜度上限 默认 90

	CACertWarnDays     int `gorm:"default:180" json:"caCertWarnDays"`    // SLO-06 根/中间 CA 提前量 默认 180
	ServerCertWarnDays int `gorm:"default:30" json:"serverCertWarnDays"` // 服务器证书提前量 默认 30
	IoTCertWarnDays    int `gorm:"default:365" json:"iotCertWarnDays"`   // IoT/长效证书提前量 默认 365

	LastRunAt *time.Time `json:"lastRunAt"` // 上次复扫执行时间
	NextRunAt *time.Time `json:"nextRunAt"` // 下次计划时间（调度器计算，供前端展示）
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// SLOMetric SLO 指标时序点（FR-7.8/7.3，SLO-01~04/08）。追加式时序，按 SLOCode+SampledAt 聚合。
type SLOMetric struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	SLOCode       string    `gorm:"index" json:"sloCode"`   // SLO-01..SLO-08
	AssetID       *uint     `gorm:"index" json:"assetId"`   // 端点级可空，全局指标 nil
	RemediationID *uint     `json:"remediationId"`          // 关联改造工单（基线对照）
	Value         float64   `json:"value"`                  // 实测值
	Threshold     float64   `json:"threshold"`              // 当时生效阈值快照
	Baseline      float64   `json:"baseline"`               // 验收基线值（趋势对照）
	Breached      bool      `json:"breached"`               // 是否越界
	Unit          string    `json:"unit"`                   // pct/ms/days
	Source        string    `json:"source"`                 // measured/synthetic（离线诚实标注）
	SampledAt     time.Time `gorm:"index" json:"sampledAt"` // 采样时刻（时序主键）
}

// MonitorEvent 监测事件/告警（FR-7.7/7.9/7.13，SLO-05/06）。
type MonitorEvent struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	Kind           string `gorm:"index" json:"kind"`     // drift/cert_expiry/slo_breach/intel/cbom_diff
	Severity       string `gorm:"index" json:"severity"` // p1/warning/inspect
	Title          string `json:"title"`
	Detail         string `gorm:"type:text" json:"detail"`
	AssetID        *uint  `gorm:"index" json:"assetId"`
	RuleSLO        string `json:"ruleSlo"`                          // SLO-05/R-L1-02 等
	Status         string `gorm:"index;default:open" json:"status"` // open/acked/resolved/muted
	ReassessTaskID *uint  `json:"reassessTaskId"`                   // 自动生成的复评批次 ID（P1 回灌回填）
	AckedBy        string `json:"ackedBy"`                          // 处置人 username

	EvidenceJSON string            `gorm:"column:evidence;type:text" json:"-"` // JSON 序列化 map[string]string
	Evidence     map[string]string `gorm:"-" json:"evidence"`                  // 漂移前后算法/证书指纹等证据

	OccurredAt time.Time  `gorm:"index" json:"occurredAt"`
	ResolvedAt *time.Time `json:"resolvedAt"`
}

// LegacyRisk 遗留风险登记（R-00x 台账，FR-7.10）。C4 唯一种子源，④ 验收挂接引用。
type LegacyRisk struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Code          string     `gorm:"uniqueIndex" json:"code"` // R-001..
	Description   string     `json:"description"`
	Level         string     `json:"level"`                          // 高/中/低
	Disposition   string     `json:"disposition"`                    // 处置路径
	Status        string     `gorm:"default:tracking" json:"status"` // tracking/mitigating/closed
	Owner         string     `json:"owner"`
	RecheckDate   *time.Time `json:"recheckDate"`   // 复检日期
	AlwaysOnSLO   bool       `json:"alwaysOnSlo"`   // SLO 看板常显（高级=true）
	RemediationID *uint      `json:"remediationId"` // 关联改造工单（双向，FR-11.2）
	EvidenceURL   string     `json:"evidenceUrl"`   // 闭合证据（close 必填）
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// 威胁情报类别。
const (
	IntelStandardUpdate = "standard_update" // 标准更新
	IntelAlgoBreak      = "algo_break"      // 算法被破
	IntelAlgoDeprecate  = "algo_deprecate"  // 算法弃用
	IntelQubitMilestone = "qubit_milestone" // 量子比特里程碑
)

// ThreatIntel 量子威胁情报条目（FR-7.11）。
type ThreatIntel struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Source   string `json:"source"`   // NIST/国密局/学界里程碑/manual
	Category string `json:"category"` // standard_update/algo_break/algo_deprecate/qubit_milestone
	Title    string `json:"title"`
	Summary  string `gorm:"type:text" json:"summary"`

	AffectedAlgosJSON string   `gorm:"column:affected_algos;type:text" json:"-"` // JSON 序列化 []string
	AffectedAlgos     []string `gorm:"-" json:"affectedAlgos"`                   // RSA/ECDSA/SM2...

	QubitCount      int       `json:"qubitCount"`      // 量子比特里程碑（~4000 逻辑比特破 RSA-2048）
	TriggerReassess bool      `json:"triggerReassess"` // 是否映射为复评触发
	PublishedAt     time.Time `json:"publishedAt"`
	IngestedAt      time.Time `json:"ingestedAt"`
	ReassessTaskID  *uint     `json:"reassessTaskId"` // 触发的复评批次
}

// ---- ④ 验收自动化（Acceptance）常量 ----

// 验收执行状态（沿用 JobPending 等风格）。
const (
	RunPending = "pending"
	RunRunning = "running"
	RunDone    = "done"
	RunFailed  = "failed"
)

// 验收执行模式：真实探测 / 模拟。
const (
	ModeProbe    = "probe"    // crypto/tls 真实握手探测
	ModeSimulate = "simulate" // 不可探测项输出基线期望值，诚实标注
)

// 验收用例类别。
const (
	CatProto  = "proto"  // 协议层（V-PROTO）
	CatCompat = "compat" // 兼容矩阵（V-COMPAT）
	CatPerf   = "perf"   // 性能基准（V-PERF）
	CatSec    = "sec"    // 安全验证（V-SEC）
	CatKeymat = "keymat" // 混合密钥材料溯源（V-KEYMAT）
)

// 逐项判定结果。
const (
	VerdictPass        = "pass"
	VerdictConditional = "conditional"
	VerdictFail        = "fail"
	VerdictSkip        = "skip"
)

// 用例证据来源（诚实标注：真实探测 / 模拟基线）。
const (
	EvProbe     = "probe"     // 真实探测得出
	EvSimulated = "simulated" // 基线期望值，诚实标注
)

// 验收报告签署状态机（FR-7.6）。
const (
	SignDraft       = "DRAFT"
	SignUnderReview = "UNDER_REVIEW"
	SignSigned      = "SIGNED"
	SignRejected    = "REJECTED"
)

// AcceptanceRun 一次验收执行（对应一个改造工单/批次，或脱离工单按资产/端点直跑）。
// 状态机：pending → running →（逐用例判定）→ done/failed。
type AcceptanceRun struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	TaskID    *uint  `json:"taskId"`    // 关联 R2 RemediationTask（可空）
	AssetID   *uint  `json:"assetId"`   // 关联 CryptoAsset（可空）
	AssetName string `json:"assetName"` // 资产名快照
	Track     string `json:"track"`     // 改造轨道键（决定用例集）
	TrackName string `json:"trackName"` // 轨道中文名快照
	Target    string `json:"target"`    // 探测目标 host:port（TLS 类真实探测落点）
	Mode      string `json:"mode"`      // probe/simulate

	Status   string `gorm:"default:pending" json:"status"` // pending/running/done/failed
	Progress int    `json:"progress"`                      // 0-100
	Total    int    `json:"total"`                         // 用例总数（基线 47）

	Passed      int `json:"passed"`
	Conditional int `json:"conditional"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`

	GatePass  bool `json:"gatePass"`  // 是否过 Gate（口径见 verify.GatePass）
	P1Covered int  `json:"p1Covered"` // P1 资产覆盖（SLO-07）
	P1Total   int  `json:"p1Total"`

	ReportID *uint  `json:"reportId"` // 生成的 AcceptanceReport
	Error    string `json:"error"`

	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// TestResult 逐项验收结果（入库，AcceptanceRun 一对多）。
type TestResult struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	RunID      uint       `gorm:"index" json:"runId"`
	Code       string     `json:"code"`       // V-PROTO-01…
	Category   string     `json:"category"`   // proto/compat/perf/sec/keymat
	Name       string     `json:"name"`       // 用例名
	Verdict    string     `json:"verdict"`    // pass/conditional/fail/skip
	Evidenced  string     `json:"evidenced"`  // probe（真实探测）/ simulated（基线期望值，诚实标注）
	Expect     string     `json:"expect"`     // 期望断言
	Actual     string     `json:"actual"`     // 实测/模拟输出
	RiskRef    string     `json:"riskRef"`    // 有条件项挂接的遗留风险编号（R-001…）
	MeasuredMs int        `json:"measuredMs"` // 性能类实测毫秒
	At         *time.Time `json:"at"`
}

// AcceptanceReport 可签署验收报告（扩展现有 Report 风格）。
type AcceptanceReport struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	RunID     uint       `gorm:"index" json:"runId"`
	Title     string     `json:"title"`
	Markdown  string     `gorm:"type:text" json:"markdown"`
	SignState string     `gorm:"default:DRAFT" json:"signState"` // DRAFT/UNDER_REVIEW/SIGNED/REJECTED
	Hash      string     `json:"hash"`                           // 报告内容 SHA-256
	Reviewer  string     `json:"reviewer"`                       // 评审人账号
	Signer    string     `json:"signer"`                         // 签署人账号
	GatePass  bool       `json:"gatePass"`                       // 冗余存，便于列表筛选
	CreatedAt time.Time  `json:"createdAt"`
	SignedAt  *time.Time `json:"signedAt"`
}

// User 平台用户。
type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Username     string     `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string     `gorm:"not null" json:"-"`
	Role         string     `gorm:"not null;default:viewer" json:"role"`
	DisplayName  string     `json:"displayName"`                  // 显示名（列表/审计展示用）
	Status       string     `gorm:"default:active" json:"status"` // active/disabled
	LastLoginAt  *time.Time `json:"lastLoginAt"`                  // 最近登录时间
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

// ScoreProfile 权重方案版本：一组命名五维权重。系统恒有一个 IsActive=true 的当前方案；
// 标准方案 30/25/20/15/10 为内置只读基线（IsBuiltin=true，禁改权重/禁删）。
// 权重用整数百分数（30 而非 0.30），Σ 须=100，引擎内部 /100.0 转浮点。
type ScoreProfile struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"not null" json:"name"`
	Description string     `json:"description"` // 调权理由（DP-11 留痕）
	W1          int        `json:"w1"`
	W2          int        `json:"w2"`
	W3          int        `json:"w3"`
	W4          int        `json:"w4"`
	W5          int        `json:"w5"`
	IsActive    bool       `gorm:"default:false;index" json:"isActive"` // 当前生效，全局唯一 true
	IsBuiltin   bool       `gorm:"default:false" json:"isBuiltin"`      // 内置标准方案，禁改权重/禁删
	Version     int        `gorm:"default:1" json:"version"`            // 同名方案修订号
	CreatedBy   string     `json:"createdBy"`                           // 创建人 username
	AppliedBy   string     `json:"appliedBy"`                           // 最近激活人
	AppliedAt   *time.Time `json:"appliedAt"`                           // 最近激活时间
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// ScoreHistory 评分快照/审计轨迹：每次资产评分变化写一条不可变快照（时间线排序键 CreatedAt）。
type ScoreHistory struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AssetID     uint      `gorm:"index" json:"assetId"`
	AssetName   string    `json:"assetName"` // 资产名快照（删除后仍可读）
	ProfileID   uint      `json:"profileId"`
	ProfileName string    `json:"profileName"`
	D1          int       `json:"d1"`
	D2          int       `json:"d2"`
	D3          int       `json:"d3"`
	D4          int       `json:"d4"`
	D5          int       `json:"d5"`
	Score       int       `json:"score"`
	RawScore    float64   `json:"rawScore"`
	Level       string    `json:"level"`
	LevelText   string    `json:"levelText"`
	HNDL        bool      `json:"hndl"`
	PrevScore   int       `json:"prevScore"` // 上一条综合分（无则 -1）
	PrevLevel   string    `json:"prevLevel"` // 上一条等级（无则空）
	Reason      string    `json:"reason"`    // manual/rescore/profile-switch/scan-import/reassess
	ChangedBy   string    `json:"changedBy"` // 操作人 username
	CreatedAt   time.Time `gorm:"index" json:"createdAt"`
}

// RescoreRun 批量复算批次（权重切换或批量复算时记录一次），便于 before/after 分布对比与撤销/对比。
// activate 与 rescore 共用复算流程，事务内逐资产 ScoreWith 后落本表。
type RescoreRun struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	FromProfileID  uint           `json:"fromProfileId"`                         // 复算前生效方案
	ToProfileID    uint           `json:"toProfileId"`                           // 复算后方案
	Trigger        string         `json:"trigger"`                               // profile-switch/rescore/scan-import（触发原因）
	Scope          string         `json:"scope"`                                 // all/unscored/scan:<jobId>/asset_ids
	AssetCount     int            `json:"assetCount"`                            // 参与复算资产数
	ShiftedCount   int            `json:"shiftedCount"`                          // 等级发生变化的资产数
	LevelShiftJSON string         `gorm:"column:level_shift;type:text" json:"-"` // JSON：{"P2->P1":3,...} 等级迁移矩阵
	ShiftMatrix    map[string]int `gorm:"-" json:"shiftMatrix"`                  // 反序列化镜像（响应用）
	BeforeDistJSON string         `gorm:"column:before_dist;type:text" json:"-"` // 复算前 P1-P4 分布 {"P1":n,...}
	BeforeDist     map[string]int `gorm:"-" json:"beforeDist"`                   // 反序列化镜像
	AfterDistJSON  string         `gorm:"column:after_dist;type:text" json:"-"`  // 复算后 P1-P4 分布
	AfterDist      map[string]int `gorm:"-" json:"afterDist"`                    // 反序列化镜像
	RunBy          string         `json:"runBy"`                                 // 操作人 username
	CreatedAt      time.Time      `json:"createdAt"`
}

// AuditLog 操作审计日志：敏感写操作的留痕（actor/动作/对象/结果/IP/时间）。
type AuditLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	ActorID    uint      `gorm:"index" json:"actorId"`
	ActorName  string    `json:"actorName"` // 用户名快照
	ActorRole  string    `json:"actorRole"` // 操作时角色快照
	Action     string    `gorm:"index" json:"action"`
	Module     string    `gorm:"index" json:"module"`
	TargetType string    `json:"targetType"`
	TargetID   string    `json:"targetId"` // 字符串兼容非数字目标（如导出文件名）
	TargetName string    `json:"targetName"`
	Result     string    `gorm:"index" json:"result"` // success/failure/denied
	Detail     string    `gorm:"type:text" json:"detail"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `gorm:"index" json:"createdAt"`
}

// ---- ⑥ 平台横切（Wave C）：系统设置 / 仪表板趋势 / 资产分组 ----

// 系统设置键（KV 配置表，避免每加一项配置改表结构）。
const (
	SettingScanDefaults     = "scan.defaults"      // 扫描默认并发/超时/端口/暴露面
	SettingSLOThresholds    = "slo.thresholds"     // SLO 阈值组（PRD 默认）
	SettingScoringWeights   = "scoring.weights"    // 权重展示（C3：只读/回退默认，真相源在 ScoreProfile）
	SettingThreatIntelSrc   = "threatintel.sources" // 威胁情报源
	SettingRetention        = "retention"          // 保存期（审计/监测/快照天数）
)

// Setting 单行 KV 配置表（Key→Value(JSON)）。
type Setting struct {
	Key       string    `gorm:"primaryKey" json:"key"`
	Value     string    `gorm:"type:text" json:"-"`        // JSON 序列化值（原文不直接暴露，经 ValueRaw 解析后输出）
	Category  string    `gorm:"index" json:"category"`     // 分组：scan/slo/scoring/threatintel/retention
	UpdatedBy string    `json:"updatedBy"`                 // 最后修改人 username
	UpdatedAt time.Time `json:"updatedAt"`
}

// MetricSnapshot 仪表板趋势数据源（每日一行，资产/风险随时间演进）。
type MetricSnapshot struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Date            string    `gorm:"uniqueIndex" json:"date"` // YYYY-MM-DD，当日重复采集 upsert
	TotalAssets     int       `json:"totalAssets"`
	P1Count         int       `json:"p1Count"`
	P2Count         int       `json:"p2Count"`
	P3Count         int       `json:"p3Count"`
	P4Count         int       `json:"p4Count"`
	HNDLCount       int       `json:"hndlCount"`
	AvgScore        int       `json:"avgScore"`
	RemediatedCount int       `json:"remediatedCount"` // 改造完成（RemediationTask.Status=done）资产数
	HandledCount    int       `json:"handledCount"`    // 已处置告警数（监测健康）
	Synthetic       bool      `json:"synthetic"`       // 诚实标注：演示态合成补点
	CreatedAt       time.Time `json:"createdAt"`
}

// 资产分组维度（AssetGroup.Kind）。
const (
	GroupBusiness   = "business"   // 业务
	GroupRegion     = "region"     // 区域
	GroupCompliance = "compliance" // 合规域
	GroupCustom     = "custom"     // 自定义
)

// AssetGroup 资产分组/系统维度受控词表（FR-4，标签式多对多，资产侧用 GroupTags）。
type AssetGroup struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Kind        string    `json:"kind"` // business/region/compliance/custom
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// CryptoAsset 密码使用点：一个具体的密码学资产/端点及其风险画像。
type CryptoAsset struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Name       string `gorm:"not null" json:"name"`
	System     string `json:"system"`     // 所属系统
	Layer      string `json:"layer"`      // L1/L2/L3/L4
	Department string `json:"department"` // 责任部门
	Owner      string `json:"owner"`      // 责任人

	Algorithm string `json:"algorithm"` // 算法名（RSA/ECDSA/SM2...）
	KeySize   int    `json:"keySize"`   // 密钥位数
	Protocol  string `json:"protocol"`  // 协议（TLS1.2/IKEv2...）

	Endpoint        string     `json:"endpoint"`        // host:port
	CertFingerprint string     `json:"certFingerprint"` // 证书指纹
	CertNotAfter    *time.Time `json:"certNotAfter"`    // 证书到期时间

	Source     string `gorm:"default:manual" json:"source"`     // scan/manual/import
	Confidence int    `gorm:"default:100" json:"confidence"`    // 置信度 0-100
	Status     string `gorm:"default:discovered" json:"status"` // 资产状态
	Exposure   string `gorm:"default:internal" json:"exposure"` // 暴露面

	// ② 建档深化（Wave B-1）CUP 治理字段。
	Version    int   `gorm:"default:1" json:"version"` // CUP 记录版本号，关键字段变更/合并/状态迁移递增（FR-4.4.2）
	MergedInto *uint `gorm:"index" json:"mergedInto"`  // 被合并时指向主 CUP 的 ID；非空即 status=merged（4.4 终态）

	RiskHint string `json:"riskHint"` // 综合风险提示文本

	// ⑥ 平台横切（Wave C）：资产分组标签（业务/区域/合规域/自定义，仿 Device.Capabilities）。
	GroupTagsJSON string   `gorm:"column:group_tags;type:text" json:"-"` // JSON 序列化 []string
	GroupTags     []string `gorm:"-" json:"groupTags"`                   // 反序列化镜像（响应/筛选用）

	// 五维评分与综合结果。
	D1            int     `json:"d1"`            // 算法脆弱性
	D2            int     `json:"d2"`            // 数据敏感度
	D3            int     `json:"d3"`            // 数据生命周期
	D4            int     `json:"d4"`            // 迁移复杂度
	D5            int     `json:"d5"`            // 暴露面
	RiskScore     int     `json:"riskScore"`     // 综合分（四舍五入）
	RawScore      float64 `json:"rawScore"`      // 原始加权浮点分（审计用）
	RiskLevel     string  `json:"riskLevel"`     // P1/P2/P3/P4
	RiskLevelText string  `json:"riskLevelText"` // 极高/高/中/低
	HNDL          bool    `json:"hndl"`          // Harvest-Now-Decrypt-Later 标记

	SuggestedAlgo string `json:"suggestedAlgo"` // 建议迁移目标算法

	// 后量子双维建模（KEX 维 × 认证维），来源 cryptoref 分类。
	KexGroup   string `json:"kexGroup"`   // 协商的密钥交换组规范名（X25519MLKEM768/curveSM2MLKEM768/x25519...）
	KexSafety  string `json:"kexSafety"`  // 交换维安全态 safe/hybrid/classical/na
	AuthSafety string `json:"authSafety"` // 认证维安全态 safe/hybrid/classical/na
	ReportedBy string `json:"reportedBy"` // 上报来源 Agent/探针 ID（M-B 起用；本轮默认空）

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ---- ② 建档深化（Wave B-1）证据链 / 快照 ----

// 证据来源（AssetEvidence.Source，对齐发现层证据契约）。
const (
	EvidenceScan       = "scan"        // 主动扫描得出
	EvidenceImportPEM  = "import-pem"  // PEM/证书导入（M5）
	EvidenceImportSBOM = "import-sbom" // SBOM 导入（M4）
	EvidenceImportCBOM = "import-cbom" // CBOM 反向导入（FR-4.8）
	EvidenceManual     = "manual"      // 人工补录（M7 访谈）
	EvidenceAudit      = "audit"       // 状态迁移/合并留痕（who/when/from→to）
)

// AssetEvidence CUP 证据链：一条资产可由多源证据交叉佐证（FR-4.3.1 / FR-4.7）。
// 只追加不篡改；合并时全部改挂主 CUP，证据链可溯。
type AssetEvidence struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	AssetID    uint       `gorm:"index" json:"assetId"` // 所属 CUP
	Source     string     `gorm:"index" json:"source"`  // scan/import-pem/import-sbom/import-cbom/manual/audit
	RuleRef    string     `json:"ruleRef"`              // 命中规则号（R-L1-01 等），下钻关联第 3 章
	Raw        string     `gorm:"type:text" json:"raw"` // 原始证据载荷（握手摘要/证书指纹/配置片段/CycloneDX 组件 JSON）
	Hash       string     `gorm:"index" json:"hash"`    // sha256(Raw)，固化防篡改（FR-4.7）
	Confidence string     `json:"confidence"`           // 高/中/低，单条来源置信度（FR-3.4.2 口径）
	ScannedAt  *time.Time `json:"scannedAt"`            // 采集时间
	CreatedAt  time.Time  `json:"createdAt"`
}

// CbomSnapshot 命名 CBOM 快照（FR-4.6.1，C2 唯一实现，⑤ 监测域复用）。
// 冻结某一时刻的全量 CBOM；diff 在线计算（DigestJSON/AlgoDistJSON 比对）。
type CbomSnapshot struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Name       string `gorm:"uniqueIndex;not null" json:"name"` // 命名快照，如 2026Q2-baseline
	Version    int    `json:"version"`                          // 快照版本号（同序自增）
	Scope      string `json:"scope"`                            // 冻结范围（全量 / layer=L1 / system=xxx）
	AssetCount int    `json:"assetCount"`                       // 冻结时 CUP 数

	BOMJSON      string         `gorm:"column:bom;type:text" json:"-"`       // cbom.Build() 完整 CycloneDX JSON（长期留存）
	DigestJSON   string         `gorm:"column:digests;type:text" json:"-"`   // map[key]assetDigest，供 diff 快速比对
	AlgoDistJSON string         `gorm:"column:algo_dist;type:text" json:"-"` // map[algo]count，供环比 diff
	AlgoDist     map[string]int `gorm:"-" json:"algoDist"`                   // 反序列化镜像（响应用）

	TriggeredBy string    `json:"triggeredBy"` // manual/rescan/cron
	CreatedBy   string    `json:"createdBy"`   // 操作人 username
	CreatedAt   time.Time `json:"createdAt"`
}

// ScanJob 一次发现扫描任务。
type ScanJob struct {
	ID          uint     `gorm:"primaryKey" json:"id"`
	Name        string   `json:"name"`
	Targets     string   `gorm:"type:text" json:"-"` // JSON 序列化的 []string
	TargetList  []string `gorm:"-" json:"targets"`   // 反序列化后的目标，仅用于响应
	Exposure    string   `gorm:"default:internal" json:"exposure"`
	Status      string   `gorm:"default:pending" json:"status"`
	ResultCount int      `json:"resultCount"`
	Error       string   `json:"error"`

	// ① 发现深化（Wave B-1）新增字段（向后兼容，默认值锚定 M1/tls/full）。
	Method          string     `gorm:"default:M1" json:"method"`       // M1/import-pem/import-sbom/manual
	ScannerType     string     `gorm:"default:tls" json:"scannerType"` // tls/ssh/ike/rdp
	Schedule        string     `json:"schedule"`                       // cron 表达式，空=一次性
	ScheduleEnabled bool       `json:"scheduleEnabled"`                // 周期开关
	LastRunAt       *time.Time `json:"lastRunAt"`                      // 调度器维护，监测复扫复用
	NextRunAt       *time.Time `json:"nextRunAt"`
	Mode            string     `gorm:"default:full" json:"mode"` // full/incremental
	RateLimit       int        `json:"rateLimit"`                // 每目标速率上限（继承 M1 护栏）

	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// ScanResult 单个目标的探测结果。
type ScanResult struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	ScanJobID uint   `gorm:"index" json:"scanJobId"`
	Host      string `json:"host"`
	Port      int    `json:"port"`

	TLSVersion  string `json:"tlsVersion"`
	CipherSuite string `json:"cipherSuite"`
	KeyAlgo     string `json:"keyAlgo"`
	KeySize     int    `json:"keySize"`
	SigAlgo     string `json:"sigAlgo"`
	KexGroup    string `json:"kexGroup"`  // 被动/主动观测到的密钥交换组规范名
	KexSafety   string `json:"kexSafety"` // 观测层交换维安全态（权威，优先于按组名反查；FIX 2）

	CertSubject     string     `json:"certSubject"`
	CertIssuer      string     `json:"certIssuer"`
	CertNotAfter    *time.Time `json:"certNotAfter"`
	CertFingerprint string     `json:"certFingerprint"` // 叶证书 SHA-256 指纹（去重锚点输入）

	Raw     string `gorm:"type:text" json:"-"` // 原始 JSON 快照
	AssetID uint   `json:"assetId"`            // 关联的 CryptoAsset

	// 探测状态（① 失败可视化）：ok=成功取到密码学特征；failed=不可达/超时/非 TLS 等。
	Status string `gorm:"default:ok" json:"status"`
	Error  string `json:"error"` // 探测失败的人类可读原因

	// ① 发现深化（Wave B-1）发现契约字段（FR-3.7/3.8/3.10）。
	Method           string     `gorm:"default:M1" json:"method"`      // 发现方式 M1-M7
	Source           string     `json:"source"`                        // scan/manual/import 映射
	AssetFingerprint string     `gorm:"index" json:"assetFingerprint"` // 跨方式去重锚点（C6），供②建档合并
	EvidenceNote     string     `gorm:"type:text" json:"evidenceNote"` // M7/手录必填
	FirstSeen        *time.Time `json:"firstSeen"`                     // 增量扫描差异基准
	LastSeen         *time.Time `json:"lastSeen"`

	// Hits 命中规则（gorm:"-" 响应镜像；持久化在 RuleHit 表，按 ScanResult.ID 反查）。
	Hits []RuleHit `gorm:"-" json:"hits,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
}

// CertFingerprintOrEmpty 返回证书指纹（无证书时空串），供去重锚点计算。
func (r *ScanResult) CertFingerprintOrEmpty() string {
	return r.CertFingerprint
}

// Report 摸底报告。
type Report struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `json:"title"`
	Scope     string    `json:"scope"`
	Markdown  string    `gorm:"type:text" json:"markdown"`
	CreatedAt time.Time `json:"createdAt"`
}

// Device 改造执行设备：编排改造时被下发指令的外部设备（网关/加密机/CA/代理）。
type Device struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Name     string `gorm:"not null" json:"name"`
	Type     string `json:"type"`     // gateway/hsm/ca/proxy
	Vendor   string `json:"vendor"`   // 厂商
	Endpoint string `json:"endpoint"` // 管理面地址，连通性探测目标
	Username string `json:"username"` // 网关登录用户名（gateway 真机联调用，空则默认 sysadmin）
	Token    string `json:"-"`        // 接入凭据（明文存，绝不出响应；写入仍走请求体）
	HasToken bool   `gorm:"-" json:"hasToken"` // 派生：是否已配置接入凭据（替代明文 Token 暴露）

	CapabilitiesJSON string   `gorm:"column:capabilities;type:text" json:"-"` // JSON 序列化的 []string
	Capabilities     []string `gorm:"-" json:"capabilities"`                  // 反序列化后的能力清单

	Status      string     `gorm:"default:unknown" json:"status"` // unknown/online/offline
	LatencyMs   int        `json:"latencyMs"`                     // 最近一次探测时延
	LastCheckAt *time.Time `json:"lastCheckAt"`                   // 最近一次探测时间
	CreatedAt   time.Time  `json:"createdAt"`
}

// Step 改造工单中的一个执行步骤（嵌入 RemediationTask.Steps JSON，不单独建表）。
type Step struct {
	Name   string     `json:"name"`
	Status string     `json:"status"` // pending/running/done/simulated/failed
	Detail string     `json:"detail"` // 实际动作或说明
	At     *time.Time `json:"at"`     // 执行完成时间
}

// RemediationTask 改造工单：以编排外部设备为主线，把一个资产迁移到后量子算法。
type RemediationTask struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	AssetID    *uint  `json:"assetId"`    // 关联资产（可空）
	AssetName  string `json:"assetName"`  // 资产名快照
	Track      string `json:"track"`      // 剧本 Key（tls-hybrid 等）
	TrackName  string `json:"trackName"`  // 剧本中文名
	TargetAlgo string `json:"targetAlgo"` // 目标算法

	DeviceID   *uint  `json:"deviceId"`   // 执行设备
	DeviceName string `json:"deviceName"` // 设备名快照
	DeviceType string `json:"deviceType"` // 设备类型快照

	Status   string `gorm:"default:planned" json:"status"` // planned/running/done/failed/rolledback
	Progress int    `json:"progress"`                      // 0-100

	// AllowWrite 显式授权对真实密码设备执行写操作（建密钥/PQC 签名等）。默认 false=只模拟，
	// 前端建单勾选后才为 true，编排器仅在 true 时真调 HSM/签名机 PQC 接口（[[改造闸门]]）。
	AllowWrite bool `gorm:"default:false" json:"allowWrite"`

	StepsJSON string `gorm:"column:steps;type:text" json:"-"` // JSON 序列化的 []Step
	Steps     []Step `gorm:"-" json:"steps"`                  // 反序列化后的步骤清单

	Deliverable string `json:"deliverable"` // 交付物
	Acceptance  string `json:"acceptance"`  // 验收标准

	EvidenceJSON string            `gorm:"column:evidence;type:text" json:"-"` // JSON 序列化的 map[string]string
	Evidence     map[string]string `gorm:"-" json:"evidence"`                  // 反序列化后的验收证据

	Error      string     `json:"error"`
	CreatedAt  time.Time  `json:"createdAt"`
	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
}

// ---- B0-4 全局资产状态机白名单（C7）----
//
// 单一迁移白名单，纳入 ②（discovered/confirmed/archived/merged）、
// ④（verified）、⑤（accepted/monitored/reassessing）、R2（remediating/remediated）
// 全部域的合法迁移。所有域改资产状态一律经 ValidateAssetTransition 校验，
// 任何域不得私开非法迁移。merged 为终态（仅由合并触发，不在本表）。
var assetTransitions = map[string][]string{
	StatusDiscovered:  {StatusConfirmed, StatusArchived, StatusMerged},
	StatusConfirmed:   {StatusArchived, StatusMerged, StatusRemediating, StatusReassessing},
	StatusArchived:    {StatusConfirmed},
	StatusRemediating: {StatusRemediated, StatusConfirmed, StatusReassessing}, // 改造完成 / 失败回退 / 触发复评
	StatusRemediated:  {StatusVerified, StatusReassessing, StatusRemediating}, // 验收 / 复评 / 重做
	StatusVerified:    {StatusAccepted, StatusMonitored, StatusReassessing},   // 验收后纳管/监测/复评
	StatusAccepted:    {StatusMonitored, StatusReassessing},
	StatusMonitored:   {StatusReassessing, StatusAccepted},
	StatusReassessing: {StatusConfirmed, StatusMonitored, StatusRemediating}, // 复评后回流：回评估/回监测/重改造
	StatusMerged:      {},                                                    // 终态
}

// AssetStatusKnown 判定状态值是否为已知合法态（含终态）。
func AssetStatusKnown(status string) bool {
	if status == "" {
		return false
	}
	if _, ok := assetTransitions[status]; ok {
		return true
	}
	return false
}

// AssetTransitionAllowed 判定 from→to 是否为白名单内合法迁移。
// 同态自迁移（from==to）视为合法幂等，不报错。
func AssetTransitionAllowed(from, to string) bool {
	if from == to {
		return AssetStatusKnown(from)
	}
	allowed, ok := assetTransitions[from]
	if !ok {
		return false
	}
	for _, t := range allowed {
		if t == to {
			return true
		}
	}
	return false
}

// ValidateAssetTransition 校验资产状态迁移；非法迁移返回错误供调用方拒绝（422）。
// ④⑤ 改资产状态前必须调用此函数。
func ValidateAssetTransition(from, to string) error {
	if !AssetStatusKnown(to) {
		return fmt.Errorf("未知目标状态 %q", to)
	}
	if !AssetTransitionAllowed(from, to) {
		return fmt.Errorf("非法状态迁移 %s→%s", from, to)
	}
	return nil
}
