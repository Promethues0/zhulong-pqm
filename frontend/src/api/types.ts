// 烛龙 PQM 后端 API 数据契约（与 backend/internal/model 对齐）。

/** 平台用户 */
export interface User {
  id: number
  username: string
  role: string // admin / operator / viewer
  createdAt?: string
}

/** 登录响应 */
export interface LoginResp {
  token: string
  user: User
}

/** 资产层级 */
export type Layer = 'L1' | 'L2' | 'L3' | 'L4'

/** 暴露面 */
export type Exposure = 'internal' | 'dmz' | 'public'

/** 风险等级 */
export type RiskLevel = 'P1' | 'P2' | 'P3' | 'P4' | ''

/** 密码使用点 / 密码学资产 */
export interface CryptoAsset {
  id: number
  name: string
  system: string
  layer: string
  department: string
  owner: string

  algorithm: string
  keySize: number
  protocol: string

  endpoint: string
  certFingerprint?: string
  certNotAfter: string | null

  source: string // scan / manual / import
  confidence?: number
  status: string // discovered / confirmed / archived / merged
  exposure: string // internal / dmz / public

  riskHint?: string

  d1: number
  d2: number
  d3: number
  d4: number
  d5: number
  riskScore: number
  rawScore?: number
  riskLevel: string
  riskLevelText: string
  hndl: boolean

  suggestedAlgo: string

  // 后量子双维建模（KEX 维 × 认证维），来源 cryptoref 分类（M-A 起后端下发）。
  kexGroup?: string
  kexSafety?: 'safe' | 'hybrid' | 'classical' | 'na'
  authSafety?: 'safe' | 'hybrid' | 'classical' | 'na'
  reportedBy?: string

  createdAt?: string
  updatedAt?: string
}

/** 资产创建/更新载荷（字段全部可选，便于部分更新） */
export type CryptoAssetInput = Partial<
  Pick<
    CryptoAsset,
    | 'name'
    | 'system'
    | 'layer'
    | 'department'
    | 'owner'
    | 'algorithm'
    | 'keySize'
    | 'protocol'
    | 'endpoint'
    | 'exposure'
    | 'status'
    | 'suggestedAlgo'
  >
> & { name?: string }

/** 五维评分载荷（可部分提交） */
export interface ScoreInput {
  d1?: number
  d2?: number
  d3?: number
  d4?: number
  d5?: number
}

/** 资产筛选查询 */
export interface AssetQuery {
  layer?: string
  level?: string
  system?: string
  hndl?: string // 'true' / 'false'
  q?: string
  group?: string // Wave C：按分组筛选（分组名或 id）
}

/** 扫描任务 */
export interface ScanJob {
  id: number
  name: string
  targets: string[]
  exposure: string
  status: string // pending / running / done / failed
  resultCount: number
  error?: string
  startedAt: string | null
  finishedAt: string | null
  createdAt?: string
}

/** 扫描创建载荷 */
export interface ScanInput {
  name: string
  targets: string[]
  exposure: string
  scannerType?: string
}

/** 单个目标的探测结果 */
export interface ScanResult {
  id: number
  scanJobId: number
  host: string
  port: number
  tlsVersion: string
  cipherSuite: string
  keyAlgo: string
  keySize: number
  sigAlgo: string
  certSubject: string
  certIssuer: string
  certNotAfter: string | null
  assetId: number
  /** R3 ① 命中规则（每条结果可命中多条规则）。 */
  hits?: RuleHit[]
  method?: string // M1 …
  status?: string // ok / failed（探测状态）
  error?: string // 探测失败原因（不可达/超时/非 TLS）
  createdAt?: string
}

/** 扫描任务详情 */
export interface ScanDetail {
  job: ScanJob
  results: ScanResult[]
}

/** 仪表板汇总 */
export interface Dashboard {
  totalAssets: number
  byLayer: { L1: number; L2: number; L3: number; L4: number }
  p1Count: number
  hndlCount: number
  criticalCount: number
  avgScore: number
  scanJobs: number
  lastScanAt: string | null
}

/** 优先级分桶 */
export interface ScoreBucket {
  count: number
  avg: number
}

/** 评分汇总看板 */
export interface ScoreSummary {
  p1: ScoreBucket
  p2: ScoreBucket
  p3: ScoreBucket
  p4: ScoreBucket
  hndlCount: number
  criticalCount: number
  avgScore: number
  scoredCount: number
}

/** 预设风险画像 */
export interface ScorePreset {
  name: string
  dims: number[] // [d1, d2, d3, d4, d5]
  score: number
  level: string
  hndl: boolean
}

/** 五维选项 */
export interface ScoreOption {
  label: string
  value: number
}

export interface ScoreOptions {
  d1: ScoreOption[]
  d2: ScoreOption[]
  d3: ScoreOption[]
  d4: ScoreOption[]
  d5: ScoreOption[]
}

/** 摸底报告 */
export interface Report {
  id: number
  title: string
  scope?: string
  markdown: string
  createdAt?: string
}

/** 报告生成载荷 */
export interface ReportInput {
  scope?: string
}

// ============ R2 改造编排（设备 / 剧本 / 工单） ============

/** 外部执行设备类型 */
export type DeviceType = 'gateway' | 'hsm' | 'ca' | 'proxy'

/** 设备连通状态 */
export type DeviceStatus = 'unknown' | 'online' | 'offline'

/** 可编排的外部设备（网关 / 加密机 / CA / 反代） */
export interface Device {
  // 后端主键为 uint，JSON 序列化为数字。
  id: number
  name: string
  type: DeviceType
  vendor: string
  endpoint: string
  capabilities: string[]
  status: DeviceStatus
  latencyMs: number
  lastCheckAt: string | null
}

/** 设备创建/更新载荷 */
export interface DeviceInput {
  name: string
  type: DeviceType
  vendor: string
  endpoint: string
  token?: string
  capabilities: string[]
}

/** 设备连通性测试结果 */
export interface DeviceTestResult {
  status: DeviceStatus
  latencyMs: number
  detail: string
}

/** 改造剧本（轨道 → 步骤 → 执行体 → 交付 → 验收 的对照模板） */
export interface Playbook {
  key: string
  name: string
  deviceType: DeviceType
  targetAlgo: string
  steps: string[]
  deliverable: string
  acceptance: string
}

/** 改造步骤状态 */
export type StepStatus = 'pending' | 'running' | 'done' | 'simulated' | 'failed'

/** 改造工单的单个步骤 */
export interface Step {
  name: string
  status: StepStatus
  detail: string
  at: string | null
}

/** 改造工单状态 */
export type RemediationStatus =
  | 'planned'
  | 'running'
  | 'done'
  | 'failed'
  | 'rolledback'

/** 改造工单（一次「编排外部设备完成 PQC 改造」的任务） */
export interface RemediationTask {
  // 后端主键为 uint，JSON 序列化为数字。
  id: number
  assetId: number
  assetName: string
  track: string
  trackName: string
  targetAlgo: string
  deviceId: number
  deviceName: string
  deviceType: DeviceType
  status: RemediationStatus
  progress: number
  steps: Step[]
  deliverable: string
  acceptance: string
  evidence: Record<string, string>
  error: string
  createdAt: string | null
  startedAt: string | null
  finishedAt: string | null
}

/** 新建改造工单载荷 */
export interface RemediationInput {
  assetId?: number
  assetName?: string
  track: string
  targetAlgo?: string
  deviceId: number
  allowWrite?: boolean
}

/** 改造工单汇总 */
export interface RemediationSummary {
  planned: number
  running: number
  done: number
  failed: number
  total: number
}

// ============ R3 ④ 验收自动化（用例 / 运行 / 逐项结果 / 报告） ============

/** 验收用例类别：协议层 / 兼容性 / 性能 / 安全 / 密钥材料溯源 */
export type AcceptanceCategory =
  | 'proto'
  | 'compat'
  | 'perf'
  | 'sec'
  | 'keymat'

/** 单条用例的判定 */
export type Verdict = 'pass' | 'conditional' | 'fail' | 'skip'

/** 证据来源：真实探测得出 / 基线期望值（诚实标注为模拟） */
export type Evidenced = 'probe' | 'simulated'

/** 验收运行模式 */
export type VerifyMode = 'probe' | 'simulate'

/** 验收运行状态 */
export type AcceptanceRunStatus = 'pending' | 'running' | 'done' | 'failed'

/** 报告签署状态机（FR-7.6） */
export type SignState = 'DRAFT' | 'UNDER_REVIEW' | 'SIGNED' | 'REJECTED'

/** 静态用例定义（来自 verify/cases.go 内存表） */
export interface AcceptanceCase {
  code: string // V-PROTO-01 …
  category: AcceptanceCategory
  name: string
  probe: string // 期望执行的命令文本
  expect: string // 期望断言文本
  tracks: string[] // 适用轨道
  probeable: boolean // 平台能否真实探测
}

/** 逐项结果（AcceptanceRun 一对多） */
export interface TestResult {
  id: number
  runId: number
  code: string // V-PROTO-01 …
  category: AcceptanceCategory
  name: string
  verdict: Verdict
  evidenced: Evidenced // probe / simulated
  expect: string
  actual: string // 实测/模拟输出摘要
  riskRef: string // 有条件项挂接的遗留风险编号（R-001…）
  measuredMs: number // 性能类实测毫秒
  at: string | null
}

/** 一次验收执行 */
export interface AcceptanceRun {
  id: number
  taskId?: number | null // 关联改造工单（可空）
  assetId?: number | null
  assetName: string
  track: string
  trackName: string
  target: string // 探测目标 host:port
  mode: VerifyMode // probe / simulate
  status: AcceptanceRunStatus
  progress: number // 0-100
  total: number // 用例总数（基线 47）
  passed: number
  conditional: number
  failed: number
  skipped: number
  gatePass: boolean
  p1Covered: number
  p1Total: number
  reportId?: number | null
  error: string
  startedAt: string | null
  finishedAt: string | null
  createdAt: string | null
}

/** 验收运行详情：运行 + 逐项结果 */
export interface AcceptanceRunDetail {
  run: AcceptanceRun
  results: TestResult[]
}

/** 发起验收运行载荷 */
export interface VerifyRunInput {
  taskId?: number
  assetId?: number
  track?: string
  target?: string
  mode?: VerifyMode
}

/** 可签署的验收报告 */
export interface AcceptanceReport {
  id: number
  runId: number
  title: string
  markdown: string
  signState: SignState
  hash: string // 报告内容 SHA-256
  reviewer: string
  signer: string
  gatePass: boolean
  createdAt: string | null
  signedAt: string | null
}

/** 报告签署动作 */
export type SignAction = 'submit' | 'approve' | 'sign' | 'reject'

/** 签署请求载荷 */
export interface SignInput {
  action: SignAction
}

/** 遗留风险登记（R-00x 台账，供有条件项挂接） */
export interface LegacyRisk {
  id: number
  code: string // R-001 …
  description: string
  level: string // 高/中/低
  disposition: string
  status: string // tracking / mitigating / closed
  owner: string
  recheckDate?: string | null
  alwaysOnSlo?: boolean
  remediationId?: number | null
  evidenceUrl?: string
  createdAt?: string | null
  updatedAt?: string | null
}

// ============ R3 ① 发现深化（规则库 / 命中 / 覆盖度） ============

/** 发现方式 M1 主动 / M2 被动 / M3 Agent / M4 SBOM / M5 证书 / M6 配置 / M7 手录 */
export type DiscoverMethod =
  | 'M1'
  | 'M2'
  | 'M3'
  | 'M4'
  | 'M5'
  | 'M6'
  | 'M7'

/** 综合风险提示等级（发现层，非最终 D1） */
export type RiskHintLevel = '极高' | '高' | '中'

/** 规则优先级（覆盖度窗口口径） */
export type RulePriority = 'P1' | 'P2' | 'P3'

/** 内置规则库条目（30 条 L1-L4） */
export interface ScanRule {
  id: number
  ruleId: string // R-L1-01 …
  layer: string // L1 / L2 / L3 / L4
  checkItem: string // 检查项名
  algoFeature: string // 目标算法特征
  tools: string // 推荐工具
  riskHint: string // 极高 / 高 / 中
  priority: string // P1 / P2 / P3
  methods: string[] // 默认发现方式
  builtin: boolean // 内置=true（只可禁用不可删）
  enabled: boolean
  createdAt?: string | null
}

/** 规则库统计头 */
export interface RuleStats {
  total: number // 30
  p1High: number // 14
  critical: number // 7（极高）
  byLayer: { L1: number; L2: number; L3: number; L4: number }
}

/** 规则库列表响应（含统计头） */
export interface RuleListResp {
  items: ScanRule[]
  stats: RuleStats
}

/** 规则库筛选查询 */
export interface RuleQuery {
  layer?: string
  priority?: string
  risk?: string
  method?: string
  enabled?: string
}

/** 一条扫描结果命中的规则（ScanResult.hits[]） */
export interface RuleHit {
  ruleId: string // R-L1-02 …
  confidence: string // 高 / 中 / 低
  evidence: string // 可复核佐证串
  method: string // 命中方式
  layer?: string
  riskHint?: string
}

/** 覆盖度矩阵单元格 */
export interface CoverageCell {
  layer: string // L1 / L2 / L3 / L4
  method: string // M1 … M7
  covered: boolean // 是否已覆盖
  count: number // 命中数
}

/** 覆盖度矩阵响应：L1-L4 × 发现方式 */
export interface Coverage {
  layers: string[] // ['L1','L2','L3','L4']
  methods: string[] // ['M1'..'M7']
  cells: CoverageCell[]
  p1Covered?: number
  p1Total?: number
}

/** 证据导入返回（PEM / SBOM / CBOM） */
export interface ImportResult {
  job?: ScanJob | null
  results?: ScanResult[]
  imported?: number
  merged?: number
  skipped?: number
  errors?: string[]
}

// ============ R3 ② 建档深化（CRUD / 合并 / 证据链 / 快照 diff） ============

/** 资产证据链单条（FR-4.7） */
export interface AssetEvidence {
  id?: number
  source: string // 来源工具：sslyze / testssl.sh / manual / import …
  ruleRef: string // 命中规则号（R-L1-01 …）
  raw: string // 原始证据载荷
  hash: string // sha256(raw)，固化防篡改
  confidence: string // 高 / 中 / 低
  scannedAt?: string | null
  createdAt?: string | null
}

/** 重复簇（去重候选，按去重主键分组） */
export interface DedupCluster {
  key: string // 去重键
  keyType: string // certFingerprint / endpoint / name
  assets: CryptoAsset[]
}

/** 合并请求载荷 */
export interface MergeInput {
  primaryId: number
  mergeIds: number[]
}

/** CBOM 快照 */
export interface CbomSnapshot {
  id: number
  name: string
  version?: number
  scope?: string
  assetCount: number
  algoDist?: Record<string, number>
  triggeredBy?: string // manual / rescan / cron
  createdBy?: string
  createdAt?: string | null
}

/** 快照创建载荷 */
export interface SnapshotInput {
  name: string
  scope?: string
}

/** 快照 diff —— 新增/移除条目 */
export interface DiffEntry {
  name: string
  key: string
  algorithm?: string
  riskLevel?: string
}

/** 快照 diff —— 变更条目 */
export interface DiffChange {
  name: string
  key: string
  type: string // algo_changed / cert_rotated / status_changed / level_changed
  from: string
  to: string
  isProgress?: boolean // 算法变更是否为迁移进展（升 PQC）
  direction?: string // level_changed 的方向 ↑恶化 / ↓改善
}

/** 快照 diff 汇总 */
export interface DiffSummary {
  added: number
  removed: number
  algoChanged: number
  certRotated: number
  statusChanged: number
  levelChanged: number
}

// ============ R3 ③ 评估深化（权重方案 / 评分历史 / 风险登记册） ============

/** 权重方案（五维权重命名版本，IsActive 全局唯一 true） */
export interface ScoreProfile {
  id: number
  name: string
  description?: string
  w1: number
  w2: number
  w3: number
  w4: number
  w5: number
  isActive: boolean
  isBuiltin: boolean
  version?: number
  createdBy?: string
  appliedBy?: string
  appliedAt?: string | null
  createdAt?: string | null
  updatedAt?: string | null
}

/** 新建权重方案载荷（五维之和须 = 100） */
export interface ScoreProfileInput {
  name: string
  description?: string
  w1: number
  w2: number
  w3: number
  w4: number
  w5: number
}

/** P1-P4 等级分布 */
export interface LevelDist {
  p1: number
  p2: number
  p3: number
  p4: number
}

/** 激活方案 / 批量复算返回的 before/after 迁移摘要 */
export interface RescoreResult {
  before: LevelDist
  after: LevelDist
  shifted: number
  shifts?: Record<string, number>
  assetCount?: number
  runId?: number
}

/** 资产评分历史快照（时间线） */
export interface ScoreHistory {
  id?: number
  createdAt: string
  score: number
  level: string
  reason: string // manual / rescore / profile-switch / scan-import
  changedBy?: string
  profileName?: string
  prevScore?: number
  prevLevel?: string
  hndl?: boolean
  d1: number
  d2: number
  d3: number
  d4: number
  d5: number
}

/** 风险登记册行（CryptoAsset 投影 + 最近评分时间） */
export interface RegisterRow {
  id: number
  name: string
  system: string
  layer: string
  department: string
  owner: string
  algorithm: string
  d1: number
  d2: number
  d3: number
  d4: number
  d5: number
  riskScore: number
  riskLevel: string
  riskLevelText?: string
  hndl: boolean
  suggestedAlgo?: string
  lastScoredAt?: string | null
}

/** 风险登记册筛选查询 */
export interface RegisterQuery {
  priority?: string // P1..P4
  hndl?: string // 'true'
  layer?: string
  system?: string
  department?: string
  q?: string
}

// ============ R3 ⑤ 持续监测（SLO / 告警 / 情报 / 遗留风险 / 仪表板） ============

/** 监测事件严重度（红/橙/黄，FR-7.13 三级） */
export type MonitorSeverity = 'p1' | 'warning' | 'inspect'

/** 监测事件类型 */
export type MonitorEventKind =
  | 'drift'
  | 'cert_expiry'
  | 'slo_breach'
  | 'intel'
  | 'cbom_diff'

/** 监测事件处置状态 */
export type MonitorEventStatus = 'open' | 'acked' | 'resolved' | 'muted'

/** SLO 越界判定状态（red 越界 / orange 临界 / yellow 观察 / green 正常） */
export type SloState = 'red' | 'orange' | 'yellow' | 'green'

/** SLO 指标摘要卡片（仪表板八卡数据源） */
export interface SloSummary {
  code: string // SLO-01 .. SLO-08
  name?: string
  value: number
  threshold: number
  baseline?: number
  breached: boolean
  unit: string // pct / ms / days / pct_cov
}

/** SLO 时序点 */
export interface SloPoint {
  at: string | null
  value: number
  threshold?: number
  baseline?: number
  breached?: boolean
}

/** SLO 时序响应 */
export interface SloSeries {
  code: string
  unit: string
  threshold?: number
  baseline?: number
  points: SloPoint[]
}

/** 监测事件 / 告警台账 */
export interface MonitorEvent {
  id: number
  kind: MonitorEventKind
  severity: MonitorSeverity
  title: string
  detail?: string
  assetId?: number | null
  assetName?: string
  ruleSlo?: string // SLO-05 / R-L1-02 …
  status: MonitorEventStatus
  reassessTaskId?: number | null
  ackedBy?: string
  evidence?: Record<string, string>
  occurredAt: string | null
  resolvedAt?: string | null
}

/** 监测事件筛选查询 */
export interface MonitorEventQuery {
  kind?: string
  severity?: string
  status?: string
}

/** 证书到期条目（仪表板甘特） */
export interface CertExpiring {
  assetId?: number
  name: string
  certKind?: string // ca / server / iot
  daysLeft: number
  notAfter: string | null
  noOta?: boolean // 无 OTA，需现场检修替换
}

/** 复评队列条目 */
export interface ReassessItem {
  assetId: number
  name: string
  level?: string
  reason?: string
  queuedAt?: string | null
}

/** 量子威胁情报条目 */
export interface ThreatIntel {
  id: number
  source: string // NIST / 国密局 / 学界里程碑 / manual
  category: string // standard_update / algo_break / algo_deprecate / qubit_milestone
  title: string
  summary?: string
  affectedAlgos?: string[]
  qubitCount?: number
  triggerReassess: boolean
  reassessTaskId?: number | null
  publishedAt?: string | null
  ingestedAt?: string | null
}

/** 情报录入载荷 */
export interface ThreatIntelInput {
  source: string
  category: string
  title: string
  summary?: string
  affectedAlgos?: string[]
  qubitCount?: number
  triggerReassess?: boolean
  publishedAt?: string
}

/** 监测仪表板聚合 */
export interface MonitorDashboard {
  sloSummary: SloSummary[]
  alertsBySeverity: Record<string, number>
  certExpiring: CertExpiring[]
  reassessQueue: ReassessItem[]
  recentP1Events: MonitorEvent[]
  alwaysOnRisks: LegacyRisk[]
  cbomFreshnessDays: number
}

/** 两个快照（或快照 vs 实时）的结构化 diff */
export interface SnapshotDiff {
  from: { id: number; name: string }
  to: { id: number; name: string }
  summary: DiffSummary
  added: DiffEntry[]
  removed: DiffEntry[]
  changed: DiffChange[]
  algoDistDelta: Record<string, number> // 算法分布环比
}

// ============ Wave C 平台横切（系统设置 / 趋势 / 审计 / 分组 / SIEM 外推） ============

/** 系统设置分类：扫描默认 / SLO 阈值 / 评分权重(只读) / 威胁情报源 / 保存期。 */
export type SettingCategory = 'scan' | 'slo' | 'weights' | 'intel' | 'retention'

/** 单条系统设置项（KV，value 为已反序列化的任意 JSON）。 */
export interface SettingItem {
  key: string
  category: SettingCategory
  label?: string
  value: unknown
  readonly?: boolean
  unit?: string
  hint?: string
  updatedBy?: string
  updatedAt?: string | null
}

/** 系统设置：后端按 category 分组返回。 */
export type SettingsGrouped = Record<string, SettingItem[]>

/** 设置更新载荷（PUT /settings/:key）。 */
export interface SettingUpdateInput {
  value: unknown
}

/** 仪表板趋势单点（缺日不补零，前端按现有点连线）。 */
export interface TrendPoint {
  at: string | null
  totalAssets: number
  p1Count: number
  remediatedCount: number
  avgScore: number
  hndlCount: number
}

/** 仪表板趋势响应。 */
export interface TrendResp {
  points: TrendPoint[]
}

/** 审计日志结果枚举 */
export type AuditResult = 'success' | 'failure' | 'denied'

/** 审计日志条目（actor/time/module/action/result）。 */
export interface AuditLog {
  id: number
  actorId?: number
  actorName: string
  actorRole?: string
  action: string
  module: string
  targetType?: string
  targetId?: string
  targetName?: string
  result: AuditResult
  detail?: string
  ip?: string
  createdAt: string | null
}

/** 审计日志筛选查询。 */
export interface AuditQuery {
  module?: string
  action?: string
  result?: string
  actor?: string
}

/** 资产分组类型（业务 / 系统 / 部门 / 自定义）。 */
export type AssetGroupKind = 'business' | 'system' | 'department' | 'custom'

/** 资产分组。 */
export interface AssetGroup {
  id: number
  name: string
  kind: AssetGroupKind | string
  description?: string
  createdAt?: string | null
  updatedAt?: string | null
}

/** 分组创建/更新载荷。 */
export interface AssetGroupInput {
  name: string
  kind: AssetGroupKind | string
  description?: string
}

/** 按分组聚合视图条目（每组 count/P1/HNDL）。 */
export interface AssetByGroup {
  group: string
  groupId?: number
  count: number
  p1: number
  hndl: number
}

// M-B/M-D2 主机 Agent / 探针 + 抓包任务
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
