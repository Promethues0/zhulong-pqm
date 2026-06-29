import client from './client'
import type {
  AcceptanceCase,
  AcceptanceReport,
  AcceptanceRun,
  AcceptanceRunDetail,
  AssetByGroup,
  AssetEvidence,
  AssetGroup,
  AssetGroupInput,
  AssetQuery,
  AuditLog,
  AuditQuery,
  CbomSnapshot,
  Coverage,
  CryptoAsset,
  CryptoAssetInput,
  Dashboard,
  DedupCluster,
  Device,
  DeviceInput,
  DeviceTestResult,
  ImportResult,
  LegacyRisk,
  LoginResp,
  MergeInput,
  MonitorDashboard,
  MonitorEvent,
  MonitorEventQuery,
  Playbook,
  RegisterQuery,
  RegisterRow,
  RemediationInput,
  RemediationSummary,
  RemediationTask,
  Report,
  ReportInput,
  RescoreResult,
  RuleListResp,
  RuleQuery,
  ScanDetail,
  ScanInput,
  ScanJob,
  ScanRule,
  ScoreHistory,
  ScoreInput,
  ScoreOptions,
  ScorePreset,
  ScoreProfile,
  ScoreProfileInput,
  ScoreSummary,
  SettingItem,
  SettingsGrouped,
  SignInput,
  SloSeries,
  SloSummary,
  SnapshotDiff,
  SnapshotInput,
  ThreatIntel,
  ThreatIntelInput,
  TrendResp,
  VerifyRunInput,
} from './types'

/** 认证 */
export const authApi = {
  login(username: string, password: string) {
    return client
      .post<LoginResp>('/auth/login', { username, password })
      .then((r) => r.data)
  },
}

/** 仪表板 */
export const dashboardApi = {
  get() {
    return client.get<Dashboard>('/dashboard').then((r) => r.data)
  },
}

/** 资产 / CBOM */
export const assetApi = {
  list(query: AssetQuery = {}) {
    return client
      .get<CryptoAsset[]>('/assets', { params: query })
      .then((r) => r.data ?? [])
  },
  get(id: number) {
    return client.get<CryptoAsset>(`/assets/${id}`).then((r) => r.data)
  },
  create(payload: CryptoAssetInput) {
    return client.post<CryptoAsset>('/assets', payload).then((r) => r.data)
  },
  update(id: number, payload: CryptoAssetInput) {
    return client.put<CryptoAsset>(`/assets/${id}`, payload).then((r) => r.data)
  },
  remove(id: number) {
    return client.delete(`/assets/${id}`).then((r) => r.data)
  },
  score(id: number, payload: ScoreInput) {
    return client
      .post<CryptoAsset>(`/assets/${id}/score`, payload)
      .then((r) => r.data)
  },
  /** R3 ② 资产证据链（FR-4.7）。 */
  evidence(id: number) {
    return client
      .get<AssetEvidence[]>(`/assets/${id}/evidence`)
      .then((r) => r.data ?? [])
  },
  /** R3 ③ 资产评分历史时间线（倒序，含 PrevScore/PrevLevel）。 */
  history(id: number) {
    return client
      .get<ScoreHistory[]>(`/assets/${id}/history`)
      .then((r) => r.data ?? [])
  },
  /** R3 ② 导入 CBOM（CycloneDX JSON）：反归一为资产，去重并入或新建。 */
  importCbom(payload: { name?: string; cbom: unknown } | FormData) {
    const isForm = payload instanceof FormData
    return client
      .post<ImportResult>('/assets/import/cbom', payload, {
        headers: isForm ? { 'Content-Type': 'multipart/form-data' } : undefined,
      })
      .then((r) => r.data)
  },
}

/** R3 ② 建档深化 · 重复资产去重 / 合并 */
export const dedupApi = {
  /** 重复簇（按去重主键分组，仅含 size≥2 的组）。后端返回 {total,groups}。 */
  candidates() {
    return client
      .get<{ total: number; groups: DedupCluster[] }>('/assets/dedup-candidates')
      .then((r) => r.data?.groups ?? [])
  },
  /** 合并：将 mergeIds 并入 primaryId，返回合并后的主资产。 */
  merge(payload: MergeInput) {
    return client
      .post<CryptoAsset>('/assets/merge', payload)
      .then((r) => r.data)
  },
}

/** R3 ① 发现深化 · 规则库 */
export const ruleApi = {
  /** 规则库列表（含统计头），支持按 layer/priority/risk/method/enabled 过滤。 */
  list(query: RuleQuery = {}) {
    return client.get<RuleListResp>('/rules', { params: query }).then((r) => r.data)
  },
  /** 单条规则详情。 */
  get(ruleId: string) {
    return client.get<ScanRule>(`/rules/${ruleId}`).then((r) => r.data)
  },
}

/** R3 ① 发现深化 · 覆盖度矩阵 */
export const coverageApi = {
  get() {
    return client.get<Coverage>('/coverage').then((r) => r.data)
  },
}

/** R3 ① 发现深化 · 证据导入（PEM 证书 / SBOM） */
export const importApi = {
  /** 导入 PEM 证书（文本或 multipart 文件）→ 解析 x509 生成资产。 */
  pem(payload: { name?: string; pem: string } | FormData) {
    const isForm = payload instanceof FormData
    return client
      .post<ImportResult>('/assets/import/pem', payload, {
        headers: isForm ? { 'Content-Type': 'multipart/form-data' } : undefined,
      })
      .then((r) => r.data)
  },
  /** 导入 SBOM（CycloneDX/Syft JSON 或 multipart 文件）→ 提取加密库组件。 */
  sbom(payload: unknown | FormData) {
    const isForm = payload instanceof FormData
    return client
      .post<ImportResult>('/assets/import/sbom', payload, {
        headers: isForm ? { 'Content-Type': 'multipart/form-data' } : undefined,
      })
      .then((r) => r.data)
  },
}

/** R3 ② 建档深化 · CBOM 快照与 diff */
export const snapshotApi = {
  /** 快照列表（倒序）。 */
  list() {
    return client.get<CbomSnapshot[]>('/snapshots').then((r) => r.data ?? [])
  },
  /** 冻结当前 CBOM 为命名快照。 */
  create(payload: SnapshotInput) {
    return client.post<CbomSnapshot>('/snapshots', payload).then((r) => r.data)
  },
  /** 两个快照（或快照 vs 实时）的结构化 diff。target 缺省=实时。 */
  diff(base: number, target?: number) {
    const params: Record<string, number> = { base }
    if (target != null) params.target = target
    return client
      .get<SnapshotDiff>('/snapshots/diff', { params })
      .then((r) => r.data)
  },
}

/** 扫描发现 */
export const scanApi = {
  create(payload: ScanInput) {
    return client.post<ScanJob>('/scans', payload).then((r) => r.data)
  },
  list() {
    return client.get<ScanJob[]>('/scans').then((r) => r.data ?? [])
  },
  get(id: number) {
    return client.get<ScanDetail>(`/scans/${id}`).then((r) => r.data)
  },
}

/** 评分元数据与汇总 */
export const scoreApi = {
  summary() {
    return client.get<ScoreSummary>('/score/summary').then((r) => r.data)
  },
  presets() {
    return client
      .get<ScorePreset[]>('/score/presets')
      .then((r) => r.data ?? [])
  },
  options() {
    return client.get<ScoreOptions>('/score/options').then((r) => r.data)
  },
}

/** CBOM 导出（CycloneDX JSON） */
export const cbomApi = {
  export() {
    return client
      .get('/cbom/export', { responseType: 'blob' })
      .then((r) => r.data as Blob)
  },
}

/** 摸底报告 */
export const reportApi = {
  create(payload: ReportInput = {}) {
    return client.post<Report>('/reports', payload).then((r) => r.data)
  },
  list() {
    return client.get<Report[]>('/reports').then((r) => r.data ?? [])
  },
  get(id: number) {
    return client.get<Report>(`/reports/${id}`).then((r) => r.data)
  },
}

/** R2 改造编排 · 设备纳管 */
export const deviceApi = {
  list() {
    return client.get<Device[]>('/devices').then((r) => r.data ?? [])
  },
  create(payload: DeviceInput) {
    return client.post<Device>('/devices', payload).then((r) => r.data)
  },
  update(id: number, payload: DeviceInput) {
    return client.put<Device>(`/devices/${id}`, payload).then((r) => r.data)
  },
  remove(id: number) {
    return client.delete(`/devices/${id}`).then((r) => r.data)
  },
  test(id: number) {
    return client
      .post<DeviceTestResult>(`/devices/${id}/test`)
      .then((r) => r.data)
  },
}

/** R2 改造编排 · 剧本库 */
export const playbookApi = {
  list() {
    return client.get<Playbook[]>('/playbooks').then((r) => r.data ?? [])
  },
}

/** R2 改造编排 · 改造工单 */
export const remediationApi = {
  list() {
    return client
      .get<RemediationTask[]>('/remediations')
      .then((r) => r.data ?? [])
  },
  get(id: number) {
    return client
      .get<RemediationTask>(`/remediations/${id}`)
      .then((r) => r.data)
  },
  create(payload: RemediationInput) {
    return client
      .post<RemediationTask>('/remediations', payload)
      .then((r) => r.data)
  },
  execute(id: number) {
    return client
      .post<RemediationTask>(`/remediations/${id}/execute`)
      .then((r) => r.data)
  },
  rollback(id: number) {
    return client
      .post<RemediationTask>(`/remediations/${id}/rollback`)
      .then((r) => r.data)
  },
  summary() {
    return client
      .get<RemediationSummary>('/remediations/summary')
      .then((r) => r.data)
  },
  /** R3 ④ 改造 done 后一键发起验收：从工单建 Run 并启动，返回该 Run。 */
  verify(id: number) {
    return client
      .post<AcceptanceRun>(`/remediations/${id}/verify`)
      .then((r) => r.data)
  },
}

/** R3 ④ 验收自动化 · 用例 / 运行 / 报告 / 遗留风险 */
export const verifyApi = {
  /** 静态用例库（可按轨道过滤），前端预览用例集。 */
  cases(track?: string) {
    return client
      .get<AcceptanceCase[]>('/verify/cases', {
        params: track ? { track } : {},
      })
      .then((r) => r.data ?? [])
  },
  /** 发起一次验收（异步），返回 Run（status=running）。 */
  createRun(payload: VerifyRunInput) {
    return client
      .post<AcceptanceRun>('/verify/runs', payload)
      .then((r) => r.data)
  },
  /** 验收运行列表（倒序，不含逐项）。 */
  listRuns() {
    return client
      .get<AcceptanceRun[]>('/verify/runs')
      .then((r) => r.data ?? [])
  },
  /** 单次详情：Run + 逐项 TestResult，供轮询看推进。 */
  getRun(id: number) {
    return client
      .get<AcceptanceRunDetail>(`/verify/runs/${id}`)
      .then((r) => r.data)
  },
  /** 一键生成验收报告（落 DRAFT），返回报告。 */
  createReport(runId: number) {
    return client
      .post<AcceptanceReport>(`/verify/runs/${runId}/report`)
      .then((r) => r.data)
  },
  /** 报告全文。 */
  getReport(id: number) {
    return client
      .get<AcceptanceReport>(`/verify/reports/${id}`)
      .then((r) => r.data)
  },
  /** 签署流转：submit / approve / sign / reject。 */
  sign(id: number, payload: SignInput) {
    return client
      .post<AcceptanceReport>(`/verify/reports/${id}/sign`, payload)
      .then((r) => r.data)
  },
  /** 遗留风险登记台账（R-001..，供有条件项挂接）。 */
  risks() {
    return client
      .get<LegacyRisk[]>('/verify/risks')
      .then((r) => r.data ?? [])
  },
}

/** R3 ③ 评估深化 · 权重方案（专家模式调权） */
export const profileApi = {
  /** 权重方案列表（IsActive 置顶）。 */
  list() {
    return client
      .get<ScoreProfile[]>('/score/profiles')
      .then((r) => r.data ?? [])
  },
  /** 当前生效方案。 */
  active() {
    return client
      .get<ScoreProfile>('/score/profiles/active')
      .then((r) => r.data)
  },
  /** 新建方案（不自动激活，Σw 须 = 100）。 */
  create(payload: ScoreProfileInput) {
    return client
      .post<ScoreProfile>('/score/profiles', payload)
      .then((r) => r.data)
  },
  /** 更新方案（内置仅允许改 description）。 */
  update(id: number, payload: Partial<ScoreProfileInput>) {
    return client
      .put<ScoreProfile>(`/score/profiles/${id}`, payload)
      .then((r) => r.data)
  },
  /** 删除方案（拒删内置 / 当前激活）。 */
  remove(id: number) {
    return client.delete(`/score/profiles/${id}`).then((r) => r.data)
  },
  /** 只读预演：以该方案试算全资产，返回 before/after 分布与迁移摘要（不落库）。 */
  preview(id: number) {
    return client
      .post<RescoreResult>(`/score/profiles/${id}/preview`)
      .then((r) => r.data)
  },
  /** 激活并全量复算：返回 before/after 分布与 shifted 迁移数。 */
  activate(id: number, reason?: string) {
    return client
      .post<RescoreResult>(`/score/profiles/${id}/activate`, { reason })
      .then((r) => r.data)
  },
}

/** R3 ③ 评估深化 · 批量复算 + 风险登记册 */
export const registerApi = {
  /** 批量复算/重推导（scope: all / unscored / scan:<jobId>，或显式 assetIds）。 */
  rescore(payload: { assetIds?: number[]; scope?: string } = {}) {
    return client
      .post<{ updated: number; run?: RescoreResult }>('/score/rescore', payload)
      .then((r) => r.data)
  },
  /** 风险登记册行集（可按 priority/hndl/layer/system/department/q 筛选）。 */
  list(query: RegisterQuery = {}) {
    return client
      .get<RegisterRow[]>('/score/register', { params: query })
      .then((r) => r.data ?? [])
  },
  /** 导出 CSV（带当前筛选），返回 Blob。 */
  exportCsv(query: RegisterQuery = {}) {
    return client
      .get('/score/register', {
        params: { ...query, format: 'csv' },
        responseType: 'blob',
      })
      .then((r) => r.data as Blob)
  },
}

/** R3 ⑤ 持续监测 · SLO 时序 */
export const sloApi = {
  /** 八个 SLO 最新值 + 阈值 + 状态（仪表板卡片数据源）。 */
  summary() {
    return client
      .get<SloSummary[]>('/monitor/slo/summary')
      .then((r) => r.data ?? [])
  },
  /** 单个 SLO 编号的时序点（趋势折线，叠加阈值/基线）。 */
  series(code: string) {
    return client
      .get<SloSeries>('/monitor/slo/series', { params: { code } })
      .then((r) => r.data)
  },
}

/** R3 ⑤ 持续监测 · 威胁情报订阅 */
export const intelApi = {
  /** 情报流列表。 */
  list() {
    return client.get<ThreatIntel[]>('/monitor/intel').then((r) => r.data ?? [])
  },
  /** 手工录入情报（triggerReassess=true 时命中资产批量复评）。 */
  create(payload: ThreatIntelInput) {
    return client
      .post<ThreatIntel>('/monitor/intel', payload)
      .then((r) => r.data)
  },
  /** 一键拉取（离线包导入或预置源，幂等去重）。 */
  pull() {
    return client
      .post<{ ingested: number; reassessed?: number }>('/monitor/intel/pull')
      .then((r) => r.data)
  },
}

/** R3 ⑤ 持续监测 · 仪表板 / 告警台账 / 遗留风险 */
export const monitorApi = {
  /** 仪表板一次性聚合（SLO/告警/证书甘特/复评队列/最近 P1/常显风险）。 */
  dashboard() {
    return client
      .get<MonitorDashboard>('/monitor/dashboard')
      .then((r) => r.data)
  },
  /** 告警台账（可按 kind/severity/status 过滤）。 */
  events(query: MonitorEventQuery = {}) {
    return client
      .get<MonitorEvent[]>('/monitor/events', { params: query })
      .then((r) => r.data ?? [])
  },
  /** 确认告警。 */
  ack(id: number) {
    return client
      .post<MonitorEvent>(`/monitor/events/${id}/ack`)
      .then((r) => r.data)
  },
  /** 闭合告警。 */
  resolve(id: number) {
    return client
      .post<MonitorEvent>(`/monitor/events/${id}/resolve`)
      .then((r) => r.data)
  },
  /** 一键复评：将关联资产回流评估，返回事件（含 reassessTaskId）。 */
  reassess(id: number) {
    return client
      .post<MonitorEvent>(`/monitor/events/${id}/reassess`)
      .then((r) => r.data)
  },
  /** 遗留风险登记台账（R-00x，可按 level/status 筛选）。 */
  legacyRisks(query: { level?: string; status?: string } = {}) {
    return client
      .get<LegacyRisk[]>('/monitor/legacy-risks', { params: query })
      .then((r) => r.data ?? [])
  },
  /** 关闭遗留风险（要求 evidenceUrl 非空，FR-7.10）。 */
  closeLegacyRisk(id: number, evidenceUrl: string) {
    return client
      .post<LegacyRisk>(`/monitor/legacy-risks/${id}/close`, { evidenceUrl })
      .then((r) => r.data)
  },
  /** Wave C：告警台账外推 SIEM（CEF / JSON 下载），返回 Blob。 */
  exportEvents(format: 'cef' | 'json', query: MonitorEventQuery = {}) {
    return client
      .get('/monitor/events/export', {
        params: { ...query, format },
        responseType: 'blob',
      })
      .then((r) => r.data as Blob)
  },
}

/** Wave C 平台横切 · 系统设置（按 category 分组）。 */
export const settingApi = {
  /** 全部配置键，按 category 分组（scan/slo/weights(只读)/intel/retention）。
   *  后端返回 {categories:{分组:[items]},values:{}}，此处取出 categories。 */
  get() {
    return client
      .get<{ categories?: SettingsGrouped; values?: unknown }>('/settings')
      .then((r) => r.data?.categories ?? {})
  },
  /** 更新单键（PUT /settings/:key，body={value}），返回更新后的单条设置项。 */
  update(key: string, value: unknown) {
    return client
      .put<SettingItem>(`/settings/${encodeURIComponent(key)}`, { value })
      .then((r) => r.data)
  },
}

/** Wave C 平台横切 · 仪表板趋势 + 快照采集。 */
export const trendApi = {
  /** 最近 N 日趋势序列（缺日不补零）。后端返回 {series:[{date,remediated,...}]}，此处归一为 TrendResp。 */
  get(days = 7): Promise<TrendResp> {
    return client
      .get<{ series?: any[]; points?: any[] }>('/dashboard/trend', { params: { days } })
      .then((r) => {
        const raw = r.data?.series ?? r.data?.points ?? []
        return {
          points: raw.map((s: any) => ({
            at: s.date ?? s.at ?? null,
            totalAssets: s.totalAssets ?? 0,
            p1Count: s.p1Count ?? 0,
            remediatedCount: s.remediated ?? s.remediatedCount ?? 0,
            avgScore: s.avgScore ?? 0,
            hndlCount: s.hndlCount ?? 0,
          })),
        }
      })
  },
  /** 采集今日快照（upsert by date），用于即时出趋势。 */
  snapshot() {
    return client.post('/metrics/snapshot').then((r) => r.data)
  },
}

/** Wave C 平台横切 · 审计日志（admin 可见）。 */
export const auditApi = {
  /** 审计台账（可按 module/action/result/actor 筛选）。 */
  list(query: AuditQuery = {}) {
    return client
      .get<AuditLog[]>('/audit-logs', { params: query })
      .then((r) => r.data ?? [])
  },
  /** 导出 CSV（带当前筛选），返回 Blob。 */
  exportCsv(query: AuditQuery = {}) {
    return client
      .get('/audit-logs/export', { params: query, responseType: 'blob' })
      .then((r) => r.data as Blob)
  },
}

/** Wave C 平台横切 · 资产分组。 */
export const groupApi = {
  /** 分组列表。 */
  list() {
    return client.get<AssetGroup[]>('/asset-groups').then((r) => r.data ?? [])
  },
  /** 新建分组。 */
  create(payload: AssetGroupInput) {
    return client.post<AssetGroup>('/asset-groups', payload).then((r) => r.data)
  },
  /** 更新分组。 */
  update(id: number, payload: AssetGroupInput) {
    return client
      .put<AssetGroup>(`/asset-groups/${id}`, payload)
      .then((r) => r.data)
  },
  /** 删除分组。 */
  remove(id: number) {
    return client.delete(`/asset-groups/${id}`).then((r) => r.data)
  },
  /** 按分组聚合（每组 count/P1/HNDL）。 */
  byGroup() {
    return client
      .get<AssetByGroup[]>('/assets/by-group')
      .then((r) => r.data ?? [])
  },
}
