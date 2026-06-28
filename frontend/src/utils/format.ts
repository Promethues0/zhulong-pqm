// 跨页面共享的展示工具：风险分级配色、日期/暴露面文案。

/** 根据综合分映射徽标配色（Arco color）：≥75 红 / 50-74 橙 / 25-49 黄 / <25 绿。 */
export function scoreColor(score: number): string {
  if (score >= 75) return 'red'
  if (score >= 50) return 'orange'
  if (score >= 25) return 'gold'
  return 'green'
}

/** 由综合分推导优先级级别 P1-P4。 */
export function scoreLevel(score: number): 'P1' | 'P2' | 'P3' | 'P4' {
  if (score >= 75) return 'P1'
  if (score >= 50) return 'P2'
  if (score >= 25) return 'P3'
  return 'P4'
}

/** 分级中文文案。 */
export function levelText(level: string): string {
  switch (level) {
    case 'P1':
      return '极高'
    case 'P2':
      return '高'
    case 'P3':
      return '中'
    case 'P4':
      return '低'
    default:
      return '—'
  }
}

/** 分级 → 配色（与 scoreColor 一致口径）。 */
export function levelColor(level: string): string {
  switch (level) {
    case 'P1':
      return 'red'
    case 'P2':
      return 'orange'
    case 'P3':
      return 'gold'
    case 'P4':
      return 'green'
    default:
      return 'gray'
  }
}

/** 层级中文标签。 */
export function layerLabel(layer: string): string {
  const map: Record<string, string> = {
    L1: 'L1 应用/会话层',
    L2: 'L2 协议/传输层',
    L3: 'L3 数据存储层',
    L4: 'L4 硬件/根信任层',
  }
  return map[layer] ?? layer ?? '—'
}

/** 暴露面中文标签与配色。 */
export function exposureMeta(exposure: string): { label: string; color: string } {
  switch (exposure) {
    case 'public':
      return { label: '公网', color: 'red' }
    case 'dmz':
      return { label: 'DMZ', color: 'orange' }
    case 'internal':
      return { label: '内网', color: 'arcoblue' }
    default:
      return { label: exposure || '—', color: 'gray' }
  }
}

/** 扫描状态中文与配色。 */
export function jobStatusMeta(status: string): { label: string; color: string } {
  switch (status) {
    case 'done':
      return { label: '已完成', color: 'green' }
    case 'running':
      return { label: '运行中', color: 'arcoblue' }
    case 'pending':
      return { label: '排队中', color: 'gray' }
    case 'failed':
      return { label: '失败', color: 'red' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}

/** 友好日期时间。 */
export function fmtDate(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}`
}

/** 仅日期。 */
export function fmtDay(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

// ============ R2 改造编排展示工具 ============

/** 设备类型中文标签。 */
export function deviceTypeLabel(type: string): string {
  switch (type) {
    case 'gateway':
      return '网关'
    case 'hsm':
      return '加密机'
    case 'ca':
      return 'CA'
    case 'proxy':
      return '反代'
    default:
      return type || '—'
  }
}

/** 设备类型徽标配色。 */
export function deviceTypeColor(type: string): string {
  switch (type) {
    case 'gateway':
      return 'orange'
    case 'hsm':
      return 'purple'
    case 'ca':
      return 'arcoblue'
    case 'proxy':
      return 'cyan'
    default:
      return 'gray'
  }
}

/** 设备连通状态中文与配色（online=绿 / offline=灰 / unknown=默认）。 */
export function deviceStatusMeta(status: string): { label: string; color: string } {
  switch (status) {
    case 'online':
      return { label: '在线', color: 'green' }
    case 'offline':
      return { label: '离线', color: 'gray' }
    default:
      return { label: '未知', color: '' }
  }
}

/** 改造工单状态中文与配色。 */
export function remediationStatusMeta(status: string): {
  label: string
  color: string
} {
  switch (status) {
    case 'planned':
      return { label: '待执行', color: 'arcoblue' }
    case 'running':
      return { label: '执行中', color: 'orange' }
    case 'done':
      return { label: '已完成', color: 'green' }
    case 'failed':
      return { label: '失败', color: 'red' }
    case 'rolledback':
      return { label: '已回滚', color: 'gray' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}

/** 改造步骤状态中文与配色（done=绿 / simulated=橙 / running=蓝 / failed=红 / pending=灰）。 */
export function stepStatusMeta(status: string): { label: string; color: string } {
  switch (status) {
    case 'done':
      return { label: '完成', color: 'green' }
    case 'simulated':
      return { label: '模拟', color: 'orange' }
    case 'running':
      return { label: '执行中', color: 'arcoblue' }
    case 'failed':
      return { label: '失败', color: 'red' }
    case 'pending':
      return { label: '待执行', color: 'gray' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}

/**
 * 由建议算法猜测推荐改造轨道：
 * SM2 → gm-hybrid；RSA/ECDSA/ECDH → tls-hybrid；含 VPN/IKE → ssl-vpn-hybrid；否则 tls-hybrid。
 */
export function guessTrack(algo?: string): string {
  const a = (algo ?? '').toUpperCase()
  if (!a) return 'tls-hybrid'
  if (a.includes('VPN') || a.includes('IKE')) return 'ssl-vpn-hybrid'
  if (a.includes('SM2')) return 'gm-hybrid'
  if (a.includes('RSA') || a.includes('ECDSA') || a.includes('ECDH'))
    return 'tls-hybrid'
  return 'tls-hybrid'
}

// ============ R3 ④ 验收自动化展示工具 ============

/**
 * 验收判定中文与配色（严格沿用既有 tag 色阶 + 黏土橙体系）：
 * pass=绿 / conditional=橙（黏土橙 #DB855C，挂 RiskRef） / fail=红 / skip=灰。
 */
export function verdictMeta(verdict: string): { label: string; color: string } {
  switch (verdict) {
    case 'pass':
      return { label: '通过', color: 'green' }
    case 'conditional':
      return { label: '有条件', color: 'orange' }
    case 'fail':
      return { label: '未通过', color: 'red' }
    case 'skip':
      return { label: '跳过', color: 'gray' }
    default:
      return { label: verdict || '—', color: 'gray' }
  }
}

/** 用例类别中文标签。 */
export function caseCategoryLabel(category: string): string {
  switch (category) {
    case 'proto':
      return '协议层'
    case 'compat':
      return '兼容性'
    case 'perf':
      return '性能'
    case 'sec':
      return '安全'
    case 'keymat':
      return '密钥溯源'
    default:
      return category || '—'
  }
}

/** 用例类别徽标配色。 */
export function caseCategoryColor(category: string): string {
  switch (category) {
    case 'proto':
      return 'arcoblue'
    case 'compat':
      return 'cyan'
    case 'perf':
      return 'purple'
    case 'sec':
      return 'orange'
    case 'keymat':
      return 'gold'
    default:
      return 'gray'
  }
}

/** 验收运行状态中文与配色。 */
export function acceptanceRunStatusMeta(status: string): {
  label: string
  color: string
} {
  switch (status) {
    case 'done':
      return { label: '已完成', color: 'green' }
    case 'running':
      return { label: '运行中', color: 'orange' }
    case 'pending':
      return { label: '排队中', color: 'gray' }
    case 'failed':
      return { label: '失败', color: 'red' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}

/**
 * 报告签署状态机文案与配色（DRAFT→UNDER_REVIEW→SIGNED；REJECTED 退回）。
 */
export function signStateMeta(state: string): { label: string; color: string } {
  switch (state) {
    case 'DRAFT':
      return { label: '草稿', color: 'gray' }
    case 'UNDER_REVIEW':
      return { label: '送审中', color: 'orange' }
    case 'SIGNED':
      return { label: '已签署', color: 'green' }
    case 'REJECTED':
      return { label: '已退回', color: 'red' }
    default:
      return { label: state || '—', color: 'gray' }
  }
}

/** 签署状态机 → a-steps 当前步序（0=草稿 1=送审 2=批准/签署）。REJECTED 落在送审步并标错误。 */
export function signStateStep(state: string): number {
  switch (state) {
    case 'DRAFT':
      return 0
    case 'UNDER_REVIEW':
      return 1
    case 'SIGNED':
      return 3
    case 'REJECTED':
      return 1
    default:
      return 0
  }
}

/** 证书到期是否临近（90 天内）或已过期。 */
export function certUrgency(notAfter?: string | null): 'expired' | 'soon' | 'ok' | 'none' {
  if (!notAfter) return 'none'
  const d = new Date(notAfter).getTime()
  if (Number.isNaN(d)) return 'none'
  const days = (d - Date.now()) / 86_400_000
  if (days < 0) return 'expired'
  if (days < 90) return 'soon'
  return 'ok'
}

// ============ R3 ⑤ 持续监测展示工具 ============

/**
 * 监测事件严重度中文与配色（FR-7.13 三级，黏土橙暖色系）：
 * p1=红 / warning=橙（黏土橙 #DB855C）/ inspect=黄。
 */
export function severityMeta(severity: string): { label: string; color: string } {
  switch (severity) {
    case 'p1':
      return { label: 'P1 紧急', color: 'red' }
    case 'warning':
      return { label: '预警', color: 'orange' }
    case 'inspect':
      return { label: '巡检', color: 'gold' }
    default:
      return { label: severity || '—', color: 'gray' }
  }
}

/** 严重度对应的语义色值（卡片描边/折线，黏土橙体系）。 */
export function severityColor(severity: string): string {
  switch (severity) {
    case 'p1':
      return '#cb4b3f'
    case 'warning':
      return '#db855c'
    case 'inspect':
      return '#d6a93f'
    default:
      return '#a99d90'
  }
}

/** 监测事件类型中文标签。 */
export function eventKindLabel(kind: string): string {
  switch (kind) {
    case 'drift':
      return '密码漂移'
    case 'cert_expiry':
      return '证书到期'
    case 'slo_breach':
      return 'SLO 越界'
    case 'intel':
      return '威胁情报'
    case 'cbom_diff':
      return 'CBOM 变更'
    default:
      return kind || '—'
  }
}

/** 监测事件处置状态中文与配色。 */
export function eventStatusMeta(status: string): { label: string; color: string } {
  switch (status) {
    case 'open':
      return { label: '待处置', color: 'red' }
    case 'acked':
      return { label: '已确认', color: 'orange' }
    case 'resolved':
      return { label: '已闭合', color: 'green' }
    case 'muted':
      return { label: '已静默', color: 'gray' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}

/**
 * SLO 越界状态判定（红越界 / 橙临界 / 黄观察 / 绿正常）。
 * breached → red；否则按实测值距阈值的接近度分档（≥90% 阈值=橙，≥75%=黄，余=绿）。
 * days 类（越大越好，如证书剩余天数）用反向口径：越接近阈值越危险。
 */
export function sloState(
  value: number,
  threshold: number,
  breached: boolean,
  unit?: string,
): SloState {
  if (breached) return 'red'
  if (!threshold || Number.isNaN(threshold)) return 'green'
  if (unit === 'days') {
    // 天数类：value 为剩余量，越小越危险（阈值=预警提前量）。
    if (value <= threshold) return 'red'
    if (value <= threshold * 1.25) return 'orange'
    if (value <= threshold * 1.5) return 'yellow'
    return 'green'
  }
  // pct_cov（覆盖率）：越大越好，越低越危险。
  if (unit === 'pct_cov') {
    if (value >= threshold) return 'green'
    if (value >= threshold * 0.95) return 'yellow'
    if (value >= threshold * 0.85) return 'orange'
    return 'red'
  }
  // 默认上限类（失败率/延迟/降幅）：越接近上限越危险。
  const ratio = value / threshold
  if (ratio >= 1) return 'red'
  if (ratio >= 0.9) return 'orange'
  if (ratio >= 0.75) return 'yellow'
  return 'green'
}

export type SloState = 'red' | 'orange' | 'yellow' | 'green'

/** SLO 状态 → 中文 + 色值。 */
export function sloStateMeta(state: SloState): { label: string; color: string } {
  switch (state) {
    case 'red':
      return { label: '越界', color: '#cb4b3f' }
    case 'orange':
      return { label: '临界', color: '#db855c' }
    case 'yellow':
      return { label: '观察', color: '#d6a93f' }
    default:
      return { label: '正常', color: '#5a9367' }
  }
}

/** SLO 单位 → 数值后缀。 */
export function sloUnitSuffix(unit?: string): string {
  switch (unit) {
    case 'pct':
    case 'pct_cov':
      return '%'
    case 'ms':
      return 'ms'
    case 'days':
      return ' 天'
    default:
      return ''
  }
}

/** 证书类型中文与分级配色（CA/服务器/IoT）。 */
export function certKindMeta(kind?: string): { label: string; color: string } {
  switch (kind) {
    case 'ca':
      return { label: '根/中间 CA', color: 'red' }
    case 'server':
      return { label: '服务器证书', color: 'orange' }
    case 'iot':
      return { label: 'IoT/长效', color: 'arcoblue' }
    default:
      return { label: kind || '证书', color: 'gray' }
  }
}

/** 情报来源中文与配色。 */
export function intelSourceMeta(source: string): { label: string; color: string } {
  switch (source) {
    case 'NIST':
      return { label: 'NIST', color: 'arcoblue' }
    case '国密局':
      return { label: '国密局', color: 'red' }
    case '学界里程碑':
      return { label: '学界里程碑', color: 'purple' }
    case 'manual':
      return { label: '手工录入', color: 'gray' }
    default:
      return { label: source || '—', color: 'gray' }
  }
}

/** 情报类别中文与配色。 */
export function intelCategoryMeta(category: string): { label: string; color: string } {
  switch (category) {
    case 'standard_update':
      return { label: '标准更新', color: 'arcoblue' }
    case 'algo_break':
      return { label: '算法攻破', color: 'red' }
    case 'algo_deprecate':
      return { label: '算法弃用', color: 'orange' }
    case 'qubit_milestone':
      return { label: '量子比特里程碑', color: 'purple' }
    default:
      return { label: category || '—', color: 'gray' }
  }
}

/** 遗留风险等级中文与配色（高/中/低）。 */
export function legacyLevelColor(level: string): string {
  switch (level) {
    case '高':
      return 'red'
    case '中':
      return 'orange'
    case '低':
      return 'gold'
    default:
      return 'gray'
  }
}

// ============ Wave C 平台横切展示工具 ============

/** 资产分组类型中文与配色（业务/系统/部门/自定义）。 */
export function groupKindMeta(kind: string): { label: string; color: string } {
  switch (kind) {
    case 'business':
      return { label: '业务线', color: 'orange' }
    case 'system':
      return { label: '系统', color: 'arcoblue' }
    case 'department':
      return { label: '部门', color: 'cyan' }
    case 'custom':
      return { label: '自定义', color: 'gray' }
    default:
      return { label: kind || '—', color: 'gray' }
  }
}

/** 审计结果中文与配色（success 绿 / failure 红 / denied 橙）。 */
export function auditResultMeta(result: string): { label: string; color: string } {
  switch (result) {
    case 'success':
      return { label: '成功', color: 'green' }
    case 'failure':
      return { label: '失败', color: 'red' }
    case 'denied':
      return { label: '拒绝', color: 'orange' }
    default:
      return { label: result || '—', color: 'gray' }
  }
}

/** 审计模块中文标签。 */
export function auditModuleLabel(module: string): string {
  const map: Record<string, string> = {
    scan: '扫描发现',
    asset: '资产',
    score: '评分',
    remediation: '改造编排',
    device: '设备',
    report: '报告',
    cbom: 'CBOM',
    user: '用户',
    setting: '系统设置',
    auth: '认证',
  }
  return map[module] ?? module ?? '—'
}

/** 遗留风险处置状态中文与配色。 */
export function legacyStatusMeta(status: string): { label: string; color: string } {
  switch (status) {
    case 'tracking':
      return { label: '跟踪中', color: 'arcoblue' }
    case 'mitigating':
      return { label: '缓解中', color: 'orange' }
    case 'closed':
      return { label: '已关闭', color: 'green' }
    default:
      return { label: status || '—', color: 'gray' }
  }
}
