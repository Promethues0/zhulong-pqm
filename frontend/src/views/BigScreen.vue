<script setup lang="ts">
import { onMounted, onBeforeUnmount, reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { dashboardApi, scoreApi, remediationApi, monitorApi, coverageApi, trendApi, deviceApi, assetApi } from '@/api'
import type {
  Dashboard,
  ScoreSummary,
  RemediationSummary,
  MonitorDashboard,
  Coverage,
  TrendResp,
  RemediationTask,
  Device,
  CryptoAsset,
} from '@/api/types'

const router = useRouter()

// ---- 数据 ----
const dash = ref<Dashboard | null>(null)
const score = ref<ScoreSummary | null>(null)
const rem = ref<RemediationSummary | null>(null)
const mon = ref<MonitorDashboard | null>(null)
const cov = ref<Coverage | null>(null)
const trend = ref<TrendResp | null>(null)
const remList = ref<RemediationTask[]>([])
const devices = ref<Device[]>([])
const assets = ref<CryptoAsset[]>([])
const updatedAt = ref('')

async function fetchAll() {
  const [d, s, r, m, c, t, rl, dv, av] = await Promise.allSettled([
    dashboardApi.get(),
    scoreApi.summary(),
    remediationApi.summary(),
    monitorApi.dashboard(),
    coverageApi.get(),
    trendApi.get(14),
    remediationApi.list(),
    deviceApi.list(),
    assetApi.list(),
  ])
  if (d.status === 'fulfilled') dash.value = d.value
  if (s.status === 'fulfilled') score.value = s.value
  if (r.status === 'fulfilled') rem.value = r.value
  if (m.status === 'fulfilled') mon.value = m.value
  if (c.status === 'fulfilled') cov.value = c.value
  if (t.status === 'fulfilled') trend.value = t.value
  if (rl.status === 'fulfilled') remList.value = Array.isArray(rl.value) ? rl.value : []
  if (dv.status === 'fulfilled') devices.value = Array.isArray(dv.value) ? dv.value : []
  if (av.status === 'fulfilled') assets.value = Array.isArray(av.value) ? av.value : []
  updatedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  animateHeadline()
}

// ---- 时钟 ----
const now = ref(new Date())
const clockDate = computed(() =>
  now.value.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'long' }),
)
const clockTime = computed(() => now.value.toLocaleTimeString('zh-CN', { hour12: false }))

// ---- 缩放自适应（1920×1080 设计画布） ----
const scale = ref(1)
function fit() {
  scale.value = Math.min(window.innerWidth / 1920, window.innerHeight / 1080)
}

// ---- 数字滚动 ----
const disp = reactive({ total: 0, p1: 0, hndl: 0, avg: 0, gov: 0 })
// 每个 key 只保留最新的 rAF id，卸载时统一取消，避免动画泄漏。
const rafByKey: Partial<Record<keyof typeof disp, number>> = {}
function tween(key: keyof typeof disp, to: number, dur = 1100) {
  const from = disp[key]
  const t0 = performance.now()
  const step = (t: number) => {
    const k = Math.min(1, (t - t0) / dur)
    const e = 1 - Math.pow(1 - k, 3) // easeOutCubic
    disp[key] = from + (to - from) * e
    if (k < 1) rafByKey[key] = requestAnimationFrame(step)
    else disp[key] = to
  }
  rafByKey[key] = requestAnimationFrame(step)
}
function animateHeadline() {
  tween('total', dash.value?.totalAssets ?? 0)
  tween('p1', score.value?.p1.count ?? dash.value?.p1Count ?? 0)
  tween('hndl', dash.value?.hndlCount ?? 0)
  tween('avg', dash.value?.avgScore ?? 0)
  tween('gov', govScore.value)
}

// ---- 治理巩固度（复合指标，成分透明可解释） ----
const govParts = computed(() => {
  const total = dash.value?.totalAssets ?? 0
  const scored = score.value?.scoredCount ?? 0
  const p1 = score.value?.p1.count ?? dash.value?.p1Count ?? 0
  const done = rem.value?.done ?? 0
  const remTotal = rem.value?.total ?? 0
  const assess = total ? scored / total : 0 // 评估覆盖
  const remed = remTotal ? done / remTotal : total ? done / total : 0 // 改造完成
  const health = total ? Math.max(0, 1 - p1 / total) : 0 // 低危占比（无资产=0，与其它分量一致，不虚高）
  return { assess, remed, health }
})
const govScore = computed(() => {
  const g = govParts.value
  return Math.round(100 * (0.35 * g.assess + 0.35 * g.remed + 0.3 * g.health))
})
const govLevel = computed(() => {
  const v = govScore.value
  if (v >= 80) return { t: '稳固', c: '#3fd08a' }
  if (v >= 60) return { t: '良好', c: '#22d3ee' }
  if (v >= 40) return { t: '推进中', c: '#f7b955' }
  return { t: '起步', c: '#ff6b57' }
})

// ---- SVG 弧 ----
function polar(cx: number, cy: number, r: number, deg: number) {
  const a = ((deg - 90) * Math.PI) / 180
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) }
}
function arc(cx: number, cy: number, r: number, a0: number, a1: number) {
  const s = polar(cx, cy, r, a1)
  const e = polar(cx, cy, r, a0)
  const large = a1 - a0 <= 180 ? 0 : 1
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 0 ${e.x} ${e.y}`
}
// 仪表：从 -135° 到 +135°（270° 量程）
const GA0 = -135
const GA1 = 135
const govArcBg = arc(150, 150, 118, GA0, GA1)
const govArcVal = computed(() => arc(150, 150, 118, GA0, GA0 + (270 * disp.gov) / 100))

// ---- 优先级漏斗 ----
const prio = computed(() => {
  const s = score.value
  const items = [
    { k: 'P1', label: 'P1 极高', count: s?.p1.count ?? 0, avg: s?.p1.avg ?? 0, c: '#ff5b52' },
    { k: 'P2', label: 'P2 高', count: s?.p2.count ?? 0, avg: s?.p2.avg ?? 0, c: '#ff9f45' },
    { k: 'P3', label: 'P3 中', count: s?.p3.count ?? 0, avg: s?.p3.avg ?? 0, c: '#f2c14e' },
    { k: 'P4', label: 'P4 低', count: s?.p4.count ?? 0, avg: s?.p4.avg ?? 0, c: '#59c08a' },
  ]
  const max = Math.max(1, ...items.map((i) => i.count))
  return items.map((i) => ({ ...i, pct: Math.round((i.count / max) * 100) }))
})

// ---- 分层 L1-L4 ----
const layers = computed(() => {
  const b = dash.value?.byLayer ?? { L1: 0, L2: 0, L3: 0, L4: 0 }
  const items = [
    { k: 'L1', label: 'L1 应用/会话', v: b.L1 },
    { k: 'L2', label: 'L2 协议/传输', v: b.L2 },
    { k: 'L3', label: 'L3 数据存储', v: b.L3 },
    { k: 'L4', label: 'L4 硬件/根信任', v: b.L4 },
  ]
  const max = Math.max(1, ...items.map((i) => i.v))
  const blues = ['#4080ff', '#3b9dff', '#22d3ee', '#165dff']
  return items.map((i, idx) => ({ ...i, pct: Math.round((i.v / max) * 100), c: blues[idx] }))
})

// ---- PQC 迁移分布（密钥交换维：经典/半迁移(hybrid)/全迁移(safe)，前端按已加载资产聚合） ----
const migrationDist = computed(() => {
  const all = assets.value || []
  const safe = all.filter((a) => a.kexSafety === 'safe').length
  const hybrid = all.filter((a) => a.kexSafety === 'hybrid').length
  const classical = all.filter((a) => a.kexSafety === 'classical').length
  // na/空 = 该维不适用或未判定（TLS1.2 无 KEX 观测、磁盘证书等），不得算进「待迁移」虚增经典占比
  const na = all.length - safe - hybrid - classical
  return { safe, hybrid, classical, na, total: all.length }
})

// ---- 五阶段闭环 ----
const stages = computed(() => [
  { key: 'discover', label: '发现', v: dash.value?.totalAssets ?? 0, unit: '使用点' },
  { key: 'catalog', label: '建档', v: dash.value?.totalAssets ?? 0, unit: 'CBOM' },
  { key: 'assess', label: '评估', v: score.value?.scoredCount ?? 0, unit: '已评分' },
  { key: 'remediate', label: '改造', v: rem.value?.done ?? 0, unit: '已完成' },
  { key: 'monitor', label: '监测', v: dash.value?.totalAssets ?? 0, unit: '持续' },
])

// ---- 改造进度环 ----
const remRing = computed(() => {
  const r = rem.value
  const total = r?.total ?? 0
  const done = r?.done ?? 0
  const pct = total ? Math.round((done / total) * 100) : 0
  const C = 2 * Math.PI * 74
  return {
    total,
    done,
    running: r?.running ?? 0,
    planned: r?.planned ?? 0,
    failed: r?.failed ?? 0,
    pct,
    dash: `${(C * pct) / 100} ${C}`,
  }
})

// ---- 发现方式覆盖 M1-M7 ----
const methodNames: Record<string, string> = {
  M1: '主动扫描',
  M2: '被动流量',
  M3: '主机 Agent',
  M4: 'SBOM',
  M5: '证书导入',
  M6: '配置解析',
  M7: '人工申报',
}
const coverage = computed(() => {
  const c = cov.value
  const methods = c?.methods ?? ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7']
  const cells = c?.cells ?? []
  return methods.map((m) => {
    const mine = cells.filter((x: any) => x.method === m)
    const planned = mine.reduce((a: number, x: any) => a + (x.plannedRules ?? x.count ?? 0), 0)
    const hit = mine.reduce((a: number, x: any) => a + (x.hitRules ?? x.hits ?? 0), 0)
    return { m, name: methodNames[m] ?? m, planned, hit, active: planned > 0 }
  })
})
const covMax = computed(() => Math.max(1, ...coverage.value.map((c) => c.planned)))

// ---- 趋势 ----
const trendGeom = computed(() => {
  const pts = (trend.value?.points ?? []).slice(-14)
  const W = 760
  const H = 150
  const pad = 8
  if (pts.length < 2) return { total: '', remed: '', area: '', labels: [] as string[] }
  const maxV = Math.max(1, ...pts.map((p) => Math.max(p.totalAssets, p.remediatedCount)))
  const xs = (i: number) => pad + (i * (W - 2 * pad)) / (pts.length - 1)
  const ys = (v: number) => H - pad - (v / maxV) * (H - 2 * pad)
  const line = (sel: (p: any) => number) => pts.map((p, i) => `${i ? 'L' : 'M'} ${xs(i).toFixed(1)} ${ys(sel(p)).toFixed(1)}`).join(' ')
  const totalLine = line((p) => p.totalAssets)
  const area = `${totalLine} L ${xs(pts.length - 1).toFixed(1)} ${H - pad} L ${xs(0).toFixed(1)} ${H - pad} Z`
  const labels = pts.map((p) => (p.at ? String(p.at).slice(5) : '')).filter((_, i) => i % 3 === 0 || i === pts.length - 1)
  return { total: totalLine, remed: line((p) => p.remediatedCount), area, labels }
})

// ---- 近期 P1 事件 ----
const events = computed(() => (mon.value?.recentP1Events ?? []).slice(0, 6))
const certExpiring = computed(() => (mon.value?.certExpiring ?? []).length)

// ---- 仪表末端辉光点（随动画跟随） ----
const govTip = computed(() => polar(150, 150, 118, GA0 + (270 * disp.gov) / 100))

// CBOM 新鲜度：负数/无快照时显示占位，0 天=今日。
const cbomFresh = computed(() => {
  const d = mon.value?.cbomFreshnessDays
  if (d == null || d < 0) return '—'
  return d === 0 ? '今日' : d + '天'
})

// ---- 底部统计条 ----
const strip = computed(() => {
  const total = dash.value?.totalAssets ?? 0
  const slo = mon.value?.sloSummary ?? []
  const breached = slo.filter((s: any) => s.breached).length
  const sloRate = slo.length ? Math.round((1 - breached / slo.length) * 100) : 100
  return [
    { label: '扫描任务', value: String(dash.value?.scanJobs ?? 0), c: '#7fd6ff' },
    { label: '改造工单', value: String(rem.value?.total ?? 0), c: '#7fd6ff' },
    { label: 'CBOM 新鲜度', value: cbomFresh.value, c: '#3fd08a' },
    { label: '证书临期', value: String(certExpiring.value), c: certExpiring.value ? '#ffb454' : '#3fd08a' },
    { label: 'HNDL 占比', value: (total ? Math.round(((dash.value?.hndlCount ?? 0) / total) * 100) : 0) + '%', c: '#ff9f45' },
    { label: 'SLO 达标', value: sloRate + '%', c: sloRate >= 90 ? '#3fd08a' : '#ffb454' },
  ]
})

// ---- 底部跑马灯 ----
const ticker = computed(() => {
  const t = dash.value
  const s = score.value
  const base = [
    '烛龙 PQM 治理闭环持续巡检 · 系统运行正常',
    `密码使用点 ${t?.totalAssets ?? 0} 项已纳管`,
    `P1 极高 ${s?.p1.count ?? 0} 项需立即处置`,
    `HNDL 重点关注 ${t?.hndlCount ?? 0} 项`,
    `改造完成率 ${remRing.value.pct}%`,
    `平均风险分 ${Math.round(t?.avgScore ?? 0)}`,
    `治理巩固度 ${govScore.value} / 100 · ${govLevel.value.t}`,
    `发现方式覆盖 M1–M7 · 被动流量 M2 已启用`,
  ]
  const evs = events.value.map(
    (e: any) => `⚠ P1 事件 ${e.title || e.assetName || e.kind || ''} ${String(e.occurredAt || '').slice(5, 16)}`,
  )
  return [...base, ...evs]
})

// ==== 多屏轮播 ====
const SCREENS = [
  { key: 'overview', name: '治理总览' },
  { key: 'remediation', name: '改造专题' },
  { key: 'monitor', name: '监测专题' },
]
const screenIdx = ref(0)
const paused = ref(false)
const ROTATE_MS = 16000
let rotateElapsed = 0
const rotatePct = ref(0)
function go(i: number) {
  screenIdx.value = (i + SCREENS.length) % SCREENS.length
  rotateElapsed = 0
  rotatePct.value = 0
}

// ---- 改造专题 ----
const remBreakdown = computed(() => {
  const r = rem.value
  const items = [
    { label: '已完成', v: r?.done ?? 0, c: '#3fd08a' },
    { label: '执行中', v: r?.running ?? 0, c: '#22d3ee' },
    { label: '待执行', v: r?.planned ?? 0, c: '#f2c14e' },
    { label: '失败', v: r?.failed ?? 0, c: '#ff5b52' },
  ]
  const max = Math.max(1, ...items.map((i) => i.v))
  return items.map((i) => ({ ...i, pct: Math.round((i.v / max) * 100) }))
})
const remTasks = computed(() =>
  [...remList.value]
    .sort((a, b) => (b.id ?? 0) - (a.id ?? 0))
    .slice(0, 7)
    .map((t) => ({
      name: t.assetName || t.trackName || `工单 #${t.id}`,
      track: t.trackName || t.track || '',
      target: t.targetAlgo || '',
      status: t.status,
      progress: Math.max(0, Math.min(100, t.progress ?? 0)),
    })),
)
const remStatusMeta: Record<string, { t: string; c: string }> = {
  done: { t: '完成', c: '#3fd08a' },
  running: { t: '执行中', c: '#22d3ee' },
  planned: { t: '待执行', c: '#f2c14e' },
  failed: { t: '失败', c: '#ff5b52' },
}
const deviceRows = computed(() =>
  devices.value.slice(0, 6).map((d) => ({
    name: d.name,
    type: d.type,
    online: d.status === 'online',
    latency: d.latencyMs ?? 0,
  })),
)
const remKpis = computed(() => {
  const r = rem.value
  const online = devices.value.filter((d) => d.status === 'online').length
  return [
    { v: String(r?.total ?? 0), l: '改造工单', c: '#7fd6ff' },
    { v: remRing.value.pct + '%', l: '完成率', c: '#3fd08a' },
    { v: String(r?.running ?? 0), l: '执行中', c: '#22d3ee' },
    { v: `${online}/${devices.value.length}`, l: '在线设备', c: online ? '#3fd08a' : '#ffb454' },
  ]
})

// ---- 监测专题 ----
const sloRows = computed(() =>
  (mon.value?.sloSummary ?? []).slice(0, 8).map((s: any) => {
    const th = Math.max(1, s.threshold ?? 1) // 阈值缺失/为 0 时保底，避免除零→Infinity
    const ratio = Math.max(0, Math.min(1.3, (s.value ?? 0) / th))
    return {
      code: s.code,
      name: s.name || s.code,
      value: s.value ?? 0,
      unit: s.unit || '',
      breached: !!s.breached,
      pct: Math.round(Math.min(1, ratio) * 100),
    }
  }),
)
const certRows = computed(() =>
  (mon.value?.certExpiring ?? [])
    .slice()
    .sort((a: any, b: any) => (a.daysLeft ?? 0) - (b.daysLeft ?? 0))
    .slice(0, 6)
    .map((c: any) => ({
      name: c.name,
      kind: c.certKind || '',
      days: c.daysLeft ?? 0,
      noOta: !!c.noOta,
      c: (c.daysLeft ?? 0) <= 7 ? '#ff5b52' : (c.daysLeft ?? 0) <= 30 ? '#ffb454' : '#3fd08a',
    })),
)
const p1EventRows = computed(() =>
  (mon.value?.recentP1Events ?? []).slice(0, 6).map((e: any) => ({
    title: e.title || e.assetName || e.kind || 'P1 事件',
    slo: e.ruleSlo || '',
    at: String(e.occurredAt || e.createdAt || '').slice(5, 16),
    sev: e.severity || 'p1',
  })),
)
const riskRows = computed(() =>
  (mon.value?.alwaysOnRisks ?? []).slice(0, 5).map((r: any) => ({
    code: r.code,
    desc: r.description || '',
    level: r.level || '',
    status: r.status || '',
    c: r.level === '高' ? '#ff5b52' : r.level === '中' ? '#ffb454' : '#3fd08a',
  })),
)
const monKpis = computed(() => {
  const slo = mon.value?.sloSummary ?? []
  const breached = slo.filter((s: any) => s.breached).length
  return [
    { v: slo.length ? String(slo.length - breached) : '—', l: 'SLO 达标', c: slo.length ? '#3fd08a' : '#4d6a92' },
    { v: String(breached), l: 'SLO 越界', c: breached ? '#ff5b52' : '#3fd08a' },
    { v: String((mon.value?.certExpiring ?? []).length), l: '证书临期', c: '#ffb454' },
    { v: String((mon.value?.alwaysOnRisks ?? []).length), l: '常态化风险', c: '#7fd6ff' },
  ]
})

// ---- 生命周期 ----
let clockTimer: number | undefined
let dataTimer: number | undefined
let rotateTimer: number | undefined
onMounted(() => {
  fit()
  window.addEventListener('resize', fit)
  clockTimer = window.setInterval(() => (now.value = new Date()), 1000)
  dataTimer = window.setInterval(fetchAll, 30000)
  // 轮播进度 + 到点切屏（悬停暂停）。
  rotateTimer = window.setInterval(() => {
    if (paused.value) return
    rotateElapsed += 200
    rotatePct.value = Math.min(100, (rotateElapsed / ROTATE_MS) * 100)
    if (rotateElapsed >= ROTATE_MS) go(screenIdx.value + 1)
  }, 200)
  fetchAll()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', fit)
  if (clockTimer) clearInterval(clockTimer)
  if (dataTimer) clearInterval(dataTimer)
  if (rotateTimer) clearInterval(rotateTimer)
  Object.values(rafByKey).forEach((id) => id && cancelAnimationFrame(id))
})

function exit() {
  router.push('/dashboard')
}
function toggleFullscreen() {
  if (!document.fullscreenElement) document.documentElement.requestFullscreen?.()
  else document.exitFullscreen?.()
}
function fmtInt(v: number) {
  return Math.round(v).toLocaleString('en-US')
}
</script>

<template>
  <div class="screen-root">
    <div class="canvas" :style="{ transform: `translate(-50%,-50%) scale(${scale})` }">
      <!-- 背景装饰 -->
      <div class="bg-grid"></div>
      <div class="bg-glow"></div>
      <div class="bg-stars"></div>
      <div class="scanline"></div>

      <!-- 顶栏 -->
      <header class="hd">
        <div class="hd-left">
          <div class="logo">烛</div>
        </div>
        <div class="hd-center">
          <div class="hd-title">后量子迁移治理巩固监测</div>
          <div class="hd-sub">ZHULONG POST-QUANTUM MIGRATION GOVERNANCE &amp; MONITORING</div>
        </div>
        <div class="hd-right">
          <div class="clock">
            <div class="ct">{{ clockTime }}</div>
            <div class="cd">{{ clockDate }}</div>
          </div>
          <div class="live"><span class="dot"></span>实时 · {{ updatedAt || '—' }}</div>
          <div class="scr-nav">
            <div
              v-for="(s, i) in SCREENS"
              :key="s.key"
              class="scr-dot"
              :class="{ on: screenIdx === i }"
              @click="go(i)"
            >
              {{ s.name }}
              <div v-if="screenIdx === i" class="scr-prog" :style="{ width: rotatePct + '%' }"></div>
            </div>
          </div>
          <div class="hd-btns">
            <button class="ghost" @click="toggleFullscreen">全屏</button>
            <button class="ghost" @click="exit">返回</button>
          </div>
        </div>
      </header>

      <!-- 多屏舞台 -->
      <div class="stage" @mouseenter="paused = true" @mouseleave="paused = false">
      <!-- ① 治理总览 -->
      <section class="screen" :class="{ active: screenIdx === 0 }">
      <div class="grid">
        <!-- 左列 -->
        <section class="col">
          <div class="panel">
            <div class="p-title">核心指标</div>
            <div class="kpis">
              <div class="kpi">
                <div class="kv">{{ fmtInt(disp.total) }}</div>
                <div class="kl">密码使用点</div>
              </div>
              <div class="kpi danger">
                <div class="kv">{{ fmtInt(disp.p1) }}</div>
                <div class="kl">P1 极高</div>
              </div>
              <div class="kpi warn">
                <div class="kv">{{ fmtInt(disp.hndl) }}</div>
                <div class="kl">HNDL 重点</div>
              </div>
              <div class="kpi">
                <div class="kv">{{ fmtInt(disp.avg) }}</div>
                <div class="kl">平均风险分</div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="p-title">PQC 迁移分布（密钥交换维）</div>
            <div class="compliance">
              <div class="cmp-cell">
                <div class="cmp-v" style="color: #ff9f45">{{ migrationDist.classical }}</div>
                <div class="cmp-l">经典（待迁移）</div>
              </div>
              <div class="cmp-cell">
                <div class="cmp-v" style="color: #22d3ee">{{ migrationDist.hybrid }}</div>
                <div class="cmp-l">半迁移（混合）</div>
              </div>
              <div class="cmp-cell">
                <div class="cmp-v" style="color: #3fd08a">{{ migrationDist.safe }}</div>
                <div class="cmp-l">全迁移（PQC）</div>
              </div>
              <div class="cmp-cell">
                <div class="cmp-v" style="color: #8fb0d6">{{ migrationDist.na }}</div>
                <div class="cmp-l">未判定/不适用</div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="p-title">风险优先级分布</div>
            <div class="funnel">
              <div v-for="p in prio" :key="p.k" class="fn-row">
                <span class="fn-lab">{{ p.label }}</span>
                <div class="fn-track">
                  <div class="fn-bar" :style="{ width: p.pct + '%', background: p.c, boxShadow: `0 0 12px ${p.c}88` }"></div>
                </div>
                <span class="fn-num" :style="{ color: p.c }">{{ p.count }}</span>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="p-title">资产分层分布 (L1–L4)</div>
            <div class="funnel">
              <div v-for="l in layers" :key="l.k" class="fn-row">
                <span class="fn-lab sm">{{ l.label }}</span>
                <div class="fn-track">
                  <div class="fn-bar" :style="{ width: l.pct + '%', background: l.c, boxShadow: `0 0 12px ${l.c}77` }"></div>
                </div>
                <span class="fn-num" :style="{ color: l.c }">{{ l.v }}</span>
              </div>
            </div>
          </div>
        </section>

        <!-- 中列 -->
        <section class="col center">
          <div class="panel gauge-panel">
            <div class="p-title">治理巩固度</div>
            <svg viewBox="0 0 300 210" class="gauge">
              <defs>
                <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stop-color="#165dff" />
                  <stop offset="55%" stop-color="#22d3ee" />
                  <stop offset="100%" :stop-color="govLevel.c" />
                </linearGradient>
              </defs>
              <path :d="govArcBg" fill="none" stroke="#12203a" stroke-width="16" stroke-linecap="round" />
              <path :d="govArcVal" fill="none" stroke="url(#gaugeGrad)" stroke-width="16" stroke-linecap="round" class="gauge-val" />
              <circle :cx="govTip.x" :cy="govTip.y" r="8" :fill="govLevel.c" class="gauge-tip" />
              <text x="150" y="140" text-anchor="middle" class="gauge-num">{{ Math.round(disp.gov) }}</text>
              <text x="150" y="166" text-anchor="middle" class="gauge-unit">/ 100</text>
              <text x="150" y="196" text-anchor="middle" class="gauge-lv" :fill="govLevel.c">{{ govLevel.t }}</text>
            </svg>
            <div class="gauge-parts">
              <div><b>{{ Math.round(govParts.assess * 100) }}%</b><span>评估覆盖</span></div>
              <div><b>{{ Math.round(govParts.remed * 100) }}%</b><span>改造完成</span></div>
              <div><b>{{ Math.round(govParts.health * 100) }}%</b><span>低危占比</span></div>
            </div>
          </div>

          <div class="panel pipe-panel">
            <div class="p-title">五阶段治理闭环</div>
            <svg viewBox="0 0 760 190" class="pipe">
              <path id="pipeMain" d="M 90 70 H 670" fill="none" stroke="#1c3050" stroke-width="3" />
              <path
                d="M 90 70 H 670"
                fill="none"
                stroke="#22d3ee"
                stroke-width="3"
                stroke-dasharray="10 14"
                class="flow"
              />
              <!-- 数据流入粒子 -->
              <circle v-for="n in 6" :key="'pm' + n" r="3.6" class="particle">
                <animateMotion dur="2.6s" repeatCount="indefinite" :begin="n * 0.42 + 's'">
                  <mpath href="#pipeMain" xlink:href="#pipeMain" />
                </animateMotion>
              </circle>
              <!-- 回环 -->
              <path
                d="M 670 70 C 720 70 720 150 380 150 C 40 150 40 70 90 70"
                fill="none"
                stroke="#1c3050"
                stroke-width="2.5"
              />
              <path
                d="M 670 70 C 720 70 720 150 380 150 C 40 150 40 70 90 70"
                fill="none"
                stroke="#165dff"
                stroke-width="2.5"
                stroke-dasharray="8 16"
                class="flow-rev"
              />
              <g v-for="(s, i) in stages" :key="s.key">
                <circle :cx="90 + i * 145" cy="70" r="34" fill="#0b1730" stroke="#22d3ee" stroke-width="2" class="node" />
                <circle :cx="90 + i * 145" cy="70" r="34" fill="none" stroke="#22d3ee" stroke-width="2" class="node-pulse" />
                <text :x="90 + i * 145" y="64" text-anchor="middle" class="node-v">{{ s.v }}</text>
                <text :x="90 + i * 145" y="82" text-anchor="middle" class="node-u">{{ s.unit }}</text>
                <text :x="90 + i * 145" y="128" text-anchor="middle" class="node-l">{{ s.label }}</text>
              </g>
            </svg>
          </div>

          <div class="panel">
            <div class="p-title">资产 / 改造趋势（近 14 日）</div>
            <svg viewBox="0 0 760 160" class="trend">
              <defs>
                <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#165dff" stop-opacity="0.35" />
                  <stop offset="100%" stop-color="#165dff" stop-opacity="0" />
                </linearGradient>
              </defs>
              <path v-if="trendGeom.area" :d="trendGeom.area" fill="url(#areaGrad)" />
              <path v-if="trendGeom.total" :d="trendGeom.total" fill="none" stroke="#22d3ee" stroke-width="2.5" />
              <path v-if="trendGeom.remed" :d="trendGeom.remed" fill="none" stroke="#3fd08a" stroke-width="2.5" stroke-dasharray="5 4" />
              <text v-if="!trendGeom.total" x="380" y="80" text-anchor="middle" class="empty">暂无足够趋势数据</text>
            </svg>
            <div class="legend">
              <span><i style="background:#22d3ee"></i>资产总数</span>
              <span><i style="background:#3fd08a"></i>已改造</span>
            </div>
          </div>
        </section>

        <!-- 右列 -->
        <section class="col">
          <div class="panel">
            <div class="p-title">改造进度</div>
            <div class="rem-wrap">
              <svg viewBox="0 0 180 180" class="rem-ring">
                <circle cx="90" cy="90" r="74" fill="none" stroke="#12203a" stroke-width="14" />
                <circle
                  cx="90" cy="90" r="74" fill="none" stroke="#3fd08a" stroke-width="14" stroke-linecap="round"
                  :stroke-dasharray="remRing.dash" transform="rotate(-90 90 90)" class="rem-arc"
                />
                <text x="90" y="86" text-anchor="middle" class="rem-pct">{{ remRing.pct }}%</text>
                <text x="90" y="108" text-anchor="middle" class="rem-sub">完成率</text>
              </svg>
              <div class="rem-stats">
                <div><b style="color:#3fd08a">{{ remRing.done }}</b><span>已完成</span></div>
                <div><b style="color:#22d3ee">{{ remRing.running }}</b><span>执行中</span></div>
                <div><b style="color:#f2c14e">{{ remRing.planned }}</b><span>待执行</span></div>
                <div><b style="color:#ff5b52">{{ remRing.failed }}</b><span>失败</span></div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="p-title">发现方式覆盖 (M1–M7)</div>
            <div class="cov">
              <div v-for="c in coverage" :key="c.m" class="cov-row" :class="{ off: !c.active }">
                <span class="cov-m">{{ c.m }}</span>
                <span class="cov-n">{{ c.name }}</span>
                <div class="cov-track">
                  <div class="cov-bar" :style="{ width: Math.round((c.planned / covMax) * 100) + '%' }"></div>
                </div>
                <span class="cov-h">{{ c.hit }}/{{ c.planned }}</span>
              </div>
            </div>
          </div>

          <div class="panel evt-panel">
            <div class="p-title">
              监测告警 · 近期 P1 事件
              <span class="badge" v-if="certExpiring">证书临期 {{ certExpiring }}</span>
            </div>
            <div class="evt-list">
              <div v-for="(e, i) in events" :key="i" class="evt">
                <span class="evt-dot"></span>
                <span class="evt-name">{{ (e as any).title || (e as any).assetName || (e as any).kind || 'P1 事件' }}</span>
                <span class="evt-t">{{ String((e as any).occurredAt || '').slice(5, 16) }}</span>
              </div>
              <div v-if="!events.length" class="evt empty-evt">暂无 P1 事件 · 监测态势平稳</div>
            </div>
          </div>
        </section>
      </div>
      </section>

      <!-- ② 改造专题 -->
      <section class="screen" :class="{ active: screenIdx === 1 }">
        <div class="grid">
          <section class="col">
            <div class="panel">
              <div class="p-title">改造态势</div>
              <div class="kpis">
                <div v-for="(k, i) in remKpis" :key="i" class="kpi">
                  <div class="kv" :style="{ color: k.c }">{{ k.v }}</div>
                  <div class="kl">{{ k.l }}</div>
                </div>
              </div>
            </div>
            <div class="panel">
              <div class="p-title">改造完成度</div>
              <div class="bigring-wrap">
                <svg viewBox="0 0 200 200" class="big-ring">
                  <circle cx="100" cy="100" r="82" fill="none" stroke="#12203a" stroke-width="16" />
                  <circle
                    cx="100" cy="100" r="82" fill="none" stroke="#3fd08a" stroke-width="16" stroke-linecap="round"
                    :stroke-dasharray="`${(2 * Math.PI * 82 * remRing.pct) / 100} ${2 * Math.PI * 82}`"
                    transform="rotate(-90 100 100)" class="rem-arc"
                  />
                  <text x="100" y="94" text-anchor="middle" class="bigring-pct">{{ remRing.pct }}%</text>
                  <text x="100" y="120" text-anchor="middle" class="bigring-sub">{{ remRing.done }} / {{ remRing.total }} 工单</text>
                </svg>
              </div>
            </div>
          </section>

          <section class="col center">
            <div class="panel" style="flex: 1">
              <div class="p-title">改造工单流 · 最近编排</div>
              <div class="task-list">
                <div v-for="(t, i) in remTasks" :key="i" class="task-row">
                  <div class="task-top">
                    <span class="task-name">{{ t.name }}</span>
                    <span class="task-status" :style="{ color: (remStatusMeta[t.status] || {}).c || '#9fdcf0' }">
                      {{ (remStatusMeta[t.status] || { t: '未知' }).t }} · {{ t.progress }}%
                    </span>
                  </div>
                  <div class="task-meta">{{ t.track }}<span v-if="t.target"> → {{ t.target }}</span></div>
                  <div class="task-track">
                    <div
                      class="task-bar flow-bar"
                      :style="{ width: t.progress + '%', background: (remStatusMeta[t.status] || { c: '#22d3ee' }).c }"
                    ></div>
                  </div>
                </div>
                <div v-if="!remTasks.length" class="list-empty">暂无改造工单 · 前往「改造编排」发起</div>
              </div>
            </div>
          </section>

          <section class="col">
            <div class="panel">
              <div class="p-title">工单状态分布</div>
              <div class="funnel">
                <div v-for="b in remBreakdown" :key="b.label" class="fn-row">
                  <span class="fn-lab">{{ b.label }}</span>
                  <div class="fn-track">
                    <div class="fn-bar flow-bar" :style="{ width: b.pct + '%', background: b.c, boxShadow: `0 0 12px ${b.c}88` }"></div>
                  </div>
                  <span class="fn-num" :style="{ color: b.c }">{{ b.v }}</span>
                </div>
              </div>
            </div>
            <div class="panel">
              <div class="p-title">执行设备</div>
              <div class="dev-list">
                <div v-for="(d, i) in deviceRows" :key="i" class="dev-row">
                  <span class="dev-dot" :class="{ on: d.online }"></span>
                  <span class="dev-name">{{ d.name }}</span>
                  <span class="dev-type">{{ d.type }}</span>
                  <span class="dev-lat" :style="{ color: d.online ? '#3fd08a' : '#7f9cc0' }">
                    {{ d.online ? d.latency + 'ms' : '离线' }}
                  </span>
                </div>
                <div v-if="!deviceRows.length" class="list-empty">暂无编排设备</div>
              </div>
            </div>
          </section>
        </div>
      </section>

      <!-- ③ 监测专题 -->
      <section class="screen" :class="{ active: screenIdx === 2 }">
        <div class="grid">
          <section class="col">
            <div class="panel">
              <div class="p-title">监测态势</div>
              <div class="kpis">
                <div v-for="(k, i) in monKpis" :key="i" class="kpi">
                  <div class="kv" :style="{ color: k.c }">{{ k.v }}</div>
                  <div class="kl">{{ k.l }}</div>
                </div>
              </div>
            </div>
            <div class="panel" style="flex: 1.4">
              <div class="p-title">SLO 指标达成</div>
              <div class="funnel">
                <div v-for="s in sloRows" :key="s.code" class="fn-row">
                  <span class="fn-lab sm">{{ s.name }}</span>
                  <div class="fn-track">
                    <div
                      class="fn-bar flow-bar"
                      :style="{ width: s.pct + '%', background: s.breached ? '#ff5b52' : '#22d3ee' }"
                    ></div>
                  </div>
                  <span class="fn-num sm" :style="{ color: s.breached ? '#ff5b52' : '#7fd6ff' }">
                    {{ s.value }}{{ s.unit === 'pct' || s.unit === 'pct_cov' ? '%' : s.unit === 'ms' ? 'ms' : '' }}
                  </span>
                </div>
                <div v-if="!sloRows.length" class="list-empty">SLO 指标待接入</div>
              </div>
            </div>
          </section>

          <section class="col center">
            <div class="panel" style="flex: 1.2">
              <div class="p-title">近期 P1 监测事件</div>
              <div class="evt-list">
                <div v-for="(e, i) in p1EventRows" :key="i" class="evt">
                  <span class="evt-dot"></span>
                  <span class="evt-name">{{ e.title }}</span>
                  <span class="evt-t">{{ e.slo }} · {{ e.at }}</span>
                </div>
                <div v-if="!p1EventRows.length" class="evt empty-evt">暂无 P1 事件 · 监测态势平稳</div>
              </div>
            </div>
            <div class="panel">
              <div class="p-title">常态化风险台账</div>
              <div class="risk-list">
                <div v-for="(r, i) in riskRows" :key="i" class="risk-row">
                  <span class="risk-lvl" :style="{ color: r.c, borderColor: r.c }">{{ r.level }}</span>
                  <span class="risk-desc">{{ r.code }} · {{ r.desc }}</span>
                  <span class="risk-st">{{ r.status }}</span>
                </div>
                <div v-if="!riskRows.length" class="list-empty">无常态化风险</div>
              </div>
            </div>
          </section>

          <section class="col">
            <div class="panel" style="flex: 1.3">
              <div class="p-title">证书到期预警</div>
              <div class="cert-list">
                <div v-for="(c, i) in certRows" :key="i" class="cert-row">
                  <span class="cert-days" :style="{ color: c.c, borderColor: c.c }">{{ c.days }}天</span>
                  <span class="cert-name">{{ c.name }}</span>
                  <span class="cert-kind">{{ c.kind }}</span>
                  <span v-if="c.noOta" class="cert-ota">无OTA</span>
                </div>
                <div v-if="!certRows.length" class="list-empty">近 90 日无证书临期</div>
              </div>
            </div>
            <div class="panel">
              <div class="p-title">CBOM 与合规</div>
              <div class="compliance">
                <div class="cmp-cell">
                  <div class="cmp-v" style="color: #3fd08a">{{ cbomFresh }}</div>
                  <div class="cmp-l">CBOM 新鲜度</div>
                </div>
                <div class="cmp-cell">
                  <div class="cmp-v" style="color: #7fd6ff">{{ (mon?.reassessQueue || []).length }}</div>
                  <div class="cmp-l">待复评</div>
                </div>
                <div class="cmp-cell">
                  <div class="cmp-v" style="color: #22d3ee">{{ govScore }}</div>
                  <div class="cmp-l">治理巩固度</div>
                </div>
              </div>
            </div>
          </section>
        </div>
      </section>
      </div>

      <!-- 底部：统计条 + 跑马灯 -->
      <footer class="btm">
        <div class="stat-strip">
          <div v-for="(s, i) in strip" :key="i" class="chip">
            <span class="chip-glyph"></span>
            <div class="chip-body">
              <div class="chip-v" :style="{ color: s.c }">{{ s.value }}</div>
              <div class="chip-l">{{ s.label }}</div>
            </div>
          </div>
        </div>
        <div class="ticker">
          <span class="ticker-live"><span class="tl-dot"></span>LIVE</span>
          <div class="ticker-mask">
            <div class="ticker-track">
              <span v-for="(m, i) in ticker" :key="'a' + i" class="ticker-item">{{ m }}</span>
              <span v-for="(m, i) in ticker" :key="'b' + i" class="ticker-item">{{ m }}</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.screen-root {
  position: fixed;
  inset: 0;
  background: radial-gradient(1200px 700px at 50% -10%, #0b1d3a 0%, #060a16 55%, #04060e 100%);
  overflow: hidden;
  z-index: 3000;
}
.canvas {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 1920px;
  height: 1080px;
  transform-origin: center center;
  color: #cfe0f5;
  font-family: 'Hanken Grotesk', -apple-system, 'PingFang SC', 'Microsoft YaHei', sans-serif;
  padding: 26px 34px;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}
.bg-grid {
  position: absolute;
  inset: 0;
  background-image: linear-gradient(rgba(34, 211, 238, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(34, 211, 238, 0.05) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(1000px 700px at 50% 40%, #000 30%, transparent 85%);
  pointer-events: none;
}
.bg-glow {
  position: absolute;
  inset: 0;
  background: radial-gradient(600px 300px at 50% 42%, rgba(22, 93, 255, 0.14), transparent 70%);
  pointer-events: none;
}

/* 顶栏 */
.hd {
  position: relative;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 18px;
  border-bottom: 1px solid rgba(34, 211, 238, 0.22);
  margin-bottom: 20px;
}
.hd::after {
  content: '';
  position: absolute;
  left: 0;
  bottom: -1px;
  width: 320px;
  height: 2px;
  background: linear-gradient(90deg, #22d3ee, transparent);
}
.hd-left {
  display: flex;
  align-items: center;
  gap: 16px;
}
.hd-center {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  top: 0;
  bottom: 18px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  text-align: center;
  pointer-events: none;
}
.logo {
  width: 54px;
  height: 54px;
  border-radius: 14px;
  background: linear-gradient(135deg, #165dff, #22d3ee);
  color: #fff;
  font-size: 30px;
  font-weight: 800;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 26px rgba(34, 211, 238, 0.5);
}
.hd-title {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: 1px;
  background: linear-gradient(90deg, #eaf4ff, #7fd6ff);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.hd-sub {
  font-size: 12px;
  letter-spacing: 3px;
  color: #4d6a92;
  margin-top: 4px;
}
.hd-right {
  display: flex;
  align-items: center;
  gap: 26px;
}
.clock {
  text-align: right;
}
.ct {
  font-size: 30px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  color: #d9ecff;
}
.cd {
  font-size: 12px;
  color: #5a789f;
}
.live {
  font-size: 13px;
  color: #3fd08a;
  display: flex;
  align-items: center;
  gap: 7px;
  font-variant-numeric: tabular-nums;
}
.live .dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #3fd08a;
  box-shadow: 0 0 10px #3fd08a;
  animation: pulse 1.6s infinite;
}
.hd-btns {
  display: flex;
  gap: 10px;
}
.ghost {
  background: rgba(34, 211, 238, 0.08);
  border: 1px solid rgba(34, 211, 238, 0.3);
  color: #9fdcf0;
  padding: 7px 16px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 13px;
  font-family: inherit;
}
.ghost:hover {
  background: rgba(34, 211, 238, 0.18);
}

/* 栅格 */
.stage {
  position: relative;
  flex: 1;
  min-height: 0;
  margin-bottom: 16px;
}
.screen {
  position: absolute;
  inset: 0;
  opacity: 0;
  transform: translateX(46px) scale(0.99);
  transition: opacity 0.6s ease, transform 0.6s cubic-bezier(0.22, 1, 0.36, 1);
  pointer-events: none;
}
.screen.active {
  opacity: 1;
  transform: none;
  pointer-events: auto;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1.35fr 1fr;
  gap: 20px;
  height: 100%;
}
.col {
  display: flex;
  flex-direction: column;
  gap: 20px;
  min-height: 0;
}
.col.center {
  gap: 20px;
}
.panel {
  position: relative;
  background: linear-gradient(160deg, rgba(15, 32, 60, 0.72), rgba(9, 18, 36, 0.72));
  border: 1px solid rgba(56, 116, 190, 0.28);
  border-radius: 14px;
  padding: 16px 18px;
  flex: 1;
  min-height: 0;
  backdrop-filter: blur(4px);
  box-shadow: inset 0 0 40px rgba(20, 60, 120, 0.12);
}
.panel::before,
.panel::after {
  content: '';
  position: absolute;
  width: 14px;
  height: 14px;
  border: 2px solid #22d3ee;
  opacity: 0.7;
}
.panel::before {
  top: -1px;
  left: -1px;
  border-right: none;
  border-bottom: none;
  border-top-left-radius: 6px;
}
.panel::after {
  bottom: -1px;
  right: -1px;
  border-left: none;
  border-top: none;
  border-bottom-right-radius: 6px;
}
.p-title {
  font-size: 17px;
  font-weight: 700;
  color: #bfe4ff;
  margin-bottom: 14px;
  padding-left: 12px;
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
}
.p-title::before {
  content: '';
  position: absolute;
  left: 0;
  top: 2px;
  bottom: 2px;
  width: 4px;
  border-radius: 2px;
  background: linear-gradient(#22d3ee, #165dff);
}
.badge {
  font-size: 12px;
  font-weight: 600;
  color: #ffb454;
  background: rgba(255, 159, 69, 0.14);
  border: 1px solid rgba(255, 159, 69, 0.35);
  padding: 1px 9px;
  border-radius: 10px;
}

/* KPI */
.kpis {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  height: calc(100% - 32px);
}
.kpi {
  border-radius: 12px;
  background: rgba(22, 93, 255, 0.08);
  border: 1px solid rgba(56, 116, 190, 0.3);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
}
.kpi.danger {
  background: rgba(255, 91, 82, 0.09);
  border-color: rgba(255, 91, 82, 0.32);
}
.kpi.warn {
  background: rgba(255, 159, 69, 0.09);
  border-color: rgba(255, 159, 69, 0.32);
}
.kv {
  font-size: 40px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: #eaf4ff;
  text-shadow: 0 0 18px rgba(34, 211, 238, 0.4);
}
.kpi.danger .kv {
  color: #ff7b72;
  text-shadow: 0 0 18px rgba(255, 91, 82, 0.4);
}
.kpi.warn .kv {
  color: #ffb454;
  text-shadow: 0 0 18px rgba(255, 159, 69, 0.4);
}
.kl {
  font-size: 13px;
  color: #8fb0d6;
}

/* 漏斗 / 分层条 */
.funnel {
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  height: calc(100% - 32px);
}
.fn-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.fn-lab {
  width: 66px;
  font-size: 14px;
  color: #a9c6e6;
  flex-shrink: 0;
}
.fn-lab.sm {
  width: 108px;
  font-size: 13px;
}
.fn-track {
  flex: 1;
  height: 16px;
  background: rgba(20, 40, 70, 0.6);
  border-radius: 8px;
  overflow: hidden;
}
.fn-bar {
  height: 100%;
  border-radius: 8px;
  transition: width 1.1s cubic-bezier(0.22, 1, 0.36, 1);
}
.fn-num {
  width: 44px;
  text-align: right;
  font-size: 20px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

/* 仪表 */
.center {
  display: flex;
}
.gauge-panel {
  flex: 1.15;
  display: flex;
  flex-direction: column;
}
.gauge {
  width: 100%;
  height: calc(100% - 66px);
  max-height: 210px;
}
.gauge-val {
  filter: drop-shadow(0 0 8px rgba(34, 211, 238, 0.6));
  transition: none;
}
.gauge-num {
  font-size: 62px;
  font-weight: 800;
  fill: #eaf4ff;
  font-variant-numeric: tabular-nums;
}
.gauge-unit {
  font-size: 16px;
  fill: #5f80a8;
}
.gauge-lv {
  font-size: 20px;
  font-weight: 700;
}
.gauge-parts {
  display: flex;
  justify-content: space-around;
  margin-top: 6px;
}
.gauge-parts div {
  display: flex;
  flex-direction: column;
  align-items: center;
}
.gauge-parts b {
  font-size: 22px;
  color: #7fd6ff;
  font-variant-numeric: tabular-nums;
}
.gauge-parts span {
  font-size: 12px;
  color: #7f9cc0;
}

/* 闭环 */
.pipe-panel {
  flex: 1;
}
.pipe {
  width: 100%;
  height: calc(100% - 32px);
}
.flow {
  animation: dash 1.2s linear infinite;
}
.flow-rev {
  animation: dash 2.4s linear infinite reverse;
  opacity: 0.7;
}
.node {
  filter: drop-shadow(0 0 8px rgba(34, 211, 238, 0.35));
}
.node-pulse {
  transform-origin: center;
  transform-box: fill-box;
  animation: ring 2.4s ease-out infinite;
}
.node-v {
  font-size: 24px;
  font-weight: 800;
  fill: #eaf4ff;
  font-variant-numeric: tabular-nums;
}
.node-u {
  font-size: 11px;
  fill: #6f90b8;
}
.node-l {
  font-size: 16px;
  font-weight: 700;
  fill: #9fdcf0;
}

/* 趋势 */
.trend {
  width: 100%;
  height: calc(100% - 56px);
}
.empty {
  fill: #4d6a92;
  font-size: 15px;
}
.legend {
  display: flex;
  gap: 22px;
  justify-content: center;
  font-size: 13px;
  color: #8fb0d6;
}
.legend i {
  display: inline-block;
  width: 14px;
  height: 4px;
  border-radius: 2px;
  margin-right: 6px;
  vertical-align: middle;
}

/* 改造环 */
.rem-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  height: calc(100% - 32px);
}
.rem-ring {
  width: 150px;
  height: 150px;
  flex-shrink: 0;
}
.rem-arc {
  filter: drop-shadow(0 0 6px rgba(63, 208, 138, 0.6));
  transition: stroke-dasharray 1.1s cubic-bezier(0.22, 1, 0.36, 1);
}
.rem-pct {
  font-size: 34px;
  font-weight: 800;
  fill: #eaf4ff;
  font-variant-numeric: tabular-nums;
}
.rem-sub {
  font-size: 12px;
  fill: #6f90b8;
}
.rem-stats {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 8px;
}
.rem-stats div {
  display: flex;
  flex-direction: column;
}
.rem-stats b {
  font-size: 26px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}
.rem-stats span {
  font-size: 12px;
  color: #7f9cc0;
}

/* 覆盖 */
.cov {
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  height: calc(100% - 32px);
}
.cov-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.cov-row.off {
  opacity: 0.45;
}
.cov-m {
  width: 34px;
  font-size: 14px;
  font-weight: 700;
  color: #22d3ee;
}
.cov-n {
  width: 76px;
  font-size: 13px;
  color: #a9c6e6;
}
.cov-track {
  flex: 1;
  height: 12px;
  background: rgba(20, 40, 70, 0.6);
  border-radius: 6px;
  overflow: hidden;
}
.cov-bar {
  height: 100%;
  border-radius: 6px;
  background: linear-gradient(90deg, #165dff, #22d3ee);
  box-shadow: 0 0 10px rgba(34, 211, 238, 0.5);
  transition: width 1.1s cubic-bezier(0.22, 1, 0.36, 1);
}
.cov-h {
  width: 52px;
  text-align: right;
  font-size: 15px;
  font-weight: 700;
  color: #cfe0f5;
  font-variant-numeric: tabular-nums;
}

/* 事件 */
.evt-panel {
  flex: 1.1;
}
.evt-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.evt {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
  padding: 8px 10px;
  background: rgba(255, 91, 82, 0.06);
  border-left: 3px solid #ff5b52;
  border-radius: 6px;
}
.evt-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #ff5b52;
  box-shadow: 0 0 8px #ff5b52;
  flex-shrink: 0;
}
.evt-name {
  flex: 1;
  color: #dbe8f7;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.evt-t {
  font-size: 12px;
  color: #7f9cc0;
  font-variant-numeric: tabular-nums;
}
.empty-evt {
  justify-content: center;
  color: #4d8a6a;
  background: rgba(63, 208, 138, 0.06);
  border-left-color: #3fd08a;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
@keyframes dash {
  to { stroke-dashoffset: -24; }
}
@keyframes ring {
  0% { opacity: 0.7; transform: scale(1); }
  100% { opacity: 0; transform: scale(1.5); }
}

/* 星点漂移 */
.bg-stars {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image:
    radial-gradient(1.4px 1.4px at 12% 22%, rgba(140, 200, 255, 0.7), transparent),
    radial-gradient(1.2px 1.2px at 32% 68%, rgba(120, 230, 255, 0.55), transparent),
    radial-gradient(1.6px 1.6px at 58% 18%, rgba(160, 210, 255, 0.6), transparent),
    radial-gradient(1.1px 1.1px at 74% 52%, rgba(120, 220, 255, 0.5), transparent),
    radial-gradient(1.5px 1.5px at 88% 30%, rgba(150, 205, 255, 0.6), transparent),
    radial-gradient(1.2px 1.2px at 46% 84%, rgba(120, 220, 255, 0.45), transparent),
    radial-gradient(1.3px 1.3px at 22% 46%, rgba(140, 200, 255, 0.5), transparent);
  animation: twinkle 4.5s ease-in-out infinite alternate;
}

/* 全屏扫描线扫掠 */
.scanline {
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  height: 160px;
  pointer-events: none;
  background: linear-gradient(180deg, transparent, rgba(34, 211, 238, 0.05) 60%, rgba(34, 211, 238, 0.14) 92%, rgba(120, 230, 255, 0.55) 100%);
  animation: sweep 7.5s linear infinite;
  will-change: transform;
}

/* 仪表末端辉光点 */
.gauge-tip {
  filter: drop-shadow(0 0 8px currentColor);
}

/* 底部区 */
.btm {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.stat-strip {
  display: flex;
  gap: 14px;
}
.chip {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 18px;
  border-radius: 12px;
  background: linear-gradient(160deg, rgba(15, 32, 60, 0.72), rgba(9, 18, 36, 0.72));
  border: 1px solid rgba(56, 116, 190, 0.3);
  box-shadow: inset 0 0 30px rgba(20, 60, 120, 0.12);
  position: relative;
  overflow: hidden;
}
.chip::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  background: linear-gradient(#22d3ee, #165dff);
}
.chip-glyph {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #22d3ee;
  box-shadow: 0 0 10px #22d3ee;
  flex-shrink: 0;
  animation: pulse 2s infinite;
}
.chip-v {
  font-size: 28px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
  text-shadow: 0 0 14px rgba(34, 211, 238, 0.3);
}
.chip-l {
  font-size: 13px;
  color: #8fb0d6;
}

/* 跑马灯 */
.ticker {
  display: flex;
  align-items: center;
  height: 40px;
  border-radius: 10px;
  background: linear-gradient(90deg, rgba(22, 93, 255, 0.14), rgba(9, 18, 36, 0.6));
  border: 1px solid rgba(56, 116, 190, 0.3);
  overflow: hidden;
}
.ticker-live {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 0 18px;
  height: 100%;
  font-size: 14px;
  font-weight: 800;
  letter-spacing: 1px;
  color: #ff5b52;
  background: rgba(255, 91, 82, 0.12);
  border-right: 1px solid rgba(255, 91, 82, 0.3);
  flex-shrink: 0;
}
.tl-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #ff5b52;
  box-shadow: 0 0 8px #ff5b52;
  animation: pulse 1.4s infinite;
}
.ticker-mask {
  flex: 1;
  overflow: hidden;
}
.ticker-track {
  display: inline-flex;
  white-space: nowrap;
  animation: marquee 46s linear infinite;
}
.ticker-item {
  padding: 0 34px;
  font-size: 14.5px;
  color: #b6d2ee;
  position: relative;
}
.ticker-item::after {
  content: '◆';
  position: absolute;
  right: -5px;
  color: #22d3ee;
  opacity: 0.5;
  font-size: 9px;
  top: 50%;
  transform: translateY(-50%);
}

@keyframes twinkle {
  from { opacity: 0.35; }
  to { opacity: 0.9; }
}
@keyframes sweep {
  0% { transform: translateY(-160px); }
  100% { transform: translateY(1080px); }
}
@keyframes marquee {
  from { transform: translateX(0); }
  to { transform: translateX(-50%); }
}

/* 管线数据粒子 */
.particle {
  fill: #9df0ff;
  filter: drop-shadow(0 0 5px #22d3ee);
}

/* 进度条流光 */
.flow-bar {
  position: relative;
  overflow: hidden;
}
.flow-bar::after {
  content: '';
  position: absolute;
  top: 0;
  bottom: 0;
  left: 0;
  width: 45%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.5), transparent);
  transform: translateX(-120%);
  animation: streak 2.4s linear infinite;
  will-change: transform;
}
@keyframes streak {
  from { transform: translateX(-120%); }
  to { transform: translateX(340%); }
}
.flow,
.flow-rev,
.ticker-track,
.bg-stars {
  will-change: transform;
}
/* 尊重系统「减少动态」偏好：关掉常驻氛围动画 */
@media (prefers-reduced-motion: reduce) {
  .scanline,
  .bg-stars,
  .particle,
  .flow,
  .flow-rev,
  .ticker-track,
  .flow-bar::after,
  .node-pulse,
  .chip-glyph,
  .tl-dot,
  .live .dot {
    animation: none !important;
  }
}

/* 轮播导航 */
.scr-nav {
  display: flex;
  gap: 8px;
}
.scr-dot {
  position: relative;
  padding: 6px 14px;
  border-radius: 8px;
  font-size: 14px;
  color: #7f9cc0;
  cursor: pointer;
  border: 1px solid transparent;
  background: rgba(20, 40, 70, 0.4);
  overflow: hidden;
  transition: color 0.3s, background 0.3s, border-color 0.3s;
}
.scr-dot.on {
  color: #bfe4ff;
  border-color: rgba(34, 211, 238, 0.4);
  background: rgba(34, 211, 238, 0.12);
}
.scr-prog {
  position: absolute;
  left: 0;
  bottom: 0;
  height: 2px;
  background: #22d3ee;
  box-shadow: 0 0 6px #22d3ee;
}

/* 改造完成度大环 */
.bigring-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  height: calc(100% - 32px);
}
.big-ring {
  width: 200px;
  height: 200px;
}
.bigring-pct {
  font-size: 44px;
  font-weight: 800;
  fill: #eaf4ff;
  font-variant-numeric: tabular-nums;
}
.bigring-sub {
  font-size: 14px;
  fill: #7f9cc0;
}

/* 工单流 */
.task-list {
  display: flex;
  flex-direction: column;
  gap: 11px;
  height: calc(100% - 32px);
  overflow: hidden;
}
.task-row {
  background: rgba(20, 40, 70, 0.35);
  border: 1px solid rgba(56, 116, 190, 0.22);
  border-radius: 10px;
  padding: 10px 14px;
}
.task-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.task-name {
  font-size: 16px;
  font-weight: 600;
  color: #dbe8f7;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.task-status {
  font-size: 13px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
  margin-left: 10px;
}
.task-meta {
  font-size: 12px;
  color: #7f9cc0;
  margin: 4px 0 8px;
}
.task-track {
  height: 8px;
  background: rgba(20, 40, 70, 0.6);
  border-radius: 4px;
  overflow: hidden;
}
.task-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 1s cubic-bezier(0.22, 1, 0.36, 1);
}

/* 设备列表 */
.dev-list {
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  height: calc(100% - 32px);
}
.dev-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.dev-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #6f90b8;
  flex-shrink: 0;
}
.dev-dot.on {
  background: #3fd08a;
  box-shadow: 0 0 8px #3fd08a;
}
.dev-name {
  flex: 1;
  color: #cfe0f5;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dev-type {
  font-size: 12px;
  color: #7f9cc0;
}
.dev-lat {
  font-size: 13px;
  font-variant-numeric: tabular-nums;
  width: 54px;
  text-align: right;
}

/* 证书到期 */
.cert-list {
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  height: calc(100% - 32px);
}
.cert-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.cert-days {
  width: 56px;
  text-align: center;
  font-size: 14px;
  font-weight: 700;
  border: 1px solid;
  border-radius: 6px;
  padding: 2px 0;
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}
.cert-name {
  flex: 1;
  color: #cfe0f5;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.cert-kind {
  font-size: 12px;
  color: #7f9cc0;
}
.cert-ota {
  font-size: 11px;
  color: #ff9f45;
  border: 1px solid rgba(255, 159, 69, 0.4);
  border-radius: 8px;
  padding: 1px 7px;
}

/* 风险台账 */
.risk-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  height: calc(100% - 32px);
}
.risk-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.risk-lvl {
  width: 34px;
  text-align: center;
  font-size: 13px;
  font-weight: 700;
  border: 1px solid;
  border-radius: 6px;
  padding: 1px 0;
  flex-shrink: 0;
}
.risk-desc {
  flex: 1;
  color: #cfe0f5;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.risk-st {
  font-size: 12px;
  color: #7f9cc0;
}

/* 合规 */
.compliance {
  display: flex;
  justify-content: space-around;
  align-items: center;
  height: calc(100% - 32px);
}
.cmp-cell {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}
.cmp-v {
  font-size: 34px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}
.cmp-l {
  font-size: 13px;
  color: #8fb0d6;
}

.list-empty {
  color: #4d6a92;
  font-size: 14px;
  text-align: center;
  padding: 22px 0;
}
.fn-num.sm {
  font-size: 15px;
  width: 58px;
}
</style>
