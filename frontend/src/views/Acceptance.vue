<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Message, type TableData } from '@arco-design/web-vue'
import { marked } from 'marked'
import {
  IconCheckCircle,
  IconRefresh,
  IconPlayArrow,
  IconFile,
  IconSend,
  IconStamp,
  IconUndo,
  IconBulb,
} from '@arco-design/web-vue/es/icon'
import { remediationApi, verifyApi } from '@/api'
import type {
  AcceptanceReport,
  AcceptanceRun,
  LegacyRisk,
  RemediationTask,
  SignAction,
  TestResult,
  VerifyMode,
  VerifyRunInput,
} from '@/api/types'
import {
  acceptanceRunStatusMeta,
  caseCategoryColor,
  caseCategoryLabel,
  fmtDate,
  signStateMeta,
  signStateStep,
  verdictMeta,
} from '@/utils/format'

const route = useRoute()

// 5 条改造轨道（与剧本 key 对齐）。
const TRACKS: { value: string; label: string }[] = [
  { value: 'tls-hybrid', label: 'TLS 混合迁移' },
  { value: 'ssl-vpn-hybrid', label: 'SSL VPN 混合迁移' },
  { value: 'root-ca-hybrid', label: '根 CA 混合迁移' },
  { value: 'code-signing', label: '代码签名（ML-DSA）' },
  { value: 'gm-hybrid', label: '国密混合迁移' },
]
function trackLabel(key: string): string {
  return TRACKS.find((t) => t.value === key)?.label ?? key
}

// ---------- 运行配置 ----------
const form = reactive({
  source: 'track' as 'track' | 'remediation', // 发起来源：选轨道 / 选 done 工单
  track: 'tls-hybrid',
  remediationId: undefined as number | undefined,
  target: '',
  mode: 'probe' as VerifyMode,
})

const doneTasks = ref<RemediationTask[]>([])
const runs = ref<AcceptanceRun[]>([])
const risks = ref<LegacyRisk[]>([])

const starting = ref(false)
const loadingRuns = ref(false)

// 当前选中工单（决定轨道/资产快照）。
const selectedTask = computed(() =>
  doneTasks.value.find((t) => t.id === form.remediationId),
)

// ---------- 当前运行 + 逐项结果 ----------
const activeRun = ref<AcceptanceRun | null>(null)
const results = ref<TestResult[]>([])
const loadingDetail = ref(false)

let pollTimer: number | undefined
function stopPoll() {
  if (pollTimer) {
    window.clearTimeout(pollTimer)
    pollTimer = undefined
  }
}

const resultColumns = [
  { title: '用例号', slotName: 'code', width: 124 },
  { title: '类别', slotName: 'category', width: 96 },
  { title: '名称', slotName: 'name', minWidth: 180, ellipsis: true, tooltip: true },
  { title: '期望', slotName: 'expect', minWidth: 180, ellipsis: true, tooltip: true },
  { title: '实测 / 模拟', slotName: 'actual', minWidth: 200, ellipsis: true, tooltip: true },
  { title: '判定', slotName: 'verdict', width: 116 },
  { title: '挂接风险', slotName: 'risk', width: 110 },
]

// 总览统计卡。
const overviewCards = computed(() => {
  const r = activeRun.value
  return [
    { key: 'total', label: '用例总数', value: r?.total ?? 0, color: '#1D2129' },
    { key: 'passed', label: '通过', value: r?.passed ?? 0, color: '#5a9367' },
    { key: 'conditional', label: '有条件', value: r?.conditional ?? 0, color: '#FF7D00' },
    { key: 'failed', label: '未通过', value: r?.failed ?? 0, color: '#cb4b3f' },
  ]
})

const p1Coverage = computed(() => {
  const r = activeRun.value
  if (!r || !r.p1Total) return '—'
  return `${r.p1Covered}/${r.p1Total}`
})
const p1Full = computed(() => {
  const r = activeRun.value
  return !!r && r.p1Total > 0 && r.p1Covered >= r.p1Total
})

const running = computed(() => activeRun.value?.status === 'running')

// ---------- 报告抽屉 + 签署 ----------
const reportOpen = ref(false)
const report = ref<AcceptanceReport | null>(null)
const generatingReport = ref(false)
const signing = ref(false)

marked.setOptions({ breaks: true, gfm: true })
const reportHtml = computed(() => {
  if (!report.value?.markdown) return ''
  return marked.parse(report.value.markdown) as string
})

const signStep = computed(() => signStateStep(report.value?.signState ?? 'DRAFT'))
const signRejected = computed(() => report.value?.signState === 'REJECTED')

// ================= 数据加载 =================
async function loadDoneTasks() {
  try {
    const all = await remediationApi.list()
    doneTasks.value = all.filter((t) => t.status === 'done')
  } catch {
    /* 忽略：发起区可只走轨道模式 */
  }
}

async function loadRuns() {
  loadingRuns.value = true
  try {
    runs.value = await verifyApi.listRuns()
  } catch {
    Message.error('加载验收运行失败，请确认后端 :8099 已启动')
  } finally {
    loadingRuns.value = false
  }
}

async function loadRisks() {
  try {
    risks.value = await verifyApi.risks()
  } catch {
    /* 风险台账为空也不阻断 */
  }
}

// ================= 发起验收 =================
async function startRun() {
  const payload: VerifyRunInput = { mode: form.mode }
  if (form.source === 'remediation') {
    if (form.remediationId == null) {
      Message.warning('请选择一个已完成（done）的改造工单')
      return
    }
    payload.taskId = form.remediationId
    const t = selectedTask.value
    if (t) {
      payload.track = t.track
      if (t.assetId != null) payload.assetId = t.assetId
    }
  } else {
    payload.track = form.track
  }
  if (form.target.trim()) payload.target = form.target.trim()

  starting.value = true
  try {
    const run = await verifyApi.createRun(payload)
    Message.info('验收已发起，正在逐项判定…')
    attachRun(run)
    await loadRuns()
  } catch {
    Message.error('发起验收失败')
  } finally {
    starting.value = false
  }
}

// 把一个 Run 设为当前，拉详情并按需轮询。
function attachRun(run: AcceptanceRun) {
  activeRun.value = run
  results.value = []
  refreshDetail(run.id, true)
}

async function refreshDetail(id: number, kickPoll = false) {
  loadingDetail.value = true
  try {
    const detail = await verifyApi.getRun(id)
    activeRun.value = detail.run
    results.value = detail.results ?? []
    // 同步列表行。
    const idx = runs.value.findIndex((x) => x.id === id)
    if (idx >= 0) runs.value[idx] = detail.run
    if (detail.run.status === 'running' && kickPoll) pollRun(id)
  } catch {
    /* 静默 */
  } finally {
    loadingDetail.value = false
  }
}

// 对运行轮询 ~2s 到结束。
function pollRun(id: number) {
  stopPoll()
  pollTimer = window.setTimeout(async () => {
    try {
      const detail = await verifyApi.getRun(id)
      if (activeRun.value?.id === id) {
        activeRun.value = detail.run
        results.value = detail.results ?? []
      }
      const idx = runs.value.findIndex((x) => x.id === id)
      if (idx >= 0) runs.value[idx] = detail.run
      if (detail.run.status === 'running') {
        pollRun(id)
      } else if (detail.run.status === 'done') {
        Message.success('验收运行完成')
      } else if (detail.run.status === 'failed') {
        Message.error(`验收失败：${detail.run.error || '执行异常'}`)
      }
    } catch {
      /* 静默轮询失败 */
    }
  }, 2000)
}

function openRun(record: TableData) {
  const r = record as AcceptanceRun
  attachRun(r)
}

// ================= 报告 + 签署 =================
async function openReport() {
  const run = activeRun.value
  if (!run) return
  reportOpen.value = true
  // 进入即清空旧报告并置加载态，避免串显上一份报告。
  report.value = null
  // 已有报告 → 直接拉全文；否则生成。
  if (run.reportId != null) {
    generatingReport.value = true
    try {
      report.value = await verifyApi.getReport(run.reportId)
    } catch {
      report.value = null
      Message.error('加载验收报告失败')
    } finally {
      generatingReport.value = false
    }
    return
  }
  generatingReport.value = true
  try {
    report.value = await verifyApi.createReport(run.id)
    if (activeRun.value) activeRun.value.reportId = report.value.id
    Message.success('验收报告已生成（草稿）')
  } catch {
    Message.error('生成验收报告失败')
  } finally {
    generatingReport.value = false
  }
}

async function doSign(action: SignAction) {
  if (!report.value) return
  signing.value = true
  try {
    const r = await verifyApi.sign(report.value.id, { action })
    report.value = r
    if (action === 'sign' && r.signState === 'SIGNED') {
      Message.success('已签署，关联资产已置「已验收」')
      // 资产置 verified 后刷新运行列表反映状态。
      await loadRuns()
    } else if (action === 'reject') {
      Message.warning('报告已退回')
    } else if (action === 'submit') {
      Message.info('已提交送审')
    } else if (action === 'approve') {
      Message.info('已批准，可签署')
    }
  } catch {
    Message.error('签署流转失败（请确认 Gate 通过且有条件项已挂风险）')
  } finally {
    signing.value = false
  }
}

// ================= 初始化 + query 自动发起 =================
onMounted(async () => {
  await Promise.all([loadDoneTasks(), loadRuns(), loadRisks()])

  const q = route.query
  // 改造页一键验收：带 runId 直接附着该运行；仅带 remediationId 则自动发起。
  if (q.runId) {
    const id = Number(q.runId)
    if (!Number.isNaN(id)) {
      await refreshDetail(id, true)
      return
    }
  }
  if (q.remediationId) {
    const rid = Number(q.remediationId)
    if (!Number.isNaN(rid)) {
      form.source = 'remediation'
      form.remediationId = rid
      // 工单可能还没加载到，等一拍再发起。
      await loadDoneTasks()
      await startRun()
    }
  }
})

onBeforeUnmount(stopPoll)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1 class="page-title">验收自动化</h1>
      <p class="page-subtitle">
        把 PQC 迁移验收（47 项实测）产品化为声明式、可重复、可回归、可签署的验收套件 ——
        改造 done → 一键跑验收 → 逐项判定 → 生成可签署报告 → 资产置「已验收」，打通改造与监测的接缝。
      </p>
    </div>

    <!-- ① 运行配置 -->
    <a-card class="block-card">
      <template #title>
        <span class="card-title-icon"><IconPlayArrow /> 发起验收</span>
      </template>
      <a-form :model="form" layout="vertical" class="run-form">
        <a-row :gutter="16">
          <a-col :xs="24" :md="6">
            <a-form-item label="发起来源">
              <a-radio-group v-model="form.source" type="button" size="small">
                <a-radio value="track">按轨道</a-radio>
                <a-radio value="remediation">按改造工单</a-radio>
              </a-radio-group>
            </a-form-item>
          </a-col>

          <a-col v-if="form.source === 'track'" :xs="24" :md="6">
            <a-form-item label="改造轨道">
              <a-select v-model="form.track" placeholder="选择改造轨道">
                <a-option
                  v-for="t in TRACKS"
                  :key="t.value"
                  :value="t.value"
                  :label="t.label"
                />
              </a-select>
            </a-form-item>
          </a-col>

          <a-col v-else :xs="24" :md="6">
            <a-form-item label="已完成改造工单">
              <a-select
                v-model="form.remediationId"
                placeholder="选择 done 状态工单"
                allow-search
                allow-clear
              >
                <a-option
                  v-for="t in doneTasks"
                  :key="t.id"
                  :value="t.id"
                  :label="t.assetName"
                >
                  {{ t.assetName }}
                  <span class="opt-sub">· {{ t.trackName }}</span>
                </a-option>
                <template #empty>
                  <a-empty description="暂无已完成工单" :image-size="36" />
                </template>
              </a-select>
            </a-form-item>
          </a-col>

          <a-col :xs="24" :md="6">
            <a-form-item>
              <template #label>
                探测目标
                <span class="label-hint">host:port（TLS 类真实探测落点）</span>
              </template>
              <a-input
                v-model="form.target"
                placeholder="如 gw.example.com:443，留空则按基线模拟"
                allow-clear
              />
            </a-form-item>
          </a-col>

          <a-col :xs="24" :md="6">
            <a-form-item>
              <template #label>
                执行模式
                <a-tooltip
                  content="真实探测：对目标做 TLS 握手实测；模拟：用文件4基线期望值并诚实标注"
                >
                  <IconBulb class="label-tip" />
                </a-tooltip>
              </template>
              <a-radio-group v-model="form.mode" type="button" size="small">
                <a-radio value="probe">真实探测</a-radio>
                <a-radio value="simulate">模拟</a-radio>
              </a-radio-group>
            </a-form-item>
          </a-col>
        </a-row>

        <div class="run-actions">
          <a-button
            type="primary"
            :loading="starting"
            @click="startRun"
          >
            <template #icon><IconPlayArrow /></template>
            开始验收
          </a-button>
          <span v-if="form.mode === 'probe' && !form.target" class="run-hint">
            未填探测目标，不可探测的用例将以「模拟」基线值诚实标注。
          </span>
        </div>
      </a-form>
    </a-card>

    <a-row :gutter="16">
      <!-- 左：当前运行 + 逐项结果 -->
      <a-col :xs="24" :lg="16">
        <!-- 总览卡 -->
        <a-card v-if="activeRun" class="block-card overview-card">
          <template #title>
            <span class="card-title-icon">
              <IconCheckCircle /> 验收总览
              <a-tag size="small" bordered class="run-meta-tag">
                {{ activeRun.trackName || trackLabel(activeRun.track) }}
              </a-tag>
              <a-tag
                :color="acceptanceRunStatusMeta(activeRun.status).color"
                size="small"
              >
                <template v-if="running" #icon><icon-loading /></template>
                {{ acceptanceRunStatusMeta(activeRun.status).label }}
              </a-tag>
              <a-tag v-if="activeRun.mode === 'simulate'" color="gray" size="small">
                模拟
              </a-tag>
            </span>
          </template>
          <template #extra>
            <a-button
              type="primary"
              size="small"
              :disabled="activeRun.status !== 'done'"
              :loading="generatingReport"
              @click="openReport"
            >
              <template #icon><IconFile /></template>
              验收报告
            </a-button>
          </template>

          <div class="ov-grid">
            <div
              v-for="c in overviewCards"
              :key="c.key"
              class="ov-cell"
              :style="{ borderTopColor: c.color }"
            >
              <div class="ov-count" :style="{ color: c.color }">{{ c.value }}</div>
              <div class="ov-label">{{ c.label }}</div>
            </div>
          </div>

          <div class="ov-foot">
            <div class="ov-gate">
              <span class="ov-gate-label">Gate 判定</span>
              <a-tag
                :color="activeRun.gatePass ? 'green' : 'red'"
                size="medium"
                bordered
              >
                {{ activeRun.gatePass ? '通过' : '未通过' }}
              </a-tag>
              <span class="ov-gate-hint">基线口径 44/47</span>
            </div>
            <div class="ov-p1">
              <span class="ov-gate-label">P1 资产覆盖</span>
              <a-tag :color="p1Full ? 'green' : 'orange'" size="medium" bordered>
                {{ p1Coverage }}
              </a-tag>
            </div>
          </div>

          <a-progress
            v-if="running"
            :percent="(activeRun.progress ?? 0) / 100"
            :stroke-width="8"
            color="#165DFF"
            class="ov-progress"
          />
        </a-card>

        <!-- 逐项结果表 -->
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconCheckCircle /> 逐项用例</span>
          </template>
          <template #extra>
            <a-button
              v-if="activeRun"
              size="mini"
              type="text"
              :loading="loadingDetail"
              @click="refreshDetail(activeRun.id)"
            >
              <template #icon><IconRefresh /></template>
            </a-button>
          </template>
          <a-table
            :data="results"
            :columns="resultColumns"
            :loading="loadingDetail"
            :pagination="{ pageSize: 15, showTotal: true, hideOnSinglePage: true }"
            row-key="id"
            :scroll="{ x: 980 }"
          >
            <template #code="{ record }">
              <span class="mono">{{ record.code }}</span>
            </template>
            <template #category="{ record }">
              <a-tag :color="caseCategoryColor(record.category)" size="small" bordered>
                {{ caseCategoryLabel(record.category) }}
              </a-tag>
            </template>
            <template #name="{ record }">{{ record.name }}</template>
            <template #expect="{ record }">
              <span class="dim-text">{{ record.expect || '—' }}</span>
            </template>
            <template #actual="{ record }">
              <div class="actual-cell">
                <span>{{ record.actual || '—' }}</span>
                <a-tag
                  v-if="record.evidenced === 'simulated'"
                  color="gray"
                  size="small"
                  class="sim-tag"
                >
                  模拟
                </a-tag>
                <a-tag
                  v-else-if="record.measuredMs"
                  color="purple"
                  size="small"
                  class="sim-tag"
                >
                  {{ record.measuredMs }}ms
                </a-tag>
              </div>
            </template>
            <template #verdict="{ record }">
              <a-tag :color="verdictMeta(record.verdict).color" size="small">
                {{ verdictMeta(record.verdict).label }}
              </a-tag>
            </template>
            <template #risk="{ record }">
              <a-tag
                v-if="record.riskRef"
                color="orange"
                size="small"
                bordered
              >
                {{ record.riskRef }}
              </a-tag>
              <span v-else class="dim-text">—</span>
            </template>
            <template #empty>
              <a-empty
                description="尚未发起验收。上方选轨道或已完成工单，点「开始验收」"
              >
                <a-button size="small" type="outline" @click="startRun">
                  <template #icon><IconPlayArrow /></template>
                  开始验收
                </a-button>
              </a-empty>
            </template>
          </a-table>
        </a-card>
      </a-col>

      <!-- 右：历史运行 + 遗留风险台账 -->
      <a-col :xs="24" :lg="8">
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconCheckCircle /> 历史运行</span>
          </template>
          <template #extra>
            <a-button size="mini" type="text" :loading="loadingRuns" @click="loadRuns">
              <template #icon><IconRefresh /></template>
            </a-button>
          </template>
          <div v-if="!runs.length" class="empty-inline">
            <a-empty description="暂无验收运行" :image-size="40" />
          </div>
          <div v-else class="run-list">
            <div
              v-for="r in runs"
              :key="r.id"
              class="run-item"
              :class="{ 'run-item--active': activeRun?.id === r.id }"
              @click="openRun(r)"
            >
              <div class="run-item-head">
                <span class="run-item-title">
                  {{ r.assetName || r.trackName || trackLabel(r.track) }}
                </span>
                <a-tag
                  :color="acceptanceRunStatusMeta(r.status).color"
                  size="small"
                >
                  {{ acceptanceRunStatusMeta(r.status).label }}
                </a-tag>
              </div>
              <div class="run-item-meta">
                <a-tag size="small" bordered>{{ r.trackName || trackLabel(r.track) }}</a-tag>
                <span class="run-counts">
                  <span class="c-pass">{{ r.passed }}</span> /
                  <span class="c-cond">{{ r.conditional }}</span> /
                  <span class="c-fail">{{ r.failed }}</span>
                </span>
                <a-tag :color="r.gatePass ? 'green' : 'red'" size="small">
                  Gate {{ r.gatePass ? '✓' : '✗' }}
                </a-tag>
              </div>
              <div class="run-item-time">{{ fmtDate(r.createdAt) }}</div>
            </div>
          </div>
        </a-card>

        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconBulb /> 遗留风险登记</span>
          </template>
          <div v-if="!risks.length" class="empty-inline">
            <a-empty description="暂无遗留风险" :image-size="40" />
          </div>
          <div v-else class="risk-list">
            <div v-for="rk in risks" :key="rk.id" class="risk-item">
              <div class="risk-head">
                <span class="risk-code">{{ rk.code }}</span>
                <a-tag
                  :color="rk.level === '高' ? 'red' : rk.level === '中' ? 'orange' : 'gray'"
                  size="small"
                >
                  {{ rk.level }}
                </a-tag>
              </div>
              <div class="risk-desc">{{ rk.description }}</div>
              <div v-if="rk.disposition" class="risk-disp">{{ rk.disposition }}</div>
            </div>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 验收报告抽屉 -->
    <a-drawer
      v-model:visible="reportOpen"
      :width="720"
      :footer="false"
      :title="report?.title || '验收报告'"
    >
      <a-spin :loading="generatingReport" style="width: 100%">
        <template v-if="report">
          <!-- 签署区 -->
          <div class="sign-block">
            <a-steps :current="signStep" size="small" class="sign-steps">
              <a-step
                title="草稿"
                description="DRAFT"
              />
              <a-step
                title="送审"
                :status="signRejected ? 'error' : undefined"
                description="UNDER_REVIEW"
              />
              <a-step title="批准" description="APPROVE" />
              <a-step title="签署" description="SIGNED" />
            </a-steps>

            <div class="sign-meta">
              <a-tag :color="signStateMeta(report.signState).color" size="medium">
                {{ signStateMeta(report.signState).label }}
              </a-tag>
              <a-tag :color="report.gatePass ? 'green' : 'red'" size="medium" bordered>
                Gate {{ report.gatePass ? '通过' : '未通过' }}
              </a-tag>
              <span v-if="report.signer" class="sign-signer">
                签署人 {{ report.signer }} · {{ fmtDate(report.signedAt) }}
              </span>
            </div>

            <div class="sign-actions">
              <a-button
                v-if="report.signState === 'DRAFT' || report.signState === 'REJECTED'"
                type="primary"
                size="small"
                :loading="signing"
                @click="doSign('submit')"
              >
                <template #icon><IconSend /></template>
                提交送审
              </a-button>
              <template v-if="report.signState === 'UNDER_REVIEW'">
                <a-button
                  type="primary"
                  size="small"
                  :loading="signing"
                  @click="doSign('approve')"
                >
                  <template #icon><IconCheckCircle /></template>
                  批准
                </a-button>
                <a-button
                  type="primary"
                  size="small"
                  status="success"
                  :disabled="!report.gatePass"
                  :loading="signing"
                  @click="doSign('sign')"
                >
                  <template #icon><IconStamp /></template>
                  签署
                </a-button>
                <a-button
                  type="outline"
                  status="danger"
                  size="small"
                  :loading="signing"
                  @click="doSign('reject')"
                >
                  <template #icon><IconUndo /></template>
                  退回
                </a-button>
              </template>
              <a-tag
                v-if="report.signState === 'SIGNED'"
                color="green"
                size="medium"
              >
                <template #icon><IconCheckCircle /></template>
                已签署，关联资产已置「已验收」
              </a-tag>
            </div>

            <div v-if="report.hash" class="sign-hash">
              报告哈希 SHA-256：<span class="mono">{{ report.hash }}</span>
            </div>
          </div>

          <a-divider class="report-divider" />

          <!-- 报告正文（markdown 暖色排版） -->
          <!-- eslint-disable-next-line vue/no-v-html -->
          <div class="markdown-body" v-html="reportHtml" />
        </template>
        <a-empty v-else description="报告生成中…" />
      </a-spin>
    </a-drawer>
  </div>
</template>

<style scoped>
.block-card {
  margin-bottom: 16px;
}
.card-title-icon {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.run-meta-tag {
  margin-left: 4px;
}
.opt-sub {
  color: var(--brand-text-soft);
  font-size: 12px;
}
.dim-text {
  color: var(--brand-text-soft);
}
.mono {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
}

/* 运行配置 */
.run-form {
  margin-top: 4px;
}
.label-hint {
  font-size: 11px;
  color: var(--brand-text-soft);
  font-weight: 400;
  margin-left: 6px;
}
.label-tip {
  margin-left: 4px;
  color: var(--brand-accent-2);
  cursor: help;
}
.run-actions {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-top: 4px;
}
.run-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
}

/* 总览卡 */
.overview-card :deep(.arco-card-body) {
  padding-top: 16px;
}
.ov-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 16px;
}
.ov-cell {
  border-top: 3px solid;
  background: linear-gradient(160deg, #FFFFFF 0%, #f8efe6 100%);
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 14px 16px;
  text-align: center;
}
.ov-count {
  font-size: 28px;
  font-weight: 800;
  line-height: 1;
}
.ov-label {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}
.ov-foot {
  display: flex;
  align-items: center;
  gap: 28px;
  flex-wrap: wrap;
  border-top: 1px solid var(--brand-border);
  padding-top: 14px;
}
.ov-gate,
.ov-p1 {
  display: flex;
  align-items: center;
  gap: 8px;
}
.ov-gate-label {
  font-size: 13px;
  color: var(--brand-text-soft);
}
.ov-gate-hint {
  font-size: 11px;
  color: var(--brand-text-soft);
}
.ov-progress {
  margin-top: 14px;
}

/* 逐项表 actual 列 */
.actual-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.sim-tag {
  flex-shrink: 0;
}

/* 历史运行列表 */
.empty-inline {
  padding: 18px 0;
}
.run-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.run-item {
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 10px 12px;
  cursor: pointer;
  transition: all 0.18s;
  background: #FFFFFF;
}
.run-item:hover {
  border-color: var(--brand-accent-2);
}
.run-item--active {
  border-color: var(--brand-accent);
  background: #E8F3FF;
}
.run-item-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.run-item-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--brand-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.run-item-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  flex-wrap: wrap;
}
.run-counts {
  font-size: 12px;
  font-weight: 600;
}
.c-pass {
  color: #5a9367;
}
.c-cond {
  color: #FF7D00;
}
.c-fail {
  color: #cb4b3f;
}
.run-item-time {
  font-size: 11px;
  color: var(--brand-text-soft);
  margin-top: 4px;
}

/* 遗留风险台账 */
.risk-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.risk-item {
  border-left: 3px solid var(--brand-accent-2);
  background: var(--brand-bg-soft);
  border-radius: 0 8px 8px 0;
  padding: 8px 12px;
}
.risk-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.risk-code {
  font-size: 13px;
  font-weight: 700;
  color: var(--brand-text);
}
.risk-desc {
  font-size: 13px;
  color: var(--brand-text);
  margin-top: 4px;
  line-height: 1.5;
}
.risk-disp {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 3px;
}

/* 签署区 */
.sign-block {
  background: linear-gradient(135deg, #E8F3FF, #F2F3F5);
  border: 1px solid var(--brand-border);
  border-radius: 12px;
  padding: 16px 18px;
}
.sign-steps {
  margin-bottom: 14px;
}
.sign-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.sign-signer {
  font-size: 12px;
  color: var(--brand-text-soft);
}
.sign-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.sign-hash {
  font-size: 11px;
  color: var(--brand-text-soft);
  margin-top: 12px;
  word-break: break-all;
}
.report-divider {
  margin: 18px 0;
}

/* markdown 渲染暖色排版（与 Reports.vue 一致口径） */
.markdown-body {
  color: var(--brand-text);
  line-height: 1.7;
  font-size: 14px;
  max-width: 100%;
  overflow-x: auto;
}
.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3) {
  color: var(--brand-text);
  font-weight: 700;
  margin: 1.2em 0 0.6em;
}
.markdown-body :deep(h1) {
  font-size: 22px;
  border-bottom: 2px solid var(--brand-border);
  padding-bottom: 8px;
}
.markdown-body :deep(h2) {
  font-size: 18px;
}
.markdown-body :deep(h3) {
  font-size: 15px;
}
.markdown-body :deep(a) {
  color: var(--brand-accent);
}
.markdown-body :deep(code) {
  background: var(--brand-bg-soft);
  border-radius: 4px;
  padding: 2px 6px;
  font-size: 13px;
}
.markdown-body :deep(pre) {
  background: #1D2129;
  color: #F2F3F5;
  border-radius: 10px;
  padding: 14px 16px;
  overflow-x: auto;
}
.markdown-body :deep(pre code) {
  background: transparent;
  color: inherit;
  padding: 0;
}
.markdown-body :deep(table) {
  border-collapse: collapse;
  width: 100%;
  margin: 14px 0;
}
.markdown-body :deep(th),
.markdown-body :deep(td) {
  border: 1px solid var(--brand-border);
  padding: 8px 12px;
  text-align: left;
}
.markdown-body :deep(th) {
  background: var(--brand-bg-soft);
  font-weight: 600;
}
.markdown-body :deep(blockquote) {
  border-left: 4px solid var(--brand-accent-2);
  margin: 12px 0;
  padding: 4px 16px;
  color: var(--brand-text-soft);
  background: var(--brand-bg-soft);
  border-radius: 0 8px 8px 0;
}
.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  padding-left: 22px;
}
</style>
