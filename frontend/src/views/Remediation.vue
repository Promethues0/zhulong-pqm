<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Message, Modal, type TableData } from '@arco-design/web-vue'
import {
  IconPlus,
  IconRefresh,
  IconPlayArrow,
  IconUndo,
  IconLink,
  IconExperiment,
  IconCheckCircle,
} from '@arco-design/web-vue/es/icon'
import { assetApi, deviceApi, playbookApi, remediationApi } from '@/api'
import type {
  CryptoAsset,
  Device,
  DeviceInput,
  DeviceType,
  Playbook,
  RemediationInput,
  RemediationTask,
} from '@/api/types'
import {
  deviceStatusMeta,
  deviceTypeColor,
  deviceTypeLabel,
  fmtDate,
  guessTrack,
  remediationStatusMeta,
} from '@/utils/format'
import RemediationSteps from '@/components/RemediationSteps.vue'
import PlaybookCard from '@/components/PlaybookCard.vue'

const route = useRoute()
const router = useRouter()

const activeTab = ref<'tasks' | 'devices' | 'playbooks'>('tasks')

// ---------- 共享数据 ----------
const tasks = ref<RemediationTask[]>([])
const devices = ref<Device[]>([])
const playbooks = ref<Playbook[]>([])
const assets = ref<CryptoAsset[]>([])
const summary = reactive({ planned: 0, running: 0, done: 0, total: 0 })

const loadingTasks = ref(false)
const loadingDevices = ref(false)
const loadingPlaybooks = ref(false)

const summaryCards = computed(() => [
  { key: 'planned', label: '待执行', value: summary.planned, color: '#FF7D00' },
  { key: 'running', label: '执行中', value: summary.running, color: '#165DFF' },
  { key: 'done', label: '已完成', value: summary.done, color: '#5a9367' },
  { key: 'total', label: '工单总数', value: summary.total, color: '#1D2129' },
])

// ================= ① 改造工单 =================
const taskColumns = [
  { title: '资产名', slotName: 'asset', minWidth: 160, ellipsis: true, tooltip: true },
  { title: '轨道', slotName: 'track', width: 150 },
  { title: '目标算法', slotName: 'algo', width: 150 },
  { title: '设备', slotName: 'device', width: 150 },
  { title: '状态', slotName: 'status', width: 110 },
  { title: '进度', slotName: 'progress', width: 160 },
]

async function loadTasks() {
  loadingTasks.value = true
  try {
    tasks.value = await remediationApi.list()
  } catch {
    Message.error('加载改造工单失败，请确认后端 :8099 已启动')
  } finally {
    loadingTasks.value = false
  }
}

async function loadSummary() {
  try {
    const s = await remediationApi.summary()
    summary.planned = s.planned
    summary.running = s.running
    summary.done = s.done
    summary.total = s.total
  } catch {
    /* 忽略 */
  }
}

// ---------- 工单详情抽屉 ----------
const drawerOpen = ref(false)
const detailLoading = ref(false)
const activeTask = ref<RemediationTask | null>(null)
const executing = ref(false)
const rollingBack = ref(false)

const evidenceRows = computed(() =>
  Object.entries(activeTask.value?.evidence ?? {}).map(([k, v]) => ({
    key: k,
    value: v,
  })),
)

let pollTimer: number | undefined
function stopPoll() {
  if (pollTimer) {
    window.clearTimeout(pollTimer)
    pollTimer = undefined
  }
}

async function openTask(record: TableData) {
  const t = record as RemediationTask
  drawerOpen.value = true
  detailLoading.value = true
  activeTask.value = t
  try {
    activeTask.value = await remediationApi.get(t.id)
  } catch {
    /* 退化为行数据 */
  } finally {
    detailLoading.value = false
  }
}

// 对单个工单轮询 ~2s，直到 done/failed/rolledback，期间刷新抽屉步骤与列表行。
function pollTask(id: number) {
  stopPoll()
  pollTimer = window.setTimeout(async () => {
    try {
      const t = await remediationApi.get(id)
      if (activeTask.value?.id === id) activeTask.value = t
      const idx = tasks.value.findIndex((x) => x.id === id)
      if (idx >= 0) tasks.value[idx] = t
      if (t.status === 'running') {
        pollTask(id)
      } else {
        await loadSummary()
        if (t.status === 'done') Message.success('改造执行完成')
        else if (t.status === 'failed') Message.error(`改造失败：${t.error || '执行异常'}`)
      }
    } catch {
      /* 静默轮询失败 */
    }
  }, 2000)
}

async function executeTask() {
  if (!activeTask.value) return
  executing.value = true
  try {
    const t = await remediationApi.execute(activeTask.value.id)
    activeTask.value = t
    const idx = tasks.value.findIndex((x) => x.id === t.id)
    if (idx >= 0) tasks.value[idx] = t
    Message.info('改造已下发，正在编排外部设备…')
    if (t.status === 'running') pollTask(t.id)
    else await loadSummary()
  } catch {
    Message.error('下发改造失败')
  } finally {
    executing.value = false
  }
}

function rollbackTask() {
  if (!activeTask.value) return
  Modal.warning({
    title: '回滚改造',
    content: `确认将「${activeTask.value.assetName}」回滚至改造前状态？该操作会撤销已下发的 PQC 改造。`,
    okText: '回滚',
    cancelText: '取消',
    hideCancel: false,
    onOk: async () => {
      if (!activeTask.value) return
      rollingBack.value = true
      try {
        const t = await remediationApi.rollback(activeTask.value.id)
        activeTask.value = t
        const idx = tasks.value.findIndex((x) => x.id === t.id)
        if (idx >= 0) tasks.value[idx] = t
        Message.success('已回滚至改造前状态')
        await loadSummary()
      } catch {
        Message.error('回滚失败')
      } finally {
        rollingBack.value = false
      }
    },
  })
}

// 一键验收：对 done 工单发起验收运行，跳转到「验收自动化」页带 query 自动发起。
const verifying = ref(false)
async function verifyTask() {
  if (!activeTask.value) return
  const taskId = activeTask.value.id
  verifying.value = true
  try {
    const run = await remediationApi.verify(taskId)
    Message.success('已发起验收，正在跳转到验收自动化…')
    router.push({ path: '/acceptance', query: { runId: run.id, remediationId: taskId } })
  } catch {
    // 后端接缝未就绪时退化：仅带工单号跳转，由验收页自行发起。
    Message.info('跳转到验收自动化…')
    router.push({ path: '/acceptance', query: { remediationId: taskId } })
  } finally {
    verifying.value = false
  }
}

// ---------- 新建改造 modal ----------
const createOpen = ref(false)
const creating = ref(false)
const form = reactive({
  assetMode: 'select' as 'select' | 'manual',
  assetId: undefined as number | undefined,
  assetName: '',
  track: '',
  targetAlgo: '',
  deviceId: undefined as number | undefined,
})

const selectedPlaybook = computed(() =>
  playbooks.value.find((p) => p.key === form.track),
)

// 设备按所选轨道的 deviceType 过滤。
const deviceOptions = computed(() => {
  const t = selectedPlaybook.value?.deviceType
  if (!t) return devices.value
  return devices.value.filter((d) => d.type === t)
})

function onTrackChange(key: unknown) {
  const pb = playbooks.value.find((p) => p.key === key)
  if (pb) {
    if (!form.targetAlgo) form.targetAlgo = pb.targetAlgo
    // 轨道变化后清掉与新 deviceType 不匹配的设备选择。
    if (form.deviceId != null) {
      const dev = devices.value.find((d) => d.id === form.deviceId)
      if (dev && dev.type !== pb.deviceType) form.deviceId = undefined
    }
  }
}

function openCreate(prefill?: { assetId?: number; assetName?: string; algo?: string }) {
  form.assetMode = prefill?.assetName ? 'manual' : 'select'
  form.assetId = prefill?.assetId
  form.assetName = prefill?.assetName ?? ''
  form.targetAlgo = prefill?.algo ?? ''
  form.track = prefill?.algo ? guessTrack(prefill.algo) : ''
  form.deviceId = undefined
  // 预填轨道后，若目标算法仍空，则用轨道默认值补齐。
  if (form.track && !form.targetAlgo) {
    const pb = playbooks.value.find((p) => p.key === form.track)
    if (pb) form.targetAlgo = pb.targetAlgo
  }
  createOpen.value = true
}

async function submitCreate() {
  if (!form.track) {
    Message.warning('请选择改造轨道')
    return
  }
  const deviceId = form.deviceId
  if (deviceId == null) {
    Message.warning('请选择执行设备')
    return
  }
  if (form.assetMode === 'select' && form.assetId == null && !form.assetName) {
    Message.warning('请选择或填写资产')
    return
  }
  if (form.assetMode === 'manual' && !form.assetName.trim()) {
    Message.warning('请填写资产名称')
    return
  }
  const payload: RemediationInput = {
    track: form.track,
    deviceId,
    targetAlgo: form.targetAlgo || undefined,
  }
  if (form.assetMode === 'select' && form.assetId != null) {
    payload.assetId = form.assetId
    const a = assets.value.find((x) => x.id === form.assetId)
    if (a) payload.assetName = a.name
  } else {
    payload.assetName = form.assetName.trim()
  }
  creating.value = true
  try {
    const t = await remediationApi.create(payload)
    Message.success('改造工单已创建')
    createOpen.value = false
    await Promise.all([loadTasks(), loadSummary()])
    openTask(t as unknown as TableData)
  } catch {
    Message.error('创建改造工单失败')
  } finally {
    creating.value = false
  }
}

// ================= ② 设备纳管 =================
const DEVICE_TYPES: { value: DeviceType; label: string }[] = [
  { value: 'gateway', label: '网关' },
  { value: 'hsm', label: '加密机' },
  { value: 'ca', label: 'CA' },
  { value: 'proxy', label: '反代' },
]

const testingId = ref<number | null>(null)

async function loadDevices() {
  loadingDevices.value = true
  try {
    devices.value = await deviceApi.list()
  } catch {
    Message.error('加载设备失败')
  } finally {
    loadingDevices.value = false
  }
}

async function testDevice(d: Device) {
  testingId.value = d.id
  try {
    const r = await deviceApi.test(d.id)
    d.status = r.status
    d.latencyMs = r.latencyMs
    const meta = deviceStatusMeta(r.status)
    if (r.status === 'online') {
      Message.success(`${d.name} ${meta.label} · ${r.latencyMs}ms${r.detail ? ' · ' + r.detail : ''}`)
    } else {
      Message.warning(`${d.name} ${meta.label}${r.detail ? ' · ' + r.detail : ''}`)
    }
  } catch {
    Message.error('连通性测试失败')
  } finally {
    testingId.value = null
  }
}

// ---------- 新增设备 modal ----------
const deviceModalOpen = ref(false)
const savingDevice = ref(false)
const deviceForm = reactive<DeviceInput>({
  name: '',
  type: 'gateway',
  vendor: '',
  endpoint: '',
  token: '',
  capabilities: [],
})
// 能力候选（多选 + 允许自定义）。
const CAP_OPTIONS = [
  'ML-KEM',
  'ML-DSA',
  'SLH-DSA',
  'TLS1.3-hybrid',
  'IKEv2-PQ',
  'SM2',
  'SM4',
  'PKCS#11',
]

function openDeviceModal() {
  deviceForm.name = ''
  deviceForm.type = 'gateway'
  deviceForm.vendor = ''
  deviceForm.endpoint = ''
  deviceForm.token = ''
  deviceForm.capabilities = []
  deviceModalOpen.value = true
}

async function submitDevice() {
  if (!deviceForm.name.trim()) {
    Message.warning('请填写设备名称')
    return
  }
  if (!deviceForm.endpoint.trim()) {
    Message.warning('请填写 endpoint')
    return
  }
  savingDevice.value = true
  try {
    await deviceApi.create({
      name: deviceForm.name.trim(),
      type: deviceForm.type,
      vendor: deviceForm.vendor.trim(),
      endpoint: deviceForm.endpoint.trim(),
      token: deviceForm.token?.trim() || undefined,
      capabilities: deviceForm.capabilities,
    })
    Message.success('设备已纳管')
    deviceModalOpen.value = false
    await loadDevices()
  } catch {
    Message.error('新增设备失败')
  } finally {
    savingDevice.value = false
  }
}

// ================= ③ 剧本库 =================
async function loadPlaybooks() {
  loadingPlaybooks.value = true
  try {
    playbooks.value = await playbookApi.list()
  } catch {
    Message.error('加载剧本库失败')
  } finally {
    loadingPlaybooks.value = false
  }
}

// ================= 初始化 + 闭环联动 =================
onMounted(async () => {
  await Promise.all([
    loadTasks(),
    loadSummary(),
    loadDevices(),
    loadPlaybooks(),
    assetApi
      .list()
      .then((a) => (assets.value = a))
      .catch(() => {}),
  ])
  // 来自 Assets 详情抽屉「发起改造」的 query：自动打开新建 modal 预填。
  const q = route.query
  if (q.assetName || q.assetId) {
    const assetId = q.assetId ? Number(q.assetId) : undefined
    openCreate({
      assetId: Number.isNaN(assetId as number) ? undefined : assetId,
      assetName: (q.assetName as string) || '',
      algo: (q.algo as string) || '',
    })
  }
})

onBeforeUnmount(stopPoll)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1 class="page-title">改造编排</h1>
      <p class="page-subtitle">
        改造主线 = 编排外部设备（网关 / 加密机 / CA / 反代）—— 按「轨道 → 步骤 → 执行体 → 交付 → 验收」
        下发后量子混合迁移，全程留痕、可模拟、可回滚。
      </p>
    </div>

    <a-tabs v-model:active-key="activeTab" type="rounded" class="rem-tabs">
      <!-- ① 改造工单 -->
      <a-tab-pane key="tasks" title="改造工单">
        <div class="sum-grid">
          <div
            v-for="c in summaryCards"
            :key="c.key"
            class="sum-cell"
            :style="{ borderLeftColor: c.color }"
          >
            <div class="sum-count" :style="{ color: c.color }">{{ c.value }}</div>
            <div class="sum-label">{{ c.label }}</div>
          </div>
        </div>

        <a-card class="block-card">
          <template #title>改造工单</template>
          <template #extra>
            <a-space>
              <a-button size="small" :loading="loadingTasks" @click="loadTasks">
                <template #icon><IconRefresh /></template>
                刷新
              </a-button>
              <a-button type="primary" size="small" @click="openCreate()">
                <template #icon><IconPlus /></template>
                新建改造
              </a-button>
            </a-space>
          </template>
          <a-table
            :data="tasks"
            :columns="taskColumns"
            :loading="loadingTasks"
            :pagination="{ pageSize: 10, showTotal: true, hideOnSinglePage: true }"
            row-key="id"
            :scroll="{ x: 880 }"
            @row-click="openTask"
          >
            <template #asset="{ record }">
              <a-link @click.stop="openTask(record)">{{ record.assetName }}</a-link>
            </template>
            <template #track="{ record }">
              <a-tag size="small" bordered>{{ record.trackName }}</a-tag>
            </template>
            <template #algo="{ record }">
              <a-tag v-if="record.targetAlgo" color="orange" size="small">
                {{ record.targetAlgo }}
              </a-tag>
              <span v-else class="dim">—</span>
            </template>
            <template #device="{ record }">
              <span class="dev-cell">
                <a-tag :color="deviceTypeColor(record.deviceType)" size="small" bordered>
                  {{ deviceTypeLabel(record.deviceType) }}
                </a-tag>
                <span class="dev-name">{{ record.deviceName }}</span>
              </span>
            </template>
            <template #status="{ record }">
              <a-tag :color="remediationStatusMeta(record.status).color" size="small">
                {{ remediationStatusMeta(record.status).label }}
              </a-tag>
            </template>
            <template #progress="{ record }">
              <a-progress
                :percent="(record.progress ?? 0) / 100"
                :stroke-width="8"
                color="#165DFF"
                size="small"
              />
            </template>
            <template #empty>
              <a-empty description="暂无改造工单，点「新建改造」编排外部设备">
                <a-button size="small" type="outline" @click="openCreate()">
                  <template #icon><IconPlus /></template>
                  新建改造
                </a-button>
              </a-empty>
            </template>
          </a-table>
        </a-card>
      </a-tab-pane>

      <!-- ② 设备纳管 -->
      <a-tab-pane key="devices" title="设备纳管">
        <a-card class="block-card">
          <template #title>
            执行设备 <span class="muted">（{{ devices.length }} 台）</span>
          </template>
          <template #extra>
            <a-space>
              <a-button size="small" :loading="loadingDevices" @click="loadDevices">
                <template #icon><IconRefresh /></template>
                刷新
              </a-button>
              <a-button type="primary" size="small" @click="openDeviceModal">
                <template #icon><IconPlus /></template>
                新增设备
              </a-button>
            </a-space>
          </template>

          <a-row :gutter="16">
            <a-col
              v-for="d in devices"
              :key="d.id"
              :xs="24"
              :sm="12"
              :lg="8"
              style="margin-bottom: 16px"
            >
              <a-card class="dev-card" :bordered="true">
                <div class="dev-head">
                  <span class="dev-title">{{ d.name }}</span>
                  <a-tag :color="deviceStatusMeta(d.status).color" size="small">
                    {{ deviceStatusMeta(d.status).label }}
                  </a-tag>
                </div>
                <div class="dev-row">
                  <a-tag :color="deviceTypeColor(d.type)" size="small" bordered>
                    {{ deviceTypeLabel(d.type) }}
                  </a-tag>
                  <span class="dev-vendor">{{ d.vendor || '—' }}</span>
                </div>
                <div class="dev-endpoint">
                  <IconLink class="dev-ep-icon" />{{ d.endpoint || '—' }}
                </div>
                <div class="dev-caps">
                  <a-tag
                    v-for="cap in d.capabilities"
                    :key="cap"
                    size="small"
                    color="arcoblue"
                    class="cap-tag"
                  >
                    {{ cap }}
                  </a-tag>
                  <span v-if="!d.capabilities?.length" class="dim">无能力标注</span>
                </div>
                <div class="dev-foot">
                  <span class="dev-latency">
                    <template v-if="d.status === 'online' && d.latencyMs">
                      时延 {{ d.latencyMs }}ms
                    </template>
                    <template v-else>上次检测 {{ fmtDate(d.lastCheckAt) }}</template>
                  </span>
                  <a-button
                    size="mini"
                    type="outline"
                    :loading="testingId === d.id"
                    @click="testDevice(d)"
                  >
                    <template #icon><IconExperiment /></template>
                    连通性测试
                  </a-button>
                </div>
              </a-card>
            </a-col>
          </a-row>
          <a-empty
            v-if="!devices.length && !loadingDevices"
            description="暂无纳管设备，点「新增设备」接入网关/加密机/CA/反代"
          />
        </a-card>
      </a-tab-pane>

      <!-- ③ 剧本库 -->
      <a-tab-pane key="playbooks" title="剧本库">
        <a-alert type="normal" class="pb-intro">
          剧本库即「轨道 → 步骤 → 执行体 → 交付 → 验收」对照表 —— 每条轨道把一类资产的 PQC 改造固化为可复用的标准作业流程。
        </a-alert>
        <a-spin :loading="loadingPlaybooks" style="width: 100%">
          <a-row :gutter="16">
            <a-col
              v-for="p in playbooks"
              :key="p.key"
              :xs="24"
              :sm="12"
              :lg="8"
              style="margin-bottom: 16px"
            >
              <PlaybookCard :playbook="p" />
            </a-col>
          </a-row>
          <a-empty v-if="!playbooks.length && !loadingPlaybooks" description="暂无剧本" />
        </a-spin>
      </a-tab-pane>
    </a-tabs>

    <!-- 工单详情抽屉 -->
    <a-drawer
      v-model:visible="drawerOpen"
      :width="640"
      :footer="false"
      :title="activeTask ? `改造工单 · ${activeTask.assetName}` : '改造工单'"
      @close="stopPoll"
    >
      <a-spin :loading="detailLoading" style="width: 100%">
        <template v-if="activeTask">
          <div class="task-banner">
            <div>
              <div class="task-track">{{ activeTask.trackName }}</div>
              <div class="task-target">
                目标算法
                <a-tag v-if="activeTask.targetAlgo" color="orange" size="small">
                  {{ activeTask.targetAlgo }}
                </a-tag>
                <span v-else>—</span>
              </div>
            </div>
            <a-tag
              :color="remediationStatusMeta(activeTask.status).color"
              size="large"
            >
              {{ remediationStatusMeta(activeTask.status).label }}
            </a-tag>
          </div>

          <a-descriptions :column="2" size="medium" bordered class="task-desc">
            <a-descriptions-item label="执行设备">
              <a-tag :color="deviceTypeColor(activeTask.deviceType)" size="small" bordered>
                {{ deviceTypeLabel(activeTask.deviceType) }}
              </a-tag>
              {{ activeTask.deviceName }}
            </a-descriptions-item>
            <a-descriptions-item label="进度">{{ activeTask.progress }}%</a-descriptions-item>
            <a-descriptions-item label="创建时间">{{ fmtDate(activeTask.createdAt) }}</a-descriptions-item>
            <a-descriptions-item label="完成时间">{{ fmtDate(activeTask.finishedAt) }}</a-descriptions-item>
            <a-descriptions-item v-if="activeTask.error" label="错误" :span="2">
              <span style="color: rgb(var(--red-6))">{{ activeTask.error }}</span>
            </a-descriptions-item>
          </a-descriptions>

          <div class="task-actions">
            <a-button
              v-if="activeTask.status === 'planned'"
              type="primary"
              :loading="executing"
              @click="executeTask"
            >
              <template #icon><IconPlayArrow /></template>
              执行改造
            </a-button>
            <template v-else-if="activeTask.status === 'done'">
              <a-button type="primary" :loading="verifying" @click="verifyTask">
                <template #icon><IconCheckCircle /></template>
                一键验收
              </a-button>
              <a-button
                type="outline"
                status="warning"
                :loading="rollingBack"
                @click="rollbackTask"
              >
                <template #icon><IconUndo /></template>
                回滚
              </a-button>
            </template>
            <a-tag v-else-if="activeTask.status === 'running'" color="orange">
              <template #icon><icon-loading /></template>
              编排执行中，自动刷新…
            </a-tag>
          </div>

          <div class="section-title">改造步骤时间线</div>
          <RemediationSteps :steps="activeTask.steps ?? []" />

          <div class="section-title">改造证据 Evidence</div>
          <a-descriptions
            v-if="evidenceRows.length"
            :column="1"
            size="medium"
            bordered
            class="ev-desc"
          >
            <a-descriptions-item
              v-for="row in evidenceRows"
              :key="row.key"
              :label="row.key"
            >
              {{ row.value }}
            </a-descriptions-item>
          </a-descriptions>
          <a-empty v-else description="暂无证据，执行后留痕" :image-size="40" />

          <div class="deliver-block">
            <div class="deliver-row">
              <span class="deliver-key">交付物</span>
              <span class="deliver-val">{{ activeTask.deliverable || '—' }}</span>
            </div>
            <div class="deliver-row">
              <span class="deliver-key">验收口径</span>
              <span class="deliver-val">{{ activeTask.acceptance || '—' }}</span>
            </div>
          </div>
        </template>
      </a-spin>
    </a-drawer>

    <!-- 新建改造 modal -->
    <a-modal
      v-model:visible="createOpen"
      title="新建改造工单"
      :width="620"
      :ok-loading="creating"
      ok-text="提交"
      cancel-text="取消"
      @ok="submitCreate"
    >
      <a-form :model="form" layout="vertical">
        <a-form-item label="资产">
          <a-radio-group v-model="form.assetMode" type="button" size="small">
            <a-radio value="select">从清单选择</a-radio>
            <a-radio value="manual">手填资产名</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.assetMode === 'select'" label="选择资产">
          <a-select
            v-model="form.assetId"
            placeholder="选择一个密码使用点"
            allow-search
            allow-clear
          >
            <a-option v-for="a in assets" :key="a.id" :value="a.id" :label="a.name">
              {{ a.name }}
              <span class="opt-sub">· {{ a.system || '未分类' }} · {{ a.algorithm || '—' }}</span>
            </a-option>
          </a-select>
        </a-form-item>
        <a-form-item v-else label="资产名称">
          <a-input v-model="form.assetName" placeholder="如：核心交易网关 TLS 入口" allow-clear />
        </a-form-item>

        <a-form-item label="改造轨道">
          <a-select
            v-model="form.track"
            placeholder="选择一条改造轨道（剧本）"
            @change="onTrackChange"
          >
            <a-option v-for="p in playbooks" :key="p.key" :value="p.key" :label="p.name">
              {{ p.name }}
              <span class="opt-sub">· {{ deviceTypeLabel(p.deviceType) }}</span>
            </a-option>
          </a-select>
        </a-form-item>

        <div v-if="selectedPlaybook" class="pb-preview">
          <div class="pb-preview-title">
            <a-tag :color="deviceTypeColor(selectedPlaybook.deviceType)" size="small">
              {{ deviceTypeLabel(selectedPlaybook.deviceType) }}
            </a-tag>
            轨道预览
          </div>
          <div class="pb-preview-row"><b>步骤：</b></div>
          <ol class="pb-preview-steps">
            <li v-for="(s, i) in selectedPlaybook.steps" :key="i">{{ s }}</li>
          </ol>
          <div class="pb-preview-row"><b>交付物：</b>{{ selectedPlaybook.deliverable || '—' }}</div>
          <div class="pb-preview-row"><b>验收口径：</b>{{ selectedPlaybook.acceptance || '—' }}</div>
        </div>

        <a-form-item label="执行设备">
          <a-select v-model="form.deviceId" placeholder="选择执行该轨道的设备">
            <a-option v-for="d in deviceOptions" :key="d.id" :value="d.id" :label="d.name">
              {{ d.name }}
              <span class="opt-sub">· {{ deviceTypeLabel(d.type) }} · {{ d.vendor || '—' }}</span>
            </a-option>
            <template #empty>
              <a-empty
                description="该轨道暂无匹配设备，先去「设备纳管」接入"
                :image-size="40"
              />
            </template>
          </a-select>
          <div v-if="selectedPlaybook" class="field-hint">
            仅展示类型为「{{ deviceTypeLabel(selectedPlaybook.deviceType) }}」的设备。
          </div>
        </a-form-item>

        <a-form-item label="目标算法">
          <a-input
            v-model="form.targetAlgo"
            placeholder="默认取轨道目标算法"
            allow-clear
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 新增设备 modal -->
    <a-modal
      v-model:visible="deviceModalOpen"
      title="新增执行设备"
      :width="560"
      :ok-loading="savingDevice"
      ok-text="纳管"
      cancel-text="取消"
      @ok="submitDevice"
    >
      <a-form :model="deviceForm" layout="vertical">
        <a-form-item label="设备名称" required>
          <a-input v-model="deviceForm.name" placeholder="如：核心区国密网关-01" allow-clear />
        </a-form-item>
        <a-form-item label="设备类型">
          <a-select v-model="deviceForm.type">
            <a-option v-for="t in DEVICE_TYPES" :key="t.value" :value="t.value">
              {{ t.label }}
            </a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="厂商">
          <a-input v-model="deviceForm.vendor" placeholder="如：烛龙 / 安恒" allow-clear />
        </a-form-item>
        <a-form-item label="Endpoint" required>
          <a-input v-model="deviceForm.endpoint" placeholder="如：https://10.50.91.133:8443" allow-clear />
        </a-form-item>
        <a-form-item label="接入 Token">
          <a-input-password v-model="deviceForm.token" placeholder="编排调用凭据（可选）" allow-clear />
        </a-form-item>
        <a-form-item label="能力">
          <a-select
            v-model="deviceForm.capabilities"
            multiple
            allow-create
            placeholder="选择或输入设备支持的算法/能力"
          >
            <a-option v-for="cap in CAP_OPTIONS" :key="cap" :value="cap">{{ cap }}</a-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.rem-tabs {
  margin-top: 4px;
}
.block-card {
  margin-bottom: 16px;
}
.muted {
  font-size: 12px;
  color: var(--brand-text-soft);
  font-weight: 400;
}
.dim {
  color: var(--brand-text-soft);
}
.opt-sub {
  color: var(--brand-text-soft);
  font-size: 12px;
}
.field-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}

/* 摘要小卡 */
.sum-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 16px;
}
.sum-cell {
  border-left: 4px solid;
  background: linear-gradient(160deg, #FFFFFF 0%, #f8efe6 100%);
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 14px 16px;
}
.sum-count {
  font-size: 26px;
  font-weight: 800;
  line-height: 1;
}
.sum-label {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}

/* 工单表格里的设备列 */
.dev-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.dev-name {
  font-size: 13px;
  color: var(--brand-text);
}

/* 设备卡片 */
.dev-card {
  border-radius: 12px;
  height: 100%;
}
.dev-card :deep(.arco-card-body) {
  padding: 16px 18px;
}
.dev-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}
.dev-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--brand-text);
}
.dev-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}
.dev-vendor {
  font-size: 13px;
  color: var(--brand-text-soft);
}
.dev-endpoint {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-bottom: 10px;
  word-break: break-all;
}
.dev-ep-icon {
  flex-shrink: 0;
}
.dev-caps {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  min-height: 24px;
  margin-bottom: 12px;
}
.cap-tag {
  margin: 0;
}
.dev-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  border-top: 1px solid var(--brand-border);
  padding-top: 12px;
}
.dev-latency {
  font-size: 12px;
  color: var(--brand-text-soft);
}

/* 剧本库 */
.pb-intro {
  margin-bottom: 16px;
}

/* 工单抽屉 */
.task-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #E8F3FF, #f6ece0);
  border: 1px solid var(--brand-border);
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 18px;
}
.task-track {
  font-size: 18px;
  font-weight: 800;
  color: var(--brand-text);
}
.task-target {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}
.task-desc :deep(.arco-descriptions-item-label),
.ev-desc :deep(.arco-descriptions-item-label) {
  background: var(--brand-bg-soft);
}
.task-actions {
  display: flex;
  gap: 10px;
  margin: 18px 0 4px;
}
.section-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--brand-text);
  margin: 20px 0 12px;
}
.deliver-block {
  margin-top: 18px;
  border-top: 1px solid var(--brand-border);
  padding-top: 14px;
}
.deliver-row {
  display: flex;
  gap: 8px;
  font-size: 13px;
  color: var(--brand-text);
  margin-bottom: 8px;
}
.deliver-key {
  flex-shrink: 0;
  width: 72px;
  color: var(--brand-text-soft);
}
.deliver-val {
  flex: 1;
}

/* 新建改造 modal 内的轨道预览 */
.pb-preview {
  background: var(--brand-bg-soft);
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 12px 14px;
  margin-bottom: 16px;
}
.pb-preview-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--brand-text);
  margin-bottom: 8px;
}
.pb-preview-row {
  font-size: 13px;
  color: var(--brand-text);
  line-height: 1.6;
}
.pb-preview-steps {
  margin: 4px 0 8px;
  padding-left: 20px;
}
.pb-preview-steps li {
  font-size: 13px;
  color: var(--brand-text);
  line-height: 1.6;
}
</style>
