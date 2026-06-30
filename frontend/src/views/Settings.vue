<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconSave,
  IconUndo,
  IconSettings,
  IconExperiment,
} from '@arco-design/web-vue/es/icon'
import { settingApi } from '@/api'
import type { SettingItem, SettingsGrouped } from '@/api/types'
import { useAuthStore } from '@/store/auth'

/**
 * 系统设置：4 页签（扫描默认 / SLO 阈值 / 评分权重(只读) / 威胁情报源&保存期）。
 * 每项编辑后 PUT /settings/:key。SLO 阈值支持一键恢复默认。
 * viewer 进入只读（writable=false）。
 */
const router = useRouter()
const auth = useAuthStore()
const writable = computed(() => auth.hasRole('admin'))

const loading = ref(false)
const grouped = ref<SettingsGrouped>({})

// 情报源行自增稳定 key（避免空 name 重复导致 a-table row-key 撞车）。
let intelSeq = 0

// ---- 扫描默认 ----
interface ScanDefaults {
  exposure: string
  ports: number[]
  timeoutSec: number
  concurrency: number
}
const scan = reactive<ScanDefaults>({
  exposure: 'internal',
  ports: [443, 8443],
  timeoutSec: 5,
  concurrency: 16,
})
const scanKey = ref('scan.defaults')
const scanSaving = ref(false)

// ---- SLO 阈值 ----
interface SloThresholds {
  handshakeFailRate: number
  latencyDeltaMs: number
  latencyMaxMs: number
}
const SLO_DEFAULTS: SloThresholds = {
  handshakeFailRate: 0.001,
  latencyDeltaMs: 8.3,
  latencyMaxMs: 15,
}
const slo = reactive<SloThresholds>({ ...SLO_DEFAULTS })
const sloKey = ref('slo.thresholds')
const sloSaving = ref(false)

// ---- 评分权重（只读展示） ----
interface Weights {
  preset?: string
  d1: number
  d2: number
  d3: number
  d4: number
  d5: number
  p1Threshold?: number
  hndlD2?: number
  hndlD3?: number
}
const weights = ref<Weights | null>(null)

// ---- 威胁情报源 ----
interface IntelSource {
  name: string
  url: string
  kind: string
  enabled: boolean
  _rid?: number
}
const intelSources = ref<IntelSource[]>([])
const intelKey = ref('threatintel.sources')
const intelSaving = ref(false)

// ---- 数据保存期 ----
interface Retention {
  auditDays: number
  snapshotDays: number
  metricDays: number
}
const retention = reactive<Retention>({
  auditDays: 365,
  snapshotDays: 180,
  metricDays: 365,
})
const retentionKey = ref('retention.policy')
const hasRetention = ref(false)
const retentionSaving = ref(false)

const exposureOptions = [
  { value: 'internal', label: '内网' },
  { value: 'dmz', label: 'DMZ' },
  { value: 'public', label: '公网' },
]

const intelColumns = [
  { title: '名称', slotName: 'name', minWidth: 140 },
  { title: 'URL', slotName: 'url', minWidth: 200 },
  { title: '类型', slotName: 'kind', width: 160 },
  { title: '启用', slotName: 'enabled', width: 80, align: 'center' as const },
  { title: '操作', slotName: 'actions', width: 70, align: 'center' as const },
]

/** 按 key 在所有分组里命中某项（不依赖 category，容错后端分组口径差异）。 */
function pick(_c: string, key: string): SettingItem | undefined {
  for (const arr of Object.values(grouped.value)) {
    const hit = (arr || []).find((s) => s.key === key)
    if (hit) return hit
  }
  return undefined
}

function hydrate() {
  // 扫描默认
  const s = pick('scan', 'scan.defaults')
  if (s) {
    scanKey.value = s.key
    const v = (s.value ?? {}) as Partial<ScanDefaults>
    scan.exposure = v.exposure ?? 'internal'
    scan.ports = Array.isArray(v.ports) ? v.ports : [443, 8443]
    scan.timeoutSec = v.timeoutSec ?? 5
    scan.concurrency = v.concurrency ?? 16
  }
  // SLO 阈值
  const sl = pick('slo', 'slo.thresholds')
  if (sl) {
    sloKey.value = sl.key
    const v = (sl.value ?? {}) as Partial<SloThresholds>
    slo.handshakeFailRate = v.handshakeFailRate ?? SLO_DEFAULTS.handshakeFailRate
    slo.latencyDeltaMs = v.latencyDeltaMs ?? SLO_DEFAULTS.latencyDeltaMs
    slo.latencyMaxMs = v.latencyMaxMs ?? SLO_DEFAULTS.latencyMaxMs
  }
  // 权重（只读）
  const w = pick('weights', 'scoring.weights')
  weights.value = w ? ((w.value ?? null) as Weights | null) : null
  // 情报源
  const it = pick('intel', 'threatintel.sources')
  if (it) {
    intelKey.value = it.key
    const arr = Array.isArray(it.value) ? (it.value as IntelSource[]) : []
    // 回填时为每行补稳定自增 key。
    arr.forEach((s) => {
      s._rid = ++intelSeq
    })
    intelSources.value = arr
  }
  // 保存期
  const rt = pick('retention', 'retention.policy')
  if (rt) {
    hasRetention.value = true
    retentionKey.value = rt.key
    const v = (rt.value ?? {}) as Partial<Retention>
    retention.auditDays = v.auditDays ?? 365
    retention.snapshotDays = v.snapshotDays ?? 180
    retention.metricDays = v.metricDays ?? 365
  } else {
    hasRetention.value = false
  }
}

async function load() {
  loading.value = true
  try {
    grouped.value = await settingApi.get()
    hydrate()
  } catch {
    Message.error('加载系统设置失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function put(key: string, value: unknown, flag: { v: boolean }, label: string) {
  if (!writable.value) return
  flag.v = true
  try {
    // 后端返回更新后的单条设置项：更新 grouped 内对应项后再 hydrate。
    const updated = await settingApi.update(key, value)
    for (const arr of Object.values(grouped.value)) {
      const idx = (arr || []).findIndex((s) => s.key === updated.key)
      if (idx >= 0) {
        arr[idx] = updated
        break
      }
    }
    hydrate()
    Message.success(`${label}已保存`)
  } catch {
    Message.error(`保存${label}失败`)
  } finally {
    flag.v = false
  }
}

function saveScan() {
  // a-input-tag 录入值可能为字符串，归一为数字端口并去除非法项。
  const ports = (scan.ports as Array<number | string>)
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
  put(
    scanKey.value,
    {
      exposure: scan.exposure,
      ports,
      timeoutSec: scan.timeoutSec,
      concurrency: scan.concurrency,
    },
    { get v() { return scanSaving.value }, set v(x) { scanSaving.value = x } },
    '扫描默认',
  )
}

function saveSlo() {
  put(
    sloKey.value,
    {
      handshakeFailRate: slo.handshakeFailRate,
      latencyDeltaMs: slo.latencyDeltaMs,
      latencyMaxMs: slo.latencyMaxMs,
    },
    { get v() { return sloSaving.value }, set v(x) { sloSaving.value = x } },
    'SLO 阈值',
  )
}

function restoreSloDefaults() {
  slo.handshakeFailRate = SLO_DEFAULTS.handshakeFailRate
  slo.latencyDeltaMs = SLO_DEFAULTS.latencyDeltaMs
  slo.latencyMaxMs = SLO_DEFAULTS.latencyMaxMs
  Message.info('已回填 PRD 默认阈值，点击「保存」生效')
}

function addIntelSource() {
  intelSources.value.push({ name: '', url: '', kind: 'algo-deprecation', enabled: true, _rid: ++intelSeq })
}
function removeIntelSource(i: number) {
  intelSources.value.splice(i, 1)
}
function saveIntel() {
  // 过滤掉名称为空的脏行，并剥掉前端内部的 _rid 再发后端。
  const clean = intelSources.value
    .filter((s) => s.name.trim())
    .map(({ _rid, ...rest }) => rest)
  put(
    intelKey.value,
    clean,
    { get v() { return intelSaving.value }, set v(x) { intelSaving.value = x } },
    '威胁情报源',
  )
}

function saveRetention() {
  put(
    retentionKey.value,
    {
      auditDays: retention.auditDays,
      snapshotDays: retention.snapshotDays,
      metricDays: retention.metricDays,
    },
    { get v() { return retentionSaving.value }, set v(x) { retentionSaving.value = x } },
    '数据保存期',
  )
}

const weightRows = computed(() => {
  const w = weights.value
  return [
    { label: 'D1 算法脆弱性', val: w?.d1 },
    { label: 'D2 数据敏感度', val: w?.d2 },
    { label: 'D3 数据生命周期', val: w?.d3 },
    { label: 'D4 迁移复杂度', val: w?.d4 },
    { label: 'D5 暴露面', val: w?.d5 },
  ]
})

function pct(v?: number): string {
  if (v == null) return '—'
  // 兼容 0.30 与 30 两种存储口径。
  const n = v <= 1 ? v * 100 : v
  return `${Math.round(n)}%`
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header set-head">
      <div>
        <h1 class="page-title"><IconSettings /> 系统设置</h1>
        <p class="page-subtitle">
          扫描默认 / SLO 阈值 / 评分权重 / 威胁情报源与数据保存期 —— 治理底座的可配置项。
          <a-tag v-if="!writable" color="gray" size="small">只读（需 admin）</a-tag>
        </p>
      </div>
      <a-button :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
        刷新
      </a-button>
    </div>

    <a-spin :loading="loading" style="width: 100%">
      <a-card class="block-card">
        <a-tabs default-active-key="scan" type="rounded">
          <!-- 扫描默认 -->
          <a-tab-pane key="scan" title="扫描默认">
            <a-form :model="scan" layout="vertical" :disabled="!writable" class="set-form">
              <a-row :gutter="20">
                <a-col :xs="24" :md="12">
                  <a-form-item label="默认暴露面">
                    <a-select v-model="scan.exposure" style="width: 200px">
                      <a-option v-for="o in exposureOptions" :key="o.value" :value="o.value">
                        {{ o.label }}
                      </a-option>
                    </a-select>
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="12">
                  <a-form-item label="默认端口">
                    <a-input-tag
                      v-model="scan.ports"
                      placeholder="回车添加端口"
                      allow-clear
                      style="width: 280px"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="12">
                  <a-form-item label="单目标超时（秒）">
                    <a-input-number v-model="scan.timeoutSec" :min="1" :max="120" style="width: 160px" />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="12">
                  <a-form-item label="并发数">
                    <a-input-number v-model="scan.concurrency" :min="1" :max="256" style="width: 160px" />
                  </a-form-item>
                </a-col>
              </a-row>
              <a-button type="primary" :loading="scanSaving" :disabled="!writable" @click="saveScan">
                <template #icon><IconSave /></template>
                保存扫描默认
              </a-button>
            </a-form>
          </a-tab-pane>

          <!-- SLO 阈值 -->
          <a-tab-pane key="slo" title="SLO 阈值">
            <a-alert type="normal" style="margin-bottom: 16px">
              PRD 默认：握手失败率 0.1% · 延迟增量 +8.3ms · 延迟阈值 15ms。可一键恢复默认。
            </a-alert>
            <a-form :model="slo" layout="vertical" :disabled="!writable" class="set-form">
              <a-row :gutter="20">
                <a-col :xs="24" :md="8">
                  <a-form-item label="握手失败率上限">
                    <a-input-number
                      v-model="slo.handshakeFailRate"
                      :min="0"
                      :max="1"
                      :step="0.001"
                      :precision="4"
                      placeholder="0.001"
                      style="width: 160px"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="8">
                  <a-form-item label="延迟增量上限（ms）">
                    <a-input-number
                      v-model="slo.latencyDeltaMs"
                      :min="0"
                      :step="0.1"
                      :precision="1"
                      placeholder="8.3"
                      style="width: 160px"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="8">
                  <a-form-item label="延迟阈值上限（ms）">
                    <a-input-number
                      v-model="slo.latencyMaxMs"
                      :min="0"
                      :step="0.5"
                      :precision="1"
                      placeholder="15"
                      style="width: 160px"
                    />
                  </a-form-item>
                </a-col>
              </a-row>
              <a-space>
                <a-button type="primary" :loading="sloSaving" :disabled="!writable" @click="saveSlo">
                  <template #icon><IconSave /></template>
                  保存 SLO 阈值
                </a-button>
                <a-button :disabled="!writable" @click="restoreSloDefaults">
                  <template #icon><IconUndo /></template>
                  恢复默认
                </a-button>
              </a-space>
            </a-form>
          </a-tab-pane>

          <!-- 评分权重（只读） -->
          <a-tab-pane key="weights" title="评分权重">
            <a-alert type="warning" style="margin-bottom: 16px">
              <template #title>权重为只读展示</template>
              评分权重为全局生效口径，调权须在「风险登记」页的<strong>专家模式</strong>进行（建方案 → 预演 → 激活全量复算）。
            </a-alert>
            <div class="weight-readonly">
              <a-descriptions :column="1" bordered size="medium">
                <a-descriptions-item label="当前预设">
                  <a-tag color="orange">{{ weights?.preset || 'default' }}</a-tag>
                </a-descriptions-item>
                <a-descriptions-item v-for="r in weightRows" :key="r.label" :label="r.label">
                  {{ pct(r.val) }}
                </a-descriptions-item>
                <a-descriptions-item label="P1 阈值">
                  {{ weights?.p1Threshold ?? 75 }}
                </a-descriptions-item>
                <a-descriptions-item label="HNDL 判定">
                  D2 ≥ {{ weights?.hndlD2 ?? 60 }} 且 D3 ≥ {{ weights?.hndlD3 ?? 60 }}
                </a-descriptions-item>
              </a-descriptions>
              <a-button type="outline" class="expert-link" @click="router.push('/risk-register')">
                <template #icon><IconExperiment /></template>
                前往专家模式调权 →
              </a-button>
            </div>
          </a-tab-pane>

          <!-- 威胁情报源 & 保存期 -->
          <a-tab-pane key="intel" title="威胁情报源 & 保存期">
            <div class="sub-title">
              <span>威胁情报订阅源</span>
              <a-button v-if="writable" size="small" type="primary" @click="addIntelSource">
                新增源
              </a-button>
            </div>
            <a-table
              :data="intelSources"
              :columns="intelColumns"
              :pagination="false"
              row-key="name"
              :scroll="{ x: 620 }"
            >
              <template #name="{ record }">
                <a-input v-model="record.name" :disabled="!writable" placeholder="源名称" size="small" />
              </template>
              <template #url="{ record }">
                <a-input v-model="record.url" :disabled="!writable" placeholder="https://…" size="small" />
              </template>
              <template #kind="{ record }">
                <a-select v-model="record.kind" :disabled="!writable" size="small" style="width: 150px">
                  <a-option value="algo-deprecation">算法弃用</a-option>
                  <a-option value="algo-break">算法攻破</a-option>
                  <a-option value="standard-update">标准更新</a-option>
                  <a-option value="qubit-milestone">量子比特里程碑</a-option>
                </a-select>
              </template>
              <template #enabled="{ record }">
                <a-switch v-model="record.enabled" :disabled="!writable" size="small" />
              </template>
              <template #actions="{ rowIndex }">
                <a-button
                  v-if="writable"
                  size="mini"
                  type="text"
                  status="danger"
                  @click="removeIntelSource(rowIndex)"
                >
                  删除
                </a-button>
              </template>
              <template #empty>
                <a-empty description="暂无情报源，点击「新增源」添加" :image-size="40" />
              </template>
            </a-table>
            <a-button
              type="primary"
              :loading="intelSaving"
              :disabled="!writable"
              style="margin-top: 12px"
              @click="saveIntel"
            >
              <template #icon><IconSave /></template>
              保存情报源
            </a-button>

            <a-divider />

            <div class="sub-title"><span>数据保存期（天）</span></div>
            <a-form :model="retention" layout="vertical" :disabled="!writable" class="set-form">
              <a-row :gutter="20">
                <a-col :xs="24" :md="8">
                  <a-form-item label="审计日志保存期">
                    <a-input-number v-model="retention.auditDays" :min="30" :max="3650" style="width: 160px" />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="8">
                  <a-form-item label="CBOM 快照保存期">
                    <a-input-number v-model="retention.snapshotDays" :min="30" :max="3650" style="width: 160px" />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :md="8">
                  <a-form-item label="指标快照保存期">
                    <a-input-number v-model="retention.metricDays" :min="30" :max="3650" style="width: 160px" />
                  </a-form-item>
                </a-col>
              </a-row>
              <a-button type="primary" :loading="retentionSaving" :disabled="!writable" @click="saveRetention">
                <template #icon><IconSave /></template>
                保存保存期
              </a-button>
            </a-form>
          </a-tab-pane>
        </a-tabs>
      </a-card>
    </a-spin>
  </div>
</template>

<style scoped>
.set-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
}
.page-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.block-card {
  margin-bottom: 16px;
}
.set-form {
  max-width: 760px;
}
.weight-readonly {
  max-width: 560px;
}
.expert-link {
  margin-top: 16px;
}
.sub-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 14px;
  font-weight: 600;
  color: var(--brand-text);
  margin-bottom: 12px;
}
</style>
