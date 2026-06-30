<script setup lang="ts">
import { onMounted, ref, computed, type Component } from 'vue'
import { useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import {
  IconStorage,
  IconThunderbolt,
  IconClockCircle,
  IconExclamationCircleFill,
  IconBarChart,
  IconRefresh,
} from '@arco-design/web-vue/es/icon'
import { dashboardApi, scanApi, scoreApi } from '@/api'
import type { Dashboard, ScanJob, ScoreSummary } from '@/api/types'
import { fmtDate, jobStatusMeta } from '@/utils/format'
import DashboardTrend from '@/components/DashboardTrend.vue'

const router = useRouter()

const loading = ref(false)
const data = ref<Dashboard | null>(null)
const summary = ref<ScoreSummary | null>(null)
const jobs = ref<ScanJob[]>([])

const layers = [
  { key: 'L1', label: 'L1 应用/会话层' },
  { key: 'L2', label: 'L2 协议/传输层' },
  { key: 'L3', label: 'L3 数据存储层' },
  { key: 'L4', label: 'L4 硬件/根信任层' },
] as const

const layerMax = computed(() => {
  if (!data.value) return 1
  const vals = Object.values(data.value.byLayer)
  return Math.max(1, ...vals)
})

interface MetricCard {
  key: string
  label: string
  value: number
  icon: Component
  bg: string
  fg: string
  accent: boolean
}

const metricCards = computed<MetricCard[]>(() => [
  {
    key: 'total',
    label: '密码使用点总数',
    value: data.value?.totalAssets ?? 0,
    icon: IconStorage,
    bg: '#E8F3FF',
    fg: '#165DFF',
    accent: false,
  },
  {
    key: 'p1',
    label: 'P1 立即处理',
    value: data.value?.p1Count ?? 0,
    icon: IconExclamationCircleFill,
    bg: '#FFECE8',
    fg: '#cb4b3f',
    accent: true,
  },
  {
    key: 'hndl',
    label: 'HNDL 重点关注',
    value: data.value?.hndlCount ?? 0,
    icon: IconClockCircle,
    bg: '#FFF7E8',
    fg: '#FF7D00',
    accent: true,
  },
  {
    key: 'critical',
    label: '极高风险',
    value: data.value?.criticalCount ?? 0,
    icon: IconThunderbolt,
    bg: '#FFECE8',
    fg: '#cb4b3f',
    accent: true,
  },
  {
    key: 'avg',
    label: '平均风险分',
    value: data.value?.avgScore ?? 0,
    icon: IconBarChart,
    bg: '#F2F3F5',
    fg: '#4E5969',
    accent: false,
  },
])

const priorities = computed(() => {
  const s = summary.value
  return [
    { key: 'P1', label: 'P1 立即处理', window: '0-3 月', color: '#cb4b3f', bucket: s?.p1 },
    { key: 'P2', label: 'P2 近期', window: '3-6 月', color: '#FF7D00', bucket: s?.p2 },
    { key: 'P3', label: 'P3 规划', window: '6-12 月', color: '#d6a93f', bucket: s?.p3 },
    { key: 'P4', label: 'P4 监测', window: '持续', color: '#5a9367', bucket: s?.p4 },
  ]
})

const recentColumns = [
  { title: '任务', dataIndex: 'name' },
  { title: '状态', slotName: 'status', width: 110 },
  { title: '命中', slotName: 'count', width: 90, align: 'right' as const },
  { title: '完成时间', slotName: 'time', width: 170 },
]

function layerPercent(v: number) {
  return Math.round((v / layerMax.value) * 100)
}

async function load() {
  loading.value = true
  try {
    const [d, s, j] = await Promise.all([
      dashboardApi.get(),
      scoreApi.summary().catch(() => null),
      scanApi.list().catch(() => [] as ScanJob[]),
    ])
    data.value = d
    summary.value = s
    jobs.value = j.slice(0, 6)
  } catch {
    Message.error('加载仪表板数据失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header dash-head">
      <div>
        <h1 class="page-title">进度仪表板</h1>
        <p class="page-subtitle">
          密码学使用点摸底进度 · 优先级窗口 P1 立即(0-3 月) / P2 近期 / P3 规划 / P4 监测
        </p>
      </div>
      <a-button :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
        刷新
      </a-button>
    </div>

    <a-spin :loading="loading" style="width: 100%">
      <!-- 顶部指标卡 -->
      <a-row :gutter="16" class="metric-row">
        <a-col
          v-for="m in metricCards"
          :key="m.key"
          :xs="24"
          :sm="12"
          :md="8"
          :lg="5"
          :xl="5"
        >
          <a-card class="metric-card" :bordered="true">
            <div class="metric-icon" :style="{ background: m.bg, color: m.fg }">
              <component :is="m.icon" />
            </div>
            <div class="metric-body">
              <div
                class="metric-value"
                :style="{ color: m.accent ? 'var(--brand-accent)' : 'var(--brand-text)' }"
              >
                {{ m.value }}
              </div>
              <div class="metric-label">{{ m.label }}</div>
            </div>
          </a-card>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <!-- 四层分布 -->
        <a-col :xs="24" :lg="14">
          <a-card title="资产分层分布（L1–L4）" class="block-card">
            <template #extra>
              <span class="muted">共 {{ data?.totalAssets ?? 0 }} 个密码使用点</span>
            </template>
            <div v-if="(data?.totalAssets ?? 0) === 0" class="empty-inline">
              <a-empty description="尚无资产数据，去「密码学发现」发起扫描" />
            </div>
            <div v-else class="layer-list">
              <div v-for="l in layers" :key="l.key" class="layer-row">
                <span class="layer-name">{{ l.label }}</span>
                <a-progress
                  :percent="layerPercent(data?.byLayer[l.key] ?? 0) / 100"
                  :stroke-width="14"
                  :color="
                    l.key === 'L4'
                      ? '#165DFF'
                      : l.key === 'L3'
                        ? '#6AA1FF'
                        : '#4080FF'
                  "
                  :show-text="false"
                  class="layer-bar"
                />
                <span class="layer-count">{{ data?.byLayer[l.key] ?? 0 }}</span>
              </div>
            </div>
          </a-card>
        </a-col>

        <!-- 优先级汇总 -->
        <a-col :xs="24" :lg="10">
          <a-card title="优先级汇总" class="block-card">
            <template #extra>
              <span class="muted">已评分 {{ summary?.scoredCount ?? 0 }} 项</span>
            </template>
            <div class="prio-grid">
              <div
                v-for="p in priorities"
                :key="p.key"
                class="prio-cell"
                :style="{ borderColor: p.color }"
              >
                <div class="prio-top">
                  <span class="prio-dot" :style="{ background: p.color }" />
                  <span class="prio-label">{{ p.label }}</span>
                </div>
                <div class="prio-count" :style="{ color: p.color }">
                  {{ p.bucket?.count ?? 0 }}
                </div>
                <div class="prio-meta">均分 {{ p.bucket?.avg ?? 0 }} · {{ p.window }}</div>
              </div>
            </div>
          </a-card>
        </a-col>
      </a-row>

      <!-- 最近扫描任务 -->
      <a-card title="最近扫描任务" class="block-card" style="margin-top: 16px">
        <template #extra>
          <a-link @click="router.push('/discovery')">前往发现 →</a-link>
        </template>
        <a-table
          :data="jobs"
          :columns="recentColumns"
          :pagination="false"
          :bordered="false"
          row-key="id"
        >
          <template #status="{ record }">
            <a-tag :color="jobStatusMeta(record.status).color" size="small">
              {{ jobStatusMeta(record.status).label }}
            </a-tag>
          </template>
          <template #count="{ record }">{{ record.resultCount }}</template>
          <template #time="{ record }">{{ fmtDate(record.finishedAt) }}</template>
          <template #empty>
            <a-empty description="暂无扫描任务" />
          </template>
        </a-table>
      </a-card>

      <!-- 迁移进度趋势（Wave C） -->
      <DashboardTrend />
    </a-spin>
  </div>
</template>

<style scoped>
.dash-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
}
.metric-row {
  margin-bottom: 4px;
  row-gap: 16px;
}
.metric-card :deep(.arco-card-body) {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px;
}
.metric-icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  flex-shrink: 0;
}
.metric-value {
  font-size: 26px;
  font-weight: 700;
  line-height: 1.1;
}
.metric-label {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 3px;
}

.block-card {
  margin-top: 16px;
}
.muted {
  font-size: 12px;
  color: var(--brand-text-soft);
}
.empty-inline {
  padding: 18px 0;
}

.layer-list {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding: 4px 0;
}
.layer-row {
  display: grid;
  grid-template-columns: 150px 1fr 40px;
  align-items: center;
  gap: 14px;
}
.layer-name {
  font-size: 13px;
  color: var(--brand-text);
}
.layer-bar {
  flex: 1;
}
.layer-count {
  text-align: right;
  font-weight: 600;
  color: var(--brand-text);
}

.prio-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.prio-cell {
  border: 1px solid;
  border-left-width: 4px;
  border-radius: 10px;
  padding: 12px 14px;
  background: #FFFFFF;
}
.prio-top {
  display: flex;
  align-items: center;
  gap: 7px;
}
.prio-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.prio-label {
  font-size: 13px;
  font-weight: 500;
  color: var(--brand-text);
}
.prio-count {
  font-size: 24px;
  font-weight: 700;
  margin-top: 4px;
}
.prio-meta {
  font-size: 11px;
  color: var(--brand-text-soft);
}
</style>
