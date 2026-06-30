<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconCamera } from '@arco-design/web-vue/es/icon'
import { trendApi } from '@/api'
import type { TrendPoint } from '@/api/types'
import { fmtDay } from '@/utils/format'

/**
 * 仪表板迁移趋势：总资产 / P1 / 已改造 / 均分 随时间（轻量 SVG 自绘，无图表库）。
 * 多条折线共用同一 Y 轴比例（计数类）；均分单独以右侧虚线参考标注，避免量纲混淆。
 * 空/单点时给出友好提示。
 */
const loading = ref(false)
const snapshotting = ref(false)
const points = ref<TrendPoint[]>([])
const days = ref(7)

const dayOptions = [
  { label: '7 天', value: 7 },
  { label: '30 天', value: 30 },
  { label: '90 天', value: 90 },
]

// 三条计数序列（共用左轴）。
const seriesDefs = [
  { key: 'totalAssets' as const, label: '总资产', color: '#165DFF' },
  { key: 'p1Count' as const, label: 'P1', color: '#cb4b3f' },
  { key: 'remediatedCount' as const, label: '已改造', color: '#5a9367' },
]

// 画布几何。
const W = 760
const H = 260
const PAD = { top: 18, right: 52, bottom: 30, left: 44 }
const plotW = W - PAD.left - PAD.right
const plotH = H - PAD.top - PAD.bottom

const hasData = computed(() => points.value.length > 0)
const single = computed(() => points.value.length === 1)

// 左轴范围：覆盖三条计数序列，留 12% 余量，下界 0。
const yMax = computed(() => {
  let m = 0
  for (const p of points.value) {
    m = Math.max(m, p.totalAssets, p.p1Count, p.remediatedCount)
  }
  return Math.max(1, Math.ceil(m * 1.12))
})

function xAt(i: number): number {
  const n = points.value.length
  if (n <= 1) return PAD.left + plotW / 2
  return PAD.left + (plotW * i) / (n - 1)
}

function yAt(v: number): number {
  const t = v / yMax.value
  return PAD.top + plotH - t * plotH
}

function pathFor(key: (typeof seriesDefs)[number]['key']): string {
  return points.value
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${yAt(p[key]).toFixed(1)}`)
    .join(' ')
}

// 均分参考（右轴，0-100）：单独一条灰橙虚线，不与计数共轴。
const avgMax = 100
function yAvg(v: number): number {
  const t = Math.min(1, v / avgMax)
  return PAD.top + plotH - t * plotH
}
const avgPath = computed(() =>
  points.value
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${yAvg(p.avgScore).toFixed(1)}`)
    .join(' '),
)

const yTicks = computed(() => {
  const ticks: { y: number; label: string }[] = []
  for (let i = 0; i <= 4; i++) {
    const v = (yMax.value * i) / 4
    ticks.push({ y: yAt(v), label: String(Math.round(v)) })
  }
  return ticks
})

// X 轴标签：首/中/尾，避免拥挤。
const xTicks = computed(() => {
  const n = points.value.length
  if (!n) return []
  const idxs = n <= 3 ? points.value.map((_, i) => i) : [0, Math.floor((n - 1) / 2), n - 1]
  return idxs.map((i) => ({ x: xAt(i), label: fmtDay(points.value[i].at) }))
})

async function load() {
  loading.value = true
  try {
    const r = await trendApi.get(days.value)
    points.value = r.points ?? []
  } catch {
    Message.error('加载迁移趋势失败')
    points.value = []
  } finally {
    loading.value = false
  }
}

async function snapshot() {
  snapshotting.value = true
  try {
    await trendApi.snapshot()
    Message.success('已采集今日快照')
    await load()
  } catch {
    Message.error('采集快照失败（需 operator/admin 权限）')
  } finally {
    snapshotting.value = false
  }
}

function changeDays(d: number) {
  days.value = d
  load()
}

onMounted(load)
defineExpose({ load })
</script>

<template>
  <a-card class="block-card">
    <template #title>迁移进度趋势</template>
    <template #extra>
      <a-space>
        <a-radio-group
          v-model="days"
          type="button"
          size="small"
          @change="(v: unknown) => changeDays(Number(v))"
        >
          <a-radio v-for="o in dayOptions" :key="o.value" :value="o.value">
            {{ o.label }}
          </a-radio>
        </a-radio-group>
        <a-button size="small" type="primary" :loading="snapshotting" @click="snapshot">
          <template #icon><IconCamera /></template>
          采集今日快照
        </a-button>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
        </a-button>
      </a-space>
    </template>

    <a-spin :loading="loading" style="width: 100%">
      <div v-if="!hasData" class="empty-hint">
        <a-empty description="暂无趋势数据，点击「采集今日快照」生成首个数据点" />
      </div>
      <div v-else class="chart-wrap">
        <div v-if="single" class="single-hint">
          仅 1 个采样点，连续多日采集后将呈现折线走势。
        </div>
        <svg :viewBox="`0 0 ${W} ${H}`" class="chart" preserveAspectRatio="xMidYMid meet">
          <!-- Y 轴网格 + 刻度（左：计数） -->
          <g class="grid">
            <line
              v-for="(t, i) in yTicks"
              :key="i"
              :x1="PAD.left"
              :y1="t.y"
              :x2="W - PAD.right"
              :y2="t.y"
            />
            <text
              v-for="(t, i) in yTicks"
              :key="`yl${i}`"
              :x="PAD.left - 8"
              :y="t.y + 3"
              class="y-label"
            >
              {{ t.label }}
            </text>
          </g>

          <!-- X 轴标签 -->
          <text
            v-for="(t, i) in xTicks"
            :key="`xl${i}`"
            :x="t.x"
            :y="H - 8"
            class="x-label"
          >
            {{ t.label }}
          </text>

          <!-- 均分参考线（右轴 0-100，灰橙虚线） -->
          <path :d="avgPath" class="avg-line" />
          <text :x="W - PAD.right + 6" :y="PAD.top + 4" class="avg-axis">均分</text>

          <!-- 计数折线 -->
          <g v-for="s in seriesDefs" :key="s.key">
            <path :d="pathFor(s.key)" class="line" :style="{ stroke: s.color }" />
            <circle
              v-for="(p, i) in points"
              :key="`${s.key}-${i}`"
              :cx="xAt(i)"
              :cy="yAt(p[s.key])"
              r="2.6"
              :style="{ fill: s.color }"
              class="pt"
            >
              <title>{{ fmtDay(p.at) }} · {{ s.label }} {{ p[s.key] }}</title>
            </circle>
          </g>
        </svg>

        <div class="chart-legend">
          <span v-for="s in seriesDefs" :key="s.key" class="lg">
            <span class="lg-dot" :style="{ background: s.color }" />
            {{ s.label }}
          </span>
          <span class="lg">
            <span class="lg-dash" />
            均分（右轴 0-100）
          </span>
        </div>
      </div>
    </a-spin>
  </a-card>
</template>

<style scoped>
.block-card {
  margin-top: 16px;
}
.empty-hint {
  padding: 24px 0;
}
.chart-wrap {
  width: 100%;
}
.single-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-bottom: 6px;
}
.chart {
  width: 100%;
  height: auto;
  display: block;
}
.grid line {
  stroke: var(--brand-border);
  stroke-width: 1;
  stroke-dasharray: 2 4;
}
.y-label {
  fill: var(--brand-text-soft);
  font-size: 11px;
  text-anchor: end;
}
.x-label {
  fill: var(--brand-text-soft);
  font-size: 11px;
  text-anchor: middle;
}
.line {
  fill: none;
  stroke-width: 2.2;
  stroke-linejoin: round;
  stroke-linecap: round;
}
.avg-line {
  fill: none;
  stroke: #d6a93f;
  stroke-width: 1.6;
  stroke-dasharray: 5 4;
}
.avg-axis {
  fill: #d6a93f;
  font-size: 10px;
  font-weight: 600;
  text-anchor: start;
}
.pt {
  stroke: #FFFFFF;
  stroke-width: 1.2;
}
.chart-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  margin-top: 10px;
  padding-left: 8px;
}
.lg {
  font-size: 12px;
  color: var(--brand-text-soft);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.lg-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}
.lg-dash {
  width: 16px;
  height: 0;
  border-top: 1.6px dashed #d6a93f;
}
</style>
