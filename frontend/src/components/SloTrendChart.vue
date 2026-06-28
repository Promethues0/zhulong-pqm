<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh } from '@arco-design/web-vue/es/icon'
import { sloApi } from '@/api'
import type { SloSeries } from '@/api/types'
import { fmtDate, sloUnitSuffix } from '@/utils/format'

/**
 * SLO 趋势折线（轻量 SVG 自绘，无第三方图表依赖）。
 * 叠加阈值线（红虚线）与基线（灰虚线），越界点标红。
 */
const props = defineProps<{
  /** 当前选中的 SLO 编号；为空则不拉取。 */
  code?: string
}>()

const loading = ref(false)
const series = ref<SloSeries | null>(null)

// 画布几何（viewBox 固定，按宽度自适应缩放）。
const W = 720
const H = 240
const PAD = { top: 18, right: 18, bottom: 28, left: 46 }
const plotW = W - PAD.left - PAD.right
const plotH = H - PAD.top - PAD.bottom

const points = computed(() => series.value?.points ?? [])

// Y 轴范围：覆盖数据 + 阈值 + 基线，留 10% 余量。
const yRange = computed(() => {
  const vals: number[] = []
  for (const p of points.value) vals.push(p.value)
  if (series.value?.threshold != null) vals.push(series.value.threshold)
  if (series.value?.baseline != null) vals.push(series.value.baseline)
  if (!vals.length) return { min: 0, max: 1 }
  let min = Math.min(...vals)
  let max = Math.max(...vals)
  if (min === max) {
    min -= 1
    max += 1
  }
  const pad = (max - min) * 0.1
  return { min: Math.max(0, min - pad), max: max + pad }
})

function xAt(i: number): number {
  const n = points.value.length
  if (n <= 1) return PAD.left + plotW / 2
  return PAD.left + (plotW * i) / (n - 1)
}

function yAt(v: number): number {
  const { min, max } = yRange.value
  const t = (v - min) / (max - min || 1)
  return PAD.top + plotH - t * plotH
}

const linePath = computed(() => {
  const ps = points.value
  if (!ps.length) return ''
  return ps
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${yAt(p.value).toFixed(1)}`)
    .join(' ')
})

// 渐变填充区（折线下方）。
const areaPath = computed(() => {
  const ps = points.value
  if (!ps.length) return ''
  const top = ps
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${yAt(p.value).toFixed(1)}`)
    .join(' ')
  const lastX = xAt(ps.length - 1)
  const baseY = PAD.top + plotH
  return `${top} L ${lastX.toFixed(1)} ${baseY} L ${xAt(0).toFixed(1)} ${baseY} Z`
})

const thresholdY = computed(() =>
  series.value?.threshold != null ? yAt(series.value.threshold) : null,
)
const baselineY = computed(() =>
  series.value?.baseline != null ? yAt(series.value.baseline) : null,
)

// Y 轴刻度（4 段）。
const yTicks = computed(() => {
  const { min, max } = yRange.value
  const ticks: { y: number; label: string }[] = []
  for (let i = 0; i <= 4; i++) {
    const v = min + ((max - min) * i) / 4
    ticks.push({ y: yAt(v), label: v.toFixed(v < 10 ? 1 : 0) })
  }
  return ticks
})

const unitSuffix = computed(() => sloUnitSuffix(series.value?.unit))

async function load() {
  if (!props.code) {
    series.value = null
    return
  }
  loading.value = true
  try {
    series.value = await sloApi.series(props.code)
  } catch {
    Message.error('加载 SLO 趋势失败')
    series.value = null
  } finally {
    loading.value = false
  }
}

watch(() => props.code, load, { immediate: true })
defineExpose({ load })
</script>

<template>
  <a-card class="block-card">
    <template #title>
      <span class="card-title-icon">
        SLO 趋势 · {{ code || '—' }}
        <span v-if="series" class="muted">{{ points.length }} 个采样点</span>
      </span>
    </template>
    <template #extra>
      <a-button size="small" :loading="loading" :disabled="!code" @click="load">
        <template #icon><IconRefresh /></template>
        刷新
      </a-button>
    </template>

    <a-spin :loading="loading" style="width: 100%">
      <div v-if="!code" class="empty-hint">点击上方 SLO 卡片查看时序趋势</div>
      <div v-else-if="!points.length" class="empty-hint">该 SLO 暂无时序数据</div>
      <div v-else class="chart-wrap">
        <svg :viewBox="`0 0 ${W} ${H}`" class="chart" preserveAspectRatio="xMidYMid meet">
          <defs>
            <linearGradient id="sloArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#db855c" stop-opacity="0.28" />
              <stop offset="100%" stop-color="#db855c" stop-opacity="0.02" />
            </linearGradient>
          </defs>

          <!-- Y 轴网格 + 刻度 -->
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
              :key="`l${i}`"
              :x="PAD.left - 8"
              :y="t.y + 3"
              class="y-label"
            >
              {{ t.label }}
            </text>
          </g>

          <!-- 基线（灰虚线） -->
          <g v-if="baselineY != null">
            <line
              :x1="PAD.left"
              :y1="baselineY"
              :x2="W - PAD.right"
              :y2="baselineY"
              class="baseline"
            />
            <text :x="W - PAD.right" :y="baselineY - 5" class="ref-label baseline-label">
              基线 {{ series?.baseline }}{{ unitSuffix }}
            </text>
          </g>

          <!-- 阈值（红虚线） -->
          <g v-if="thresholdY != null">
            <line
              :x1="PAD.left"
              :y1="thresholdY"
              :x2="W - PAD.right"
              :y2="thresholdY"
              class="threshold"
            />
            <text :x="W - PAD.right" :y="thresholdY - 5" class="ref-label threshold-label">
              阈值 {{ series?.threshold }}{{ unitSuffix }}
            </text>
          </g>

          <!-- 面积 + 折线 -->
          <path :d="areaPath" fill="url(#sloArea)" />
          <path :d="linePath" class="line" />

          <!-- 数据点 -->
          <g>
            <circle
              v-for="(p, i) in points"
              :key="i"
              :cx="xAt(i)"
              :cy="yAt(p.value)"
              :r="p.breached ? 4.5 : 3"
              :class="p.breached ? 'pt pt--breached' : 'pt'"
            >
              <title>{{ fmtDate(p.at) }} · {{ p.value }}{{ unitSuffix }}{{ p.breached ? ' · 越界' : '' }}</title>
            </circle>
          </g>
        </svg>

        <div class="chart-legend">
          <span class="lg lg-line">实测</span>
          <span class="lg lg-th">阈值</span>
          <span class="lg lg-bl">基线</span>
          <span class="lg lg-br">越界点</span>
        </div>
      </div>
    </a-spin>
  </a-card>
</template>

<style scoped>
.block-card {
  margin-bottom: 16px;
}
.card-title-icon {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.muted {
  font-size: 12px;
  color: var(--clay-text-soft);
  font-weight: 400;
}
.empty-hint {
  text-align: center;
  color: var(--clay-text-soft);
  font-size: 13px;
  padding: 40px 0;
}
.chart-wrap {
  width: 100%;
}
.chart {
  width: 100%;
  height: auto;
  display: block;
}
.grid line {
  stroke: var(--clay-border);
  stroke-width: 1;
  stroke-dasharray: 2 4;
}
.y-label {
  fill: var(--clay-text-soft);
  font-size: 11px;
  text-anchor: end;
}
.line {
  fill: none;
  stroke: #b4552d;
  stroke-width: 2.2;
  stroke-linejoin: round;
  stroke-linecap: round;
}
.threshold {
  stroke: #cb4b3f;
  stroke-width: 1.4;
  stroke-dasharray: 6 4;
}
.baseline {
  stroke: #a99d90;
  stroke-width: 1.4;
  stroke-dasharray: 4 4;
}
.ref-label {
  font-size: 11px;
  text-anchor: end;
  font-weight: 600;
}
.threshold-label {
  fill: #cb4b3f;
}
.baseline-label {
  fill: #8a7d70;
}
.pt {
  fill: #b4552d;
  stroke: #fffdfa;
  stroke-width: 1.5;
}
.pt--breached {
  fill: #cb4b3f;
}
.chart-legend {
  display: flex;
  gap: 18px;
  margin-top: 10px;
  padding-left: 8px;
}
.lg {
  font-size: 12px;
  color: var(--clay-text-soft);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.lg::before {
  content: '';
  width: 14px;
  height: 0;
  border-top-width: 2px;
  border-top-style: solid;
}
.lg-line::before {
  border-color: #b4552d;
}
.lg-th::before {
  border-color: #cb4b3f;
  border-top-style: dashed;
}
.lg-bl::before {
  border-color: #a99d90;
  border-top-style: dashed;
}
.lg-br::before {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #cb4b3f;
  border: none;
}
</style>
