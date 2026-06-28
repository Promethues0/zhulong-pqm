<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconHistory } from '@arco-design/web-vue/es/icon'
import { assetApi } from '@/api'
import type { ScoreHistory } from '@/api/types'
import { fmtDate, levelColor, levelText } from '@/utils/format'

/**
 * 资产评分历史时间线：级别变化高亮 + reason 标签 + 顶部 mini 折线（综合分漂移）。
 */
const props = defineProps<{ assetId?: number | null }>()

const loading = ref(false)
const history = ref<ScoreHistory[]>([])

const reasonMeta: Record<string, { label: string; color: string }> = {
  manual: { label: '手工调维', color: 'arcoblue' },
  rescore: { label: '批量复算', color: 'purple' },
  'profile-switch': { label: '权重切换', color: 'orange' },
  'scan-import': { label: '扫描入册', color: 'cyan' },
}

function reasonOf(reason: string) {
  return reasonMeta[reason] ?? { label: reason || '—', color: 'gray' }
}

// 级别方向：升级（恶化）红 / 降级（改善）绿。
function levelDirection(h: ScoreHistory): 'up' | 'down' | 'none' {
  if (!h.prevLevel || h.prevLevel === h.level) return 'none'
  const order: Record<string, number> = { P4: 1, P3: 2, P2: 3, P1: 4 }
  const prev = order[h.prevLevel] ?? 0
  const cur = order[h.level] ?? 0
  if (cur > prev) return 'up'
  if (cur < prev) return 'down'
  return 'none'
}

function dotColor(h: ScoreHistory): string {
  const dir = levelDirection(h)
  if (dir === 'up') return '#cb4b3f'
  if (dir === 'down') return '#5a9367'
  return '#db855c'
}

// 时间线按时间倒序展示；折线按时间正序。
const chronological = computed(() => [...history.value].reverse())

// mini 折线几何。
const SW = 280
const SH = 56
const sparkPath = computed(() => {
  const hs = chronological.value
  if (hs.length < 2) return ''
  const scores = hs.map((h) => h.score)
  const min = Math.min(...scores)
  const max = Math.max(...scores)
  const range = max - min || 1
  return hs
    .map((h, i) => {
      const x = (SW * i) / (hs.length - 1)
      const y = SH - 4 - ((h.score - min) / range) * (SH - 8)
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
    })
    .join(' ')
})

async function load() {
  if (props.assetId == null) {
    history.value = []
    return
  }
  loading.value = true
  try {
    history.value = await assetApi.history(props.assetId)
  } catch {
    Message.error('加载评分历史失败')
    history.value = []
  } finally {
    loading.value = false
  }
}

watch(() => props.assetId, load, { immediate: true })
defineExpose({ load })
</script>

<template>
  <div class="history-block">
    <div class="history-head">
      <span class="head-title"><IconHistory /> 评分历史</span>
      <span class="muted">{{ history.length }} 条快照</span>
    </div>

    <a-spin :loading="loading" style="width: 100%">
      <a-empty
        v-if="!history.length"
        description="暂无评分历史，调维/复算/权重切换后会自动留痕"
        :image-size="40"
      />
      <template v-else>
        <!-- mini 折线（综合分漂移） -->
        <div v-if="sparkPath" class="spark-wrap">
          <svg :viewBox="`0 0 ${SW} ${SH}`" class="spark" preserveAspectRatio="none">
            <path :d="sparkPath" class="spark-line" />
          </svg>
          <span class="spark-cap">综合分随时间</span>
        </div>

        <a-timeline class="tl">
          <a-timeline-item
            v-for="(h, i) in history"
            :key="i"
            :dot-color="dotColor(h)"
            :line-type="levelDirection(h) !== 'none' ? 'solid' : 'dashed'"
          >
            <div class="tl-item" :class="{ 'tl-item--hl': levelDirection(h) !== 'none' }">
              <div class="tl-top">
                <span class="tl-score">{{ h.score }}</span>
                <a-tag :color="levelColor(h.level)" size="small">
                  {{ h.level }} {{ levelText(h.level) }}
                </a-tag>
                <span v-if="levelDirection(h) !== 'none'" class="tl-shift" :class="levelDirection(h)">
                  {{ h.prevLevel }} → {{ h.level }}
                  {{ levelDirection(h) === 'up' ? '↑' : '↓' }}
                </span>
                <a-tag v-if="h.hndl" color="red" size="small">HNDL</a-tag>
              </div>
              <div class="tl-meta">
                <a-tag :color="reasonOf(h.reason).color" size="small" bordered>
                  {{ reasonOf(h.reason).label }}
                </a-tag>
                <span v-if="h.profileName" class="tl-profile">{{ h.profileName }}</span>
                <span v-if="h.changedBy" class="tl-by">· {{ h.changedBy }}</span>
                <span class="tl-time">{{ fmtDate(h.at) }}</span>
              </div>
            </div>
          </a-timeline-item>
        </a-timeline>
      </template>
    </a-spin>
  </div>
</template>

<style scoped>
.history-block {
  margin-top: 4px;
}
.history-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.head-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.muted {
  font-size: 12px;
  color: var(--clay-text-soft);
}
.spark-wrap {
  position: relative;
  margin-bottom: 16px;
  padding: 8px 10px;
  background: var(--clay-bg-soft);
  border-radius: 8px;
}
.spark {
  width: 100%;
  height: 56px;
  display: block;
}
.spark-line {
  fill: none;
  stroke: #b4552d;
  stroke-width: 2;
  stroke-linejoin: round;
  stroke-linecap: round;
  vector-effect: non-scaling-stroke;
}
.spark-cap {
  position: absolute;
  top: 8px;
  right: 12px;
  font-size: 11px;
  color: var(--clay-text-soft);
}
.tl {
  padding-top: 4px;
}
.tl-item {
  padding: 4px 0;
}
.tl-item--hl {
  background: linear-gradient(90deg, rgba(219, 133, 92, 0.1), transparent);
  border-radius: 6px;
  padding: 6px 8px;
  margin-left: -8px;
}
.tl-top {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.tl-score {
  font-size: 18px;
  font-weight: 700;
  color: var(--clay-text);
}
.tl-shift {
  font-size: 12px;
  font-weight: 600;
}
.tl-shift.up {
  color: #cb4b3f;
}
.tl-shift.down {
  color: #5a9367;
}
.tl-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 6px;
  flex-wrap: wrap;
}
.tl-profile {
  font-size: 12px;
  color: var(--clay-text);
}
.tl-by {
  font-size: 12px;
  color: var(--clay-text-soft);
}
.tl-time {
  font-size: 11px;
  color: var(--clay-text-soft);
  margin-left: auto;
}
</style>
