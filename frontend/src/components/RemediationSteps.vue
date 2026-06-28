<script setup lang="ts">
import type { Step } from '@/api/types'
import { fmtDate, stepStatusMeta } from '@/utils/format'

defineProps<{ steps: Step[] }>()

// a-timeline 圆点配色（用 Arco 语义色，与 tag 配色口径一致）。
function dotColor(status: string): string {
  switch (status) {
    case 'done':
      return 'rgb(var(--green-6))'
    case 'simulated':
      return 'rgb(var(--orange-6))'
    case 'running':
      return 'rgb(var(--arcoblue-6))'
    case 'failed':
      return 'rgb(var(--red-6))'
    default:
      return 'var(--clay-border)'
  }
}
</script>

<template>
  <a-timeline class="rem-steps">
    <a-timeline-item
      v-for="(s, i) in steps"
      :key="i"
      :dot-color="dotColor(s.status)"
    >
      <div class="step-head">
        <span class="step-name">{{ s.name }}</span>
        <a-tag :color="stepStatusMeta(s.status).color" size="small">
          {{ stepStatusMeta(s.status).label }}
        </a-tag>
        <span v-if="s.status === 'simulated'" class="step-sim">（模拟）</span>
      </div>
      <div v-if="s.detail" class="step-detail">{{ s.detail }}</div>
      <div v-if="s.at" class="step-at">{{ fmtDate(s.at) }}</div>
    </a-timeline-item>
    <template v-if="!steps.length">
      <a-empty description="暂无步骤" />
    </template>
  </a-timeline>
</template>

<style scoped>
.rem-steps {
  margin-top: 4px;
}
.step-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.step-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
}
.step-sim {
  font-size: 12px;
  color: rgb(var(--orange-6));
}
.step-detail {
  font-size: 13px;
  color: var(--clay-text-soft);
  margin-top: 4px;
  line-height: 1.5;
}
.step-at {
  font-size: 11px;
  color: var(--clay-text-soft);
  margin-top: 3px;
}
</style>
