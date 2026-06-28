<script setup lang="ts">
import type { Playbook } from '@/api/types'
import { deviceTypeColor, deviceTypeLabel } from '@/utils/format'

defineProps<{ playbook: Playbook }>()
</script>

<template>
  <a-card class="pb-card" :bordered="true">
    <div class="pb-head">
      <span class="pb-name">{{ playbook.name }}</span>
      <a-tag :color="deviceTypeColor(playbook.deviceType)" size="small">
        {{ deviceTypeLabel(playbook.deviceType) }}
      </a-tag>
    </div>

    <div class="pb-section">
      <div class="pb-label">改造步骤</div>
      <ol class="pb-steps">
        <li v-for="(s, i) in playbook.steps" :key="i">{{ s }}</li>
      </ol>
    </div>

    <div class="pb-meta">
      <div class="pb-meta-row">
        <span class="pb-meta-key">交付物</span>
        <span class="pb-meta-val">{{ playbook.deliverable || '—' }}</span>
      </div>
      <div class="pb-meta-row">
        <span class="pb-meta-key">验收口径</span>
        <span class="pb-meta-val">{{ playbook.acceptance || '—' }}</span>
      </div>
      <div class="pb-meta-row">
        <span class="pb-meta-key">默认目标算法</span>
        <a-tag v-if="playbook.targetAlgo" color="orange" size="small">
          {{ playbook.targetAlgo }}
        </a-tag>
        <span v-else class="pb-meta-val">—</span>
      </div>
    </div>
  </a-card>
</template>

<style scoped>
.pb-card {
  height: 100%;
  border-radius: 12px;
}
.pb-card :deep(.arco-card-body) {
  padding: 16px 18px;
}
.pb-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 12px;
}
.pb-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--clay-text);
}
.pb-section {
  margin-bottom: 14px;
}
.pb-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--clay-text-soft);
  margin-bottom: 6px;
}
.pb-steps {
  margin: 0;
  padding-left: 18px;
}
.pb-steps li {
  font-size: 13px;
  color: var(--clay-text);
  line-height: 1.7;
}
.pb-meta {
  border-top: 1px solid var(--clay-border);
  padding-top: 12px;
}
.pb-meta-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.pb-meta-key {
  flex-shrink: 0;
  width: 84px;
  font-size: 12px;
  color: var(--clay-text-soft);
}
.pb-meta-val {
  font-size: 13px;
  color: var(--clay-text);
}
</style>
