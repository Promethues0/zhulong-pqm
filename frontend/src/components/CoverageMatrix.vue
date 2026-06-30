<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconApps } from '@arco-design/web-vue/es/icon'
import { coverageApi } from '@/api'
import type { Coverage } from '@/api/types'

const loading = ref(false)
const coverage = ref<Coverage | null>(null)

/** 默认骨架：L1-L4 × M1-M7（后端无返回时也能呈现空矩阵）。 */
const DEFAULT_LAYERS = ['L1', 'L2', 'L3', 'L4']
const DEFAULT_METHODS = ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7']

const METHOD_LABEL: Record<string, string> = {
  M1: '主动',
  M2: '被动',
  M3: 'Agent',
  M4: 'SBOM',
  M5: '证书',
  M6: '配置',
  M7: '手录',
}

const layers = computed(() =>
  coverage.value?.layers?.length ? coverage.value.layers : DEFAULT_LAYERS,
)
const methods = computed(() =>
  coverage.value?.methods?.length ? coverage.value.methods : DEFAULT_METHODS,
)

// 单元格索引：`${layer}|${method}` → { covered, count }
const cellMap = computed(() => {
  const m = new Map<string, { covered: boolean; count: number }>()
  for (const c of coverage.value?.cells ?? []) {
    m.set(`${c.layer}|${c.method}`, { covered: c.covered, count: c.count })
  }
  return m
})

function cell(layer: string, method: string) {
  return cellMap.value.get(`${layer}|${method}`) ?? { covered: false, count: 0 }
}

const coveredCount = computed(() => {
  let n = 0
  for (const c of coverage.value?.cells ?? []) if (c.covered) n++
  return n
})
const totalCells = computed(() => layers.value.length * methods.value.length)

async function load() {
  loading.value = true
  try {
    coverage.value = await coverageApi.get()
  } catch {
    Message.error('加载覆盖度矩阵失败')
  } finally {
    loading.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<template>
  <a-card class="block-card">
    <template #title>
      <span class="card-title-icon">
        <IconApps /> 发现覆盖度矩阵
        <span class="muted">（已覆盖 {{ coveredCount }}/{{ totalCells }} 组合）</span>
      </span>
    </template>
    <template #extra>
      <a-button size="small" :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
        刷新
      </a-button>
    </template>

    <a-spin :loading="loading" style="width: 100%">
      <div class="matrix-wrap">
        <table class="matrix">
          <thead>
            <tr>
              <th class="corner">层级 ＼ 方式</th>
              <th v-for="mt in methods" :key="mt" class="method-head">
                <div class="method-code">{{ mt }}</div>
                <div class="method-label">{{ METHOD_LABEL[mt] ?? '' }}</div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ly in layers" :key="ly">
              <th class="layer-head">{{ ly }}</th>
              <td v-for="mt in methods" :key="mt" class="matrix-cell">
                <div
                  class="dot"
                  :class="cell(ly, mt).covered ? 'dot--on' : 'dot--off'"
                  :title="
                    cell(ly, mt).covered
                      ? `已覆盖 · 命中 ${cell(ly, mt).count}`
                      : '未覆盖'
                  "
                >
                  <span v-if="cell(ly, mt).covered && cell(ly, mt).count" class="dot-num">
                    {{ cell(ly, mt).count }}
                  </span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="legend">
        <span class="legend-item"><i class="dot dot--on legend-dot" /> 已覆盖</span>
        <span class="legend-item"><i class="dot dot--off legend-dot" /> 未覆盖</span>
        <span
          v-if="coverage?.p1Total"
          class="legend-item legend-p1"
        >
          P1 窗口覆盖：{{ coverage.p1Covered ?? 0 }}/{{ coverage.p1Total }}
        </span>
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
  gap: 6px;
}
.muted {
  font-size: 12px;
  color: var(--brand-text-soft);
  font-weight: 400;
}

.matrix-wrap {
  overflow-x: auto;
}
.matrix {
  border-collapse: separate;
  border-spacing: 6px;
  width: 100%;
}
.corner {
  font-size: 12px;
  color: var(--brand-text-soft);
  font-weight: 600;
  text-align: left;
  white-space: nowrap;
  padding: 4px 8px;
}
.method-head {
  text-align: center;
  min-width: 56px;
}
.method-code {
  font-size: 13px;
  font-weight: 700;
  color: var(--brand-text);
}
.method-label {
  font-size: 11px;
  color: var(--brand-text-soft);
  margin-top: 2px;
}
.layer-head {
  font-size: 13px;
  font-weight: 700;
  color: var(--brand-text);
  text-align: center;
  background: var(--brand-bg-soft);
  border-radius: 8px;
  padding: 6px 10px;
}
.matrix-cell {
  text-align: center;
  padding: 0;
}
.dot {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
}
.dot--on {
  background: rgba(90, 147, 103, 0.18);
  border: 1px solid #5a9367;
  color: #3f7150;
}
.dot--off {
  background: var(--brand-bg-soft);
  border: 1px dashed var(--brand-border);
  color: var(--brand-text-soft);
}
.dot-num {
  line-height: 1;
}

.legend {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-top: 14px;
  flex-wrap: wrap;
}
.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--brand-text-soft);
}
.legend-dot {
  width: 16px;
  height: 16px;
  border-radius: 5px;
}
.legend-p1 {
  font-weight: 600;
  color: var(--brand-accent);
}
</style>
