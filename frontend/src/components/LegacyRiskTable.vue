<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconExclamationCircle, IconCheckCircle } from '@arco-design/web-vue/es/icon'
import { monitorApi } from '@/api'
import type { LegacyRisk } from '@/api/types'
import {
  fmtDay,
  legacyLevelColor,
  legacyStatusMeta,
} from '@/utils/format'

/** R-00x 遗留风险登记台账：level 色 / AlwaysOnSLO 常显标 / close 需证据。 */
const loading = ref(false)
const risks = ref<LegacyRisk[]>([])

const filters = reactive({ level: '', status: '' })

// AlwaysOnSLO 常显项置顶。
const sorted = computed(() =>
  [...risks.value].sort((a, b) => {
    const av = a.alwaysOnSlo ? 1 : 0
    const bv = b.alwaysOnSlo ? 1 : 0
    if (av !== bv) return bv - av
    return (a.code || '').localeCompare(b.code || '')
  }),
)

const columns = [
  { title: '编号', slotName: 'code', width: 120 },
  { title: '描述', slotName: 'description', minWidth: 220, ellipsis: true, tooltip: true },
  { title: '等级', slotName: 'level', width: 90, align: 'center' as const },
  { title: '处置路径', dataIndex: 'disposition', minWidth: 160, ellipsis: true, tooltip: true },
  { title: '状态', slotName: 'status', width: 100, align: 'center' as const },
  { title: '责任人', dataIndex: 'owner', width: 100 },
  { title: '复检日期', slotName: 'recheck', width: 120 },
  { title: '操作', slotName: 'actions', width: 90, align: 'center' as const },
]

// 关闭风险弹窗（需证据 URL）。
const closeOpen = ref(false)
const closing = ref(false)
const closeTarget = ref<LegacyRisk | null>(null)
const evidenceUrl = ref('')

async function load() {
  loading.value = true
  try {
    const q: { level?: string; status?: string } = {}
    if (filters.level) q.level = filters.level
    if (filters.status) q.status = filters.status
    risks.value = await monitorApi.legacyRisks(q)
  } catch {
    Message.error('加载遗留风险台账失败')
  } finally {
    loading.value = false
  }
}

function openClose(risk: LegacyRisk) {
  closeTarget.value = risk
  evidenceUrl.value = risk.evidenceUrl ?? ''
  closeOpen.value = true
}

async function confirmClose() {
  if (!evidenceUrl.value.trim()) {
    Message.warning('关闭遗留风险须提供闭合证据（替换/升级证据 URL）')
    return
  }
  if (!closeTarget.value) return
  closing.value = true
  try {
    await monitorApi.closeLegacyRisk(closeTarget.value.id, evidenceUrl.value.trim())
    Message.success(`${closeTarget.value.code} 已关闭`)
    closeOpen.value = false
    await load()
  } catch {
    Message.error('关闭遗留风险失败')
  } finally {
    closing.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<template>
  <a-card class="block-card">
    <template #title>
      <span class="card-title-icon">
        <IconExclamationCircle /> 遗留风险登记（R-00x）
        <span class="muted">（{{ risks.length }} 项）</span>
      </span>
    </template>
    <template #extra>
      <a-space>
        <a-select
          v-model="filters.level"
          placeholder="等级"
          allow-clear
          size="small"
          style="width: 100px"
          @change="load"
        >
          <a-option value="高">高</a-option>
          <a-option value="中">中</a-option>
          <a-option value="低">低</a-option>
        </a-select>
        <a-select
          v-model="filters.status"
          placeholder="状态"
          allow-clear
          size="small"
          style="width: 120px"
          @change="load"
        >
          <a-option value="tracking">跟踪中</a-option>
          <a-option value="mitigating">缓解中</a-option>
          <a-option value="closed">已关闭</a-option>
        </a-select>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
        </a-button>
      </a-space>
    </template>

    <a-table
      :data="sorted"
      :columns="columns"
      :loading="loading"
      :pagination="{ pageSize: 8, hideOnSinglePage: true }"
      row-key="id"
      :scroll="{ x: 960 }"
    >
      <template #code="{ record }">
        <a-space :size="4">
          <span class="mono code">{{ record.code }}</span>
          <a-tag v-if="record.alwaysOnSlo" color="orange" size="small" title="SLO 看板常显">
            常显
          </a-tag>
        </a-space>
      </template>
      <template #description="{ record }">
        {{ record.description || '—' }}
      </template>
      <template #level="{ record }">
        <a-tag :color="legacyLevelColor(record.level)" size="small">
          {{ record.level || '—' }}
        </a-tag>
      </template>
      <template #status="{ record }">
        <a-tag :color="legacyStatusMeta(record.status).color" size="small">
          {{ legacyStatusMeta(record.status).label }}
        </a-tag>
      </template>
      <template #recheck="{ record }">
        {{ fmtDay(record.recheckDate) }}
      </template>
      <template #actions="{ record }">
        <a-button
          v-if="record.status !== 'closed'"
          size="mini"
          type="text"
          @click="openClose(record)"
        >
          <template #icon><IconCheckCircle /></template>
          关闭
        </a-button>
        <a-link
          v-else-if="record.evidenceUrl"
          :href="record.evidenceUrl"
          target="_blank"
          @click.stop
        >
          证据
        </a-link>
        <span v-else class="dim">—</span>
      </template>
      <template #empty>
        <a-empty description="暂无遗留风险登记" />
      </template>
    </a-table>

    <!-- 关闭风险（需证据） -->
    <a-modal
      v-model:visible="closeOpen"
      :title="`关闭遗留风险 ${closeTarget?.code ?? ''}`"
      :ok-loading="closing"
      ok-text="确认关闭"
      @ok="confirmClose"
    >
      <a-alert type="warning" style="margin-bottom: 14px">
        关闭遗留风险须留存闭合证据（替换/升级证据 URL），缺证据将被拒绝。
      </a-alert>
      <a-form-item label="闭合证据 URL" required>
        <a-input
          v-model="evidenceUrl"
          placeholder="https://… 替换/升级证据链接"
          allow-clear
        />
      </a-form-item>
    </a-modal>
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
  color: var(--clay-text-soft);
  font-weight: 400;
}
.mono {
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
}
.code {
  font-weight: 700;
  color: var(--clay-text);
}
.dim {
  color: var(--clay-text-soft);
}
</style>
