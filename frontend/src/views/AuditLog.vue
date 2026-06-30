<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconSearch,
  IconExport,
  IconHistory,
} from '@arco-design/web-vue/es/icon'
import { auditApi } from '@/api'
import type { AuditLog, AuditQuery } from '@/api/types'
import {
  fmtDate,
  auditResultMeta,
  auditModuleLabel,
} from '@/utils/format'

/**
 * 审计日志（admin 可见，路由已守卫 meta.roles=['admin']）。
 * 表格 actor/time/module/action/result + 筛选 + 导出 CSV。
 */
const loading = ref(false)
const exporting = ref(false)
const logs = ref<AuditLog[]>([])

const filters = reactive<AuditQuery>({
  module: '',
  action: '',
  result: '',
  actor: '',
})

const moduleOptions = [
  'scan', 'asset', 'score', 'remediation', 'device', 'report', 'cbom', 'user', 'setting', 'auth',
]
const resultOptions = [
  { value: 'success', label: '成功' },
  { value: 'failure', label: '失败' },
  { value: 'denied', label: '拒绝' },
]

const columns = [
  { title: '时间', slotName: 'time', width: 170 },
  { title: '操作人', slotName: 'actor', width: 150 },
  { title: '模块', slotName: 'module', width: 120 },
  { title: '动作', slotName: 'action', width: 160 },
  { title: '对象', slotName: 'target', minWidth: 180, ellipsis: true, tooltip: true },
  { title: '结果', slotName: 'result', width: 90, align: 'center' as const },
  { title: 'IP', dataIndex: 'ip', width: 130 },
]

function activeQuery(): AuditQuery {
  const q: AuditQuery = {}
  if (filters.module) q.module = filters.module
  if (filters.action) q.action = filters.action
  if (filters.result) q.result = filters.result
  if (filters.actor) q.actor = filters.actor.trim()
  return q
}

async function load() {
  loading.value = true
  try {
    logs.value = await auditApi.list(activeQuery())
  } catch {
    Message.error('加载审计日志失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.module = ''
  filters.action = ''
  filters.result = ''
  filters.actor = ''
  load()
}

async function exportCsv() {
  exporting.value = true
  try {
    const blob = await auditApi.exportCsv(activeQuery())
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const stamp = new Date().toISOString().slice(0, 10)
    a.download = `zhulong-pqm-audit-${stamp}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    Message.success('审计日志 CSV 已导出')
  } catch {
    Message.error('导出审计日志失败')
  } finally {
    exporting.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header audit-head">
      <div>
        <h1 class="page-title"><IconHistory /> 审计日志</h1>
        <p class="page-subtitle">
          敏感动作留痕台账 —— 操作人 / 时间 / 模块 / 动作 / 结果。仅管理员可见与导出。
        </p>
      </div>
      <a-button type="outline" :loading="exporting" @click="exportCsv">
        <template #icon><IconExport /></template>
        导出 CSV
      </a-button>
    </div>

    <!-- 筛选条 -->
    <a-card class="filter-card" :bordered="true">
      <a-row :gutter="12" align="center">
        <a-col flex="160px">
          <a-select v-model="filters.module" placeholder="模块" allow-clear @change="load">
            <a-option v-for="m in moduleOptions" :key="m" :value="m">
              {{ auditModuleLabel(m) }}
            </a-option>
          </a-select>
        </a-col>
        <a-col flex="180px">
          <a-input
            v-model="filters.action"
            placeholder="动作（如 scan.create）"
            allow-clear
            @press-enter="load"
            @clear="load"
          />
        </a-col>
        <a-col flex="140px">
          <a-select v-model="filters.result" placeholder="结果" allow-clear @change="load">
            <a-option v-for="r in resultOptions" :key="r.value" :value="r.value">
              {{ r.label }}
            </a-option>
          </a-select>
        </a-col>
        <a-col flex="auto">
          <a-input
            v-model="filters.actor"
            placeholder="按操作人筛选"
            allow-clear
            @press-enter="load"
            @clear="load"
          >
            <template #prefix><IconSearch /></template>
          </a-input>
        </a-col>
        <a-col flex="170px">
          <a-space>
            <a-button type="primary" :loading="loading" @click="load">查询</a-button>
            <a-button @click="resetFilters">重置</a-button>
          </a-space>
        </a-col>
      </a-row>
    </a-card>

    <a-card class="block-card">
      <template #title>
        审计记录 <span class="muted">（{{ logs.length }} 条）</span>
      </template>
      <template #extra>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
          刷新
        </a-button>
      </template>
      <a-table
        :data="logs"
        :columns="columns"
        :loading="loading"
        :pagination="{ pageSize: 15, showTotal: true, hideOnSinglePage: false }"
        row-key="id"
        :scroll="{ x: 1000 }"
      >
        <template #time="{ record }">{{ fmtDate(record.createdAt) }}</template>
        <template #actor="{ record }">
          <div class="actor">
            <span class="actor-name">{{ record.actorName || '—' }}</span>
            <a-tag v-if="record.actorRole" size="small" bordered>{{ record.actorRole }}</a-tag>
          </div>
        </template>
        <template #module="{ record }">
          <a-tag size="small" bordered>{{ auditModuleLabel(record.module) }}</a-tag>
        </template>
        <template #action="{ record }">
          <span class="mono">{{ record.action }}</span>
        </template>
        <template #target="{ record }">
          <span v-if="record.targetName || record.targetId">
            {{ record.targetName || '—' }}
            <span v-if="record.targetId" class="dim">#{{ record.targetId }}</span>
          </span>
          <span v-else class="dim">—</span>
        </template>
        <template #result="{ record }">
          <a-tag :color="auditResultMeta(record.result).color" size="small">
            {{ auditResultMeta(record.result).label }}
          </a-tag>
        </template>
        <template #empty>
          <a-empty description="无匹配审计记录" />
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<style scoped>
.audit-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
}
.page-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.filter-card {
  margin-bottom: 16px;
}
.filter-card :deep(.arco-card-body) {
  padding: 16px;
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
.mono {
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
  font-size: 12px;
}
.actor {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.actor-name {
  color: var(--brand-text);
}
</style>
