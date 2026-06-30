<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { Message } from '@arco-design/web-vue'
import { marked } from 'marked'
import { IconFile, IconRefresh, IconBook } from '@arco-design/web-vue/es/icon'
import { reportApi } from '@/api'
import type { Report } from '@/api/types'
import { fmtDate } from '@/utils/format'

const loading = ref(false)
const generating = ref(false)
const reports = ref<Report[]>([])
const active = ref<Report | null>(null)
const scope = ref('')

marked.setOptions({ breaks: true, gfm: true })

const renderedHtml = computed(() => {
  if (!active.value?.markdown) return ''
  return marked.parse(active.value.markdown) as string
})

async function loadList() {
  loading.value = true
  try {
    reports.value = await reportApi.list()
    if (!active.value && reports.value.length) {
      await openReport(reports.value[0])
    }
  } catch {
    Message.error('加载报告列表失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function openReport(r: Report) {
  active.value = r
  // 列表项可能不含完整 markdown，按 id 拉详情。
  if (!r.markdown) {
    try {
      active.value = await reportApi.get(r.id)
    } catch {
      Message.error('加载报告详情失败')
    }
  }
}

async function generate() {
  generating.value = true
  try {
    const r = await reportApi.create(scope.value ? { scope: scope.value } : {})
    Message.success('摸底报告已生成')
    active.value = r
    await loadList()
  } catch {
    Message.error('生成报告失败')
  } finally {
    generating.value = false
  }
}
function isActive(r: Report) {
  return active.value?.id === r.id
}

onMounted(loadList)
</script>

<template>
  <div class="page">
    <div class="page-header reports-head">
      <div>
        <h1 class="page-title">摸底报告</h1>
        <p class="page-subtitle">
          一键生成后量子迁移摸底报告（密码学资产盘点 · 五维风险分布 · 迁移优先级建议）。
        </p>
      </div>
      <a-space>
        <a-input
          v-model="scope"
          placeholder="可选：限定范围（系统/部门）"
          allow-clear
          style="width: 220px"
        />
        <a-button type="primary" :loading="generating" @click="generate">
          <template #icon><IconFile /></template>
          生成摸底报告
        </a-button>
      </a-space>
    </div>

    <a-row :gutter="16">
      <!-- 历史报告列表 -->
      <a-col :xs="24" :lg="7">
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconBook /> 历史报告</span>
          </template>
          <template #extra>
            <a-button size="mini" type="text" :loading="loading" @click="loadList">
              <template #icon><IconRefresh /></template>
            </a-button>
          </template>
          <a-spin :loading="loading" style="width: 100%">
            <div v-if="!reports.length" class="empty-inline">
              <a-empty description="暂无报告，点右上角生成第一份" />
            </div>
            <div v-else class="report-list">
              <div
                v-for="r in reports"
                :key="r.id"
                class="report-item"
                :class="{ 'report-item--active': isActive(r) }"
                @click="openReport(r)"
              >
                <div class="report-item-title">{{ r.title || `报告 #${r.id}` }}</div>
                <div class="report-item-meta">{{ fmtDate(r.createdAt) }}</div>
              </div>
            </div>
          </a-spin>
        </a-card>
      </a-col>

      <!-- 报告正文 -->
      <a-col :xs="24" :lg="17">
        <a-card class="block-card">
          <template #title>{{ active?.title ?? '报告预览' }}</template>
          <template v-if="active" #extra>
            <span class="muted">{{ fmtDate(active.createdAt) }}</span>
          </template>
          <div v-if="!active" class="empty-inline">
            <a-empty description="左侧选择或生成一份报告以预览" />
          </div>
          <!-- eslint-disable-next-line vue/no-v-html -->
          <div v-else class="markdown-body" v-html="renderedHtml" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.reports-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}
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
}
.empty-inline {
  padding: 28px 0;
}

.report-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.report-item {
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 10px 12px;
  cursor: pointer;
  transition: all 0.18s;
  background: #FFFFFF;
}
.report-item:hover {
  border-color: var(--brand-accent-2);
}
.report-item--active {
  border-color: var(--brand-accent);
  background: #E8F3FF;
}
.report-item-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--brand-text);
  line-height: 1.3;
}
.report-item-meta {
  font-size: 11px;
  color: var(--brand-text-soft);
  margin-top: 4px;
}

/* markdown 渲染暖色排版 */
.markdown-body {
  color: var(--brand-text);
  line-height: 1.7;
  font-size: 14px;
  max-width: 100%;
  overflow-x: auto;
}
.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3) {
  color: var(--brand-text);
  font-weight: 700;
  margin: 1.2em 0 0.6em;
}
.markdown-body :deep(h1) {
  font-size: 22px;
  border-bottom: 2px solid var(--brand-border);
  padding-bottom: 8px;
}
.markdown-body :deep(h2) {
  font-size: 18px;
}
.markdown-body :deep(h3) {
  font-size: 15px;
}
.markdown-body :deep(a) {
  color: var(--brand-accent);
}
.markdown-body :deep(code) {
  background: var(--brand-bg-soft);
  border-radius: 4px;
  padding: 2px 6px;
  font-size: 13px;
}
.markdown-body :deep(pre) {
  background: #1D2129;
  color: #F2F3F5;
  border-radius: 10px;
  padding: 14px 16px;
  overflow-x: auto;
}
.markdown-body :deep(pre code) {
  background: transparent;
  color: inherit;
  padding: 0;
}
.markdown-body :deep(table) {
  border-collapse: collapse;
  width: 100%;
  margin: 14px 0;
}
.markdown-body :deep(th),
.markdown-body :deep(td) {
  border: 1px solid var(--brand-border);
  padding: 8px 12px;
  text-align: left;
}
.markdown-body :deep(th) {
  background: var(--brand-bg-soft);
  font-weight: 600;
}
.markdown-body :deep(blockquote) {
  border-left: 4px solid var(--brand-accent-2);
  margin: 12px 0;
  padding: 4px 16px;
  color: var(--brand-text-soft);
  background: var(--brand-bg-soft);
  border-radius: 0 8px 8px 0;
}
.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  padding-left: 22px;
}
</style>
