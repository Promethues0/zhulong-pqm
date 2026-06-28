<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconPlus,
  IconCloudDownload,
  IconThunderbolt,
} from '@arco-design/web-vue/es/icon'
import { intelApi } from '@/api'
import type { ThreatIntel, ThreatIntelInput } from '@/api/types'
import {
  fmtDay,
  intelSourceMeta,
  intelCategoryMeta,
} from '@/utils/format'

/** 量子威胁情报流：列表 + 手工录入 + 一键拉取；TriggerReassess 命中标橙。 */
const loading = ref(false)
const pulling = ref(false)
const submitting = ref(false)
const items = ref<ThreatIntel[]>([])

const formOpen = ref(false)
const form = reactive<ThreatIntelInput>({
  source: 'manual',
  category: 'standard_update',
  title: '',
  summary: '',
  affectedAlgos: [],
  qubitCount: undefined,
  triggerReassess: false,
})

const emit = defineEmits<{ (e: 'reassessed'): void }>()

function resetForm() {
  form.source = 'manual'
  form.category = 'standard_update'
  form.title = ''
  form.summary = ''
  form.affectedAlgos = []
  form.qubitCount = undefined
  form.triggerReassess = false
}

async function load() {
  loading.value = true
  try {
    items.value = await intelApi.list()
  } catch {
    Message.error('加载威胁情报失败')
  } finally {
    loading.value = false
  }
}

async function pull() {
  pulling.value = true
  try {
    const r = await intelApi.pull()
    Message.success(
      `情报拉取完成：入库 ${r.ingested ?? 0} 条${
        r.reassessed ? `，触发复评 ${r.reassessed} 资产` : ''
      }`,
    )
    if (r.reassessed) emit('reassessed')
    await load()
  } catch {
    Message.error('情报拉取失败')
  } finally {
    pulling.value = false
  }
}

function openForm() {
  resetForm()
  formOpen.value = true
}

async function submit() {
  if (!form.title.trim()) {
    Message.warning('请填写情报标题')
    return
  }
  submitting.value = true
  try {
    const created = await intelApi.create({
      ...form,
      title: form.title.trim(),
    })
    Message.success(
      created.triggerReassess
        ? '情报已录入，已触发命中资产复评回流'
        : '情报已录入',
    )
    if (created.triggerReassess) emit('reassessed')
    formOpen.value = false
    await load()
  } catch {
    Message.error('情报录入失败')
  } finally {
    submitting.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<template>
  <a-card class="block-card">
    <template #title>
      <span class="card-title-icon">
        <IconThunderbolt /> 量子威胁情报
        <span class="muted">（{{ items.length }} 条）</span>
      </span>
    </template>
    <template #extra>
      <a-space>
        <a-button size="small" type="primary" @click="openForm">
          <template #icon><IconPlus /></template>
          录入
        </a-button>
        <a-button size="small" :loading="pulling" @click="pull">
          <template #icon><IconCloudDownload /></template>
          一键拉取
        </a-button>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
        </a-button>
      </a-space>
    </template>

    <a-spin :loading="loading" style="width: 100%">
      <a-empty v-if="!items.length" description="暂无情报，点击「一键拉取」导入离线情报包" />
      <div v-else class="feed">
        <div v-for="it in items" :key="it.id" class="intel-item">
          <div class="intel-head">
            <a-space :size="6" wrap>
              <a-tag :color="intelSourceMeta(it.source).color" size="small">
                {{ intelSourceMeta(it.source).label }}
              </a-tag>
              <a-tag :color="intelCategoryMeta(it.category).color" size="small" bordered>
                {{ intelCategoryMeta(it.category).label }}
              </a-tag>
              <a-tag v-if="it.triggerReassess" color="orange" size="small">
                <template #icon><IconThunderbolt /></template>
                已触发复评
              </a-tag>
            </a-space>
            <span class="intel-time">{{ fmtDay(it.publishedAt || it.ingestedAt) }}</span>
          </div>
          <div class="intel-title">{{ it.title }}</div>
          <div v-if="it.summary" class="intel-summary">{{ it.summary }}</div>
          <div class="intel-meta">
            <a-space :size="4" wrap>
              <span v-if="it.affectedAlgos?.length" class="meta-label">受影响算法：</span>
              <a-tag
                v-for="a in it.affectedAlgos ?? []"
                :key="a"
                size="small"
                class="algo-tag"
              >
                {{ a }}
              </a-tag>
              <a-tag v-if="it.qubitCount" color="purple" size="small">
                {{ it.qubitCount }} 逻辑比特
              </a-tag>
            </a-space>
          </div>
        </div>
      </div>
    </a-spin>

    <!-- 录入抽屉 -->
    <a-modal
      v-model:visible="formOpen"
      title="录入威胁情报"
      :ok-loading="submitting"
      ok-text="录入"
      @ok="submit"
    >
      <a-form :model="form" layout="vertical">
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item label="情报源">
              <a-select v-model="form.source">
                <a-option value="NIST">NIST</a-option>
                <a-option value="国密局">国密局</a-option>
                <a-option value="学界里程碑">学界里程碑</a-option>
                <a-option value="manual">手工录入</a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item label="类别">
              <a-select v-model="form.category">
                <a-option value="standard_update">标准更新</a-option>
                <a-option value="algo_break">算法攻破</a-option>
                <a-option value="algo_deprecate">算法弃用</a-option>
                <a-option value="qubit_milestone">量子比特里程碑</a-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="标题" required>
          <a-input v-model="form.title" placeholder="如：NIST 正式弃用 RSA-2048" />
        </a-form-item>
        <a-form-item label="摘要">
          <a-textarea
            v-model="form.summary"
            :auto-size="{ minRows: 2, maxRows: 4 }"
            placeholder="情报详情"
          />
        </a-form-item>
        <a-row :gutter="12">
          <a-col :span="14">
            <a-form-item label="受影响算法族">
              <a-input-tag
                v-model="form.affectedAlgos"
                placeholder="回车添加：RSA / ECDSA / SM2"
                allow-clear
              />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item label="逻辑比特数">
              <a-input-number
                v-model="form.qubitCount"
                :min="0"
                placeholder="如 4000"
              />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item>
          <a-checkbox v-model="form.triggerReassess">
            映射为复评触发（命中算法的资产将批量重评分回流）
          </a-checkbox>
        </a-form-item>
      </a-form>
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
.feed {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-height: 520px;
  overflow-y: auto;
}
.intel-item {
  border: 1px solid var(--clay-border);
  border-left: 3px solid var(--clay-accent-2);
  border-radius: 10px;
  padding: 12px 14px;
  background: #fffdfa;
}
.intel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}
.intel-time {
  font-size: 11px;
  color: var(--clay-text-soft);
  flex-shrink: 0;
}
.intel-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
  margin-top: 8px;
}
.intel-summary {
  font-size: 13px;
  color: var(--clay-text-soft);
  margin-top: 4px;
  line-height: 1.5;
}
.intel-meta {
  margin-top: 10px;
}
.meta-label {
  font-size: 12px;
  color: var(--clay-text-soft);
}
.algo-tag {
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
}
</style>
