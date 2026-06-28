<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconDownload, IconThunderbolt, IconExperiment } from '@arco-design/web-vue/es/icon'
import { registerApi, profileApi } from '@/api'
import type { RegisterQuery, RegisterRow, ScoreProfile, ScoreProfileInput, RescoreResult } from '@/api/types'
import { levelColor, levelText } from '@/utils/format'

// ---- 风险登记册 ----
const loading = ref(false)
const rescoring = ref(false)
const exporting = ref(false)
const rows = ref<RegisterRow[]>([])
const filters = reactive<RegisterQuery>({ priority: '', hndl: '', layer: '', q: '' })

const columns = [
  { title: '资产', slotName: 'name', minWidth: 170 },
  { title: '系统', dataIndex: 'system', width: 130, ellipsis: true, tooltip: true },
  { title: '层级', dataIndex: 'layer', width: 70 },
  { title: '算法', dataIndex: 'algorithm', width: 120 },
  { title: '综合分', slotName: 'score', width: 80, align: 'center' as const },
  { title: '分级', slotName: 'level', width: 90, align: 'center' as const },
  { title: 'HNDL', slotName: 'hndl', width: 70, align: 'center' as const },
  { title: '建议迁移', dataIndex: 'suggestedAlgo', width: 200, ellipsis: true, tooltip: true },
]

async function load() {
  loading.value = true
  try {
    const q: RegisterQuery = {}
    if (filters.priority) q.priority = filters.priority
    if (filters.hndl) q.hndl = filters.hndl
    if (filters.layer) q.layer = filters.layer
    if (filters.q) q.q = filters.q
    rows.value = await registerApi.list(q)
  } catch {
    Message.error('加载风险登记册失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function rescore() {
  rescoring.value = true
  try {
    const r = await registerApi.rescore({ scope: 'all' })
    Message.success(`批量复算完成：更新 ${r.updated} 项${r.run ? `，迁移 ${r.run.shifted}` : ''}`)
    await load()
    await loadProfiles()
  } catch {
    Message.error('批量复算失败')
  } finally {
    rescoring.value = false
  }
}

async function exportCsv() {
  exporting.value = true
  try {
    const blob = await registerApi.exportCsv(filters)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `zhulong-pqm-risk-register-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url)
    Message.success('风险登记册已导出 CSV')
  } catch {
    Message.error('导出 CSV 失败')
  } finally {
    exporting.value = false
  }
}

// ---- 专家模式：评分权重方案 ----
const profiles = ref<ScoreProfile[]>([])
const profileLoading = ref(false)
const formOpen = ref(false)
const form = reactive<ScoreProfileInput>({ name: '', description: '', w1: 30, w2: 25, w3: 20, w4: 15, w5: 10 })
const weightSum = computed(() => form.w1 + form.w2 + form.w3 + form.w4 + form.w5)

async function loadProfiles() {
  profileLoading.value = true
  try {
    profiles.value = await profileApi.list()
  } catch {
    /* 忽略 */
  } finally {
    profileLoading.value = false
  }
}

async function saveProfile() {
  if (!form.name.trim()) { Message.warning('请填写方案名'); return }
  if (weightSum.value !== 100) { Message.warning(`五维权重之和须为 100，当前 ${weightSum.value}`); return }
  try {
    await profileApi.create({ ...form, name: form.name.trim() })
    Message.success('权重方案已创建')
    formOpen.value = false
    Object.assign(form, { name: '', description: '', w1: 30, w2: 25, w3: 20, w4: 15, w5: 10 })
    await loadProfiles()
  } catch {
    Message.error('创建方案失败（名称重复或权重非法）')
  }
}

function describeShift(r: RescoreResult): string {
  return `P1 ${r.before.p1}→${r.after.p1} · P2 ${r.before.p2}→${r.after.p2} · P3 ${r.before.p3}→${r.after.p3} · P4 ${r.before.p4}→${r.after.p4}（迁移 ${r.shifted}）`
}

async function activate(p: ScoreProfile) {
  try {
    const r = await profileApi.activate(p.id)
    Message.success(`已激活「${p.name}」并全量复算：${describeShift(r)}`)
    await loadProfiles()
    await load()
  } catch {
    Message.error('激活方案失败')
  }
}

const dims = [
  { k: 'w1', label: 'D1 算法脆弱性' },
  { k: 'w2', label: 'D2 数据敏感度' },
  { k: 'w3', label: 'D3 数据生命周期' },
  { k: 'w4', label: 'D4 迁移复杂度' },
  { k: 'w5', label: 'D5 暴露面' },
] as const

onMounted(() => { load(); loadProfiles() })
</script>

<template>
  <div class="page">
    <div class="page-header reg-head">
      <div>
        <h1 class="page-title">风险登记册</h1>
        <p class="page-subtitle">P1 优先 / HNDL 专项的密码使用点风险台账，支持专家模式调权与批量复算、CSV 导出。</p>
      </div>
      <a-space>
        <a-button :loading="rescoring" @click="rescore"><template #icon><IconThunderbolt /></template>批量复算</a-button>
        <a-button type="primary" :loading="exporting" @click="exportCsv"><template #icon><IconDownload /></template>导出 CSV</a-button>
      </a-space>
    </div>

    <!-- 专家模式：评分权重方案 -->
    <a-card class="block-card">
      <template #title><IconExperiment /> 评分权重方案（专家模式 · 默认锁 30/25/20/15/10）</template>
      <template #extra><a-button size="small" @click="formOpen = true">新建方案</a-button></template>
      <a-spin :loading="profileLoading" style="width: 100%">
        <a-space wrap>
          <div v-for="p in profiles" :key="p.id" class="profile-chip" :class="{ active: p.isActive }">
            <div class="pc-name">
              {{ p.name }}
              <a-tag v-if="p.isBuiltin" size="small">内置</a-tag>
              <a-tag v-if="p.isActive" size="small" color="green">生效中</a-tag>
            </div>
            <div class="pc-w">{{ p.w1 }}/{{ p.w2 }}/{{ p.w3 }}/{{ p.w4 }}/{{ p.w5 }}</div>
            <a-button v-if="!p.isActive" size="mini" type="outline" @click="activate(p)">激活并复算</a-button>
          </div>
          <a-empty v-if="!profiles.length" description="暂无方案" />
        </a-space>
      </a-spin>
    </a-card>

    <!-- 筛选 -->
    <a-card class="filter-card">
      <a-row :gutter="12" align="center">
        <a-col flex="140px">
          <a-select v-model="filters.priority" placeholder="优先级" allow-clear @change="load">
            <a-option value="P1">P1 极高</a-option><a-option value="P2">P2 高</a-option>
            <a-option value="P3">P3 中</a-option><a-option value="P4">P4 低</a-option>
          </a-select>
        </a-col>
        <a-col flex="120px">
          <a-select v-model="filters.hndl" placeholder="HNDL" allow-clear @change="load">
            <a-option value="true">仅 HNDL</a-option>
          </a-select>
        </a-col>
        <a-col flex="140px">
          <a-select v-model="filters.layer" placeholder="层级" allow-clear @change="load">
            <a-option value="L1">L1</a-option><a-option value="L2">L2</a-option>
            <a-option value="L3">L3</a-option><a-option value="L4">L4</a-option>
          </a-select>
        </a-col>
        <a-col flex="auto">
          <a-input v-model="filters.q" placeholder="按名称/系统/算法搜索" allow-clear @press-enter="load" @clear="load" />
        </a-col>
        <a-col flex="120px"><a-button type="primary" :loading="loading" long @click="load">查询</a-button></a-col>
      </a-row>
    </a-card>

    <a-card class="block-card">
      <template #title>登记明细 <span class="muted">（{{ rows.length }} 项）</span></template>
      <template #extra><a-button size="small" :loading="loading" @click="load"><template #icon><IconRefresh /></template>刷新</a-button></template>
      <a-table :data="rows" :columns="columns" :loading="loading" :pagination="{ pageSize: 14, showTotal: true }" row-key="id" :scroll="{ x: 940 }">
        <template #name="{ record }">
          <span :class="{ 'p1-row': record.riskLevel === 'P1' }">{{ record.name }}</span>
        </template>
        <template #score="{ record }"><strong>{{ record.riskScore }}</strong></template>
        <template #level="{ record }">
          <a-tag :color="levelColor(record.riskLevel)" size="small">{{ record.riskLevel }} {{ record.riskLevelText || levelText(record.riskLevel) }}</a-tag>
        </template>
        <template #hndl="{ record }">
          <a-tag v-if="record.hndl" color="red" size="small">HNDL</a-tag><span v-else class="muted">—</span>
        </template>
        <template #empty><a-empty description="无匹配资产" /></template>
      </a-table>
    </a-card>

    <!-- 新建方案 -->
    <a-modal v-model:visible="formOpen" title="新建评分权重方案" @ok="saveProfile" :ok-text="`保存（Σ=${weightSum}）`" :ok-button-props="{ disabled: weightSum !== 100 }">
      <a-form :model="form" layout="vertical">
        <a-form-item label="方案名"><a-input v-model="form.name" placeholder="如：金融行业偏 HNDL" /></a-form-item>
        <a-form-item label="说明"><a-input v-model="form.description" placeholder="可选" /></a-form-item>
        <a-form-item v-for="d in dims" :key="d.k" :label="d.label">
          <a-input-number v-model="form[d.k]" :min="0" :max="100" :step="5" style="width: 160px" />
        </a-form-item>
        <a-alert :type="weightSum === 100 ? 'success' : 'warning'">五维权重之和：{{ weightSum }} / 100</a-alert>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.reg-head { display: flex; align-items: flex-end; justify-content: space-between; }
.filter-card { margin: 16px 0; }
.filter-card :deep(.arco-card-body) { padding: 16px; }
.block-card { margin-top: 16px; }
.muted { font-size: 12px; color: var(--clay-text-soft); font-weight: 400; }
.p1-row { color: var(--clay-accent); font-weight: 600; }
.profile-chip {
  border: 1px solid var(--clay-border); border-radius: 10px; padding: 10px 14px;
  background: #fffdfa; min-width: 180px;
}
.profile-chip.active { border-color: var(--clay-accent); background: #fbeee2; }
.pc-name { font-size: 13px; font-weight: 600; color: var(--clay-text); }
.pc-w { font-size: 12px; color: var(--clay-text-soft); margin: 4px 0 8px; font-variant-numeric: tabular-nums; }
</style>
