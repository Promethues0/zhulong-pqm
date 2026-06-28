<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Message } from '@arco-design/web-vue'
import {
  IconArchive,
  IconRefresh,
  IconSwap,
  IconHistory,
  IconArrowRise,
  IconArrowFall,
  IconApps,
} from '@arco-design/web-vue/es/icon'
import { snapshotApi } from '@/api'
import type { CbomSnapshot, SnapshotDiff } from '@/api/types'
import { fmtDate } from '@/utils/format'

const loading = ref(false)
const snapshots = ref<CbomSnapshot[]>([])

// 冻结新快照
const freezeOpen = ref(false)
const freezing = ref(false)
const freezeForm = reactive({ name: '', scope: '' })

// 对比
const base = ref<number | undefined>(undefined)
const target = ref<number | undefined>(undefined)
// 对比选择表单为纯布局（v-model 直绑 ref），a-form 仍需 model 占位。
const diffFormModel = reactive({})
const diffing = ref(false)
const diff = ref<SnapshotDiff | null>(null)

const columns = [
  { title: '快照名', slotName: 'name', minWidth: 180 },
  { title: '版本', dataIndex: 'version', width: 80, align: 'center' as const },
  { title: '范围', slotName: 'scope', width: 150, ellipsis: true, tooltip: true },
  { title: '资产数', dataIndex: 'assetCount', width: 90, align: 'right' as const },
  { title: '触发', slotName: 'trigger', width: 100 },
  { title: '创建人', dataIndex: 'createdBy', width: 110 },
  { title: '冻结时间', slotName: 'time', width: 170 },
]

const changedColumns = [
  { title: '资产', dataIndex: 'name', minWidth: 160, ellipsis: true, tooltip: true },
  { title: '变更类型', slotName: 'type', width: 130 },
  { title: '原值', slotName: 'from', minWidth: 130, ellipsis: true, tooltip: true },
  { title: '新值', slotName: 'to', minWidth: 130, ellipsis: true, tooltip: true },
]

const CHANGE_TYPE: Record<string, { label: string; color: string }> = {
  algo_changed: { label: '算法变更', color: 'orange' },
  cert_rotated: { label: '证书续期', color: 'arcoblue' },
  status_changed: { label: '状态变化', color: 'gray' },
  level_changed: { label: '风险等级变化', color: 'red' },
}

function changeTypeMeta(t: string) {
  return CHANGE_TYPE[t] ?? { label: t || '变更', color: 'gray' }
}

const TRIGGER_LABEL: Record<string, string> = {
  manual: '手动',
  rescan: '复扫',
  cron: '定时',
}

const diffSummaryCards = computed(() => {
  const s = diff.value?.summary
  if (!s) return []
  return [
    { key: 'added', label: '新增', value: s.added, color: '#5a9367' },
    { key: 'removed', label: '移除', value: s.removed, color: '#6f655c' },
    { key: 'algoChanged', label: '算法变更', value: s.algoChanged, color: '#db855c' },
    { key: 'certRotated', label: '证书续期', value: s.certRotated, color: '#4b7bb5' },
    { key: 'statusChanged', label: '状态变化', value: s.statusChanged, color: '#8a7a68' },
    { key: 'levelChanged', label: '等级变化', value: s.levelChanged, color: '#cb4b3f' },
  ]
})

// 算法分布环比（排序：迁移进展算法在前/降幅在前）
const algoDeltaRows = computed(() => {
  const d = diff.value?.algoDistDelta ?? {}
  return Object.entries(d)
    .map(([algo, delta]) => ({ algo, delta }))
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta))
})

async function load() {
  loading.value = true
  try {
    snapshots.value = await snapshotApi.list()
    // 默认对比项：最早 vs 最新（列表倒序，故 base=末位、target=首位）。
    if (snapshots.value.length >= 2) {
      if (base.value == null) base.value = snapshots.value[snapshots.value.length - 1].id
      if (target.value == null) target.value = snapshots.value[0].id
    }
  } catch {
    Message.error('加载快照列表失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function freeze() {
  if (!freezeForm.name.trim()) {
    Message.warning('请填写快照名称')
    return
  }
  freezing.value = true
  try {
    await snapshotApi.create({
      name: freezeForm.name.trim(),
      scope: freezeForm.scope.trim() || undefined,
    })
    Message.success('已冻结当前 CBOM 快照')
    freezeOpen.value = false
    freezeForm.name = ''
    freezeForm.scope = ''
    await load()
  } catch {
    Message.error('冻结快照失败')
  } finally {
    freezing.value = false
  }
}

async function runDiff() {
  if (base.value == null) {
    Message.warning('请选择基线快照')
    return
  }
  if (target.value != null && target.value === base.value) {
    Message.warning('基线与目标不能为同一快照')
    return
  }
  diffing.value = true
  try {
    diff.value = await snapshotApi.diff(base.value, target.value)
  } catch {
    Message.error('快照对比失败')
  } finally {
    diffing.value = false
  }
}

function snapName(id?: number): string {
  if (id == null) return '实时'
  return snapshots.value.find((s) => s.id === id)?.name ?? `#${id}`
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header snap-head">
      <div>
        <h1 class="page-title">CBOM 快照</h1>
        <p class="page-subtitle">
          冻结某一时刻的密码学资产清单为命名快照，跨快照对比迁移进展 ——
          新增/移除资产、算法变更（标注是否为 PQC 迁移进展）、证书续期、状态与风险等级变化，以及算法分布环比。
        </p>
      </div>
      <a-button type="primary" @click="freezeOpen = true">
        <template #icon><IconArchive /></template>
        冻结当前快照
      </a-button>
    </div>

    <a-row :gutter="16">
      <!-- 快照列表 -->
      <a-col :xs="24" :lg="14">
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon">
              <IconHistory /> 快照列表
              <span class="muted">（{{ snapshots.length }} 个）</span>
            </span>
          </template>
          <template #extra>
            <a-button size="small" :loading="loading" @click="load">
              <template #icon><IconRefresh /></template>
              刷新
            </a-button>
          </template>
          <a-table
            :data="snapshots"
            :columns="columns"
            :loading="loading"
            :pagination="{ pageSize: 8, hideOnSinglePage: true }"
            row-key="id"
            :scroll="{ x: 760 }"
          >
            <template #name="{ record }">
              <span class="snap-name">{{ record.name }}</span>
            </template>
            <template #scope="{ record }">{{ record.scope || '全量' }}</template>
            <template #trigger="{ record }">
              <a-tag size="small" bordered>
                {{ TRIGGER_LABEL[record.triggeredBy] ?? record.triggeredBy ?? '手动' }}
              </a-tag>
            </template>
            <template #time="{ record }">{{ fmtDate(record.createdAt) }}</template>
            <template #empty>
              <a-empty description="暂无快照，点右上角冻结第一个 CBOM 基线" />
            </template>
          </a-table>
        </a-card>
      </a-col>

      <!-- 对比选择 -->
      <a-col :xs="24" :lg="10">
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconSwap /> 快照对比</span>
          </template>
          <a-form :model="diffFormModel" layout="vertical">
            <a-form-item label="基线快照（from）">
              <a-select v-model="base" placeholder="选择基线快照" allow-clear>
                <a-option
                  v-for="s in snapshots"
                  :key="s.id"
                  :value="s.id"
                  :label="s.name"
                />
              </a-select>
            </a-form-item>
            <a-form-item label="目标快照（to）">
              <a-select v-model="target" placeholder="留空＝与实时资产对比" allow-clear>
                <a-option
                  v-for="s in snapshots"
                  :key="s.id"
                  :value="s.id"
                  :label="s.name"
                />
              </a-select>
              <div class="field-hint">不选目标则以当前实时资产集为对照。</div>
            </a-form-item>
            <a-button
              type="primary"
              long
              :loading="diffing"
              :disabled="base == null"
              @click="runDiff"
            >
              <template #icon><IconSwap /></template>
              对比
            </a-button>
          </a-form>
        </a-card>
      </a-col>
    </a-row>

    <!-- diff 结果 -->
    <a-card v-if="diff" class="block-card">
      <template #title>
        <span class="card-title-icon">
          <IconSwap /> 对比结果
          <a-tag size="small" bordered>{{ snapName(base) }}</a-tag>
          <span class="arrow">→</span>
          <a-tag size="small" bordered>{{ snapName(target) }}</a-tag>
        </span>
      </template>

      <!-- 汇总卡 -->
      <div class="diff-summary">
        <div
          v-for="c in diffSummaryCards"
          :key="c.key"
          class="diff-cell"
          :style="{ borderTopColor: c.color }"
        >
          <div class="diff-count" :style="{ color: c.color }">{{ c.value }}</div>
          <div class="diff-label">{{ c.label }}</div>
        </div>
      </div>

      <a-row :gutter="16">
        <!-- 新增 / 移除 -->
        <a-col :xs="24" :lg="12">
          <div class="sub-title"><span class="dot-add" /> 新增资产（{{ diff.added.length }}）</div>
          <div v-if="diff.added.length" class="entry-list">
            <div v-for="e in diff.added" :key="e.key" class="entry-item entry-item--add">
              <span class="entry-name">{{ e.name }}</span>
              <a-tag v-if="e.algorithm" size="small" bordered>{{ e.algorithm }}</a-tag>
            </div>
          </div>
          <a-empty v-else description="无新增" :image-size="40" />
        </a-col>
        <a-col :xs="24" :lg="12">
          <div class="sub-title"><span class="dot-rm" /> 移除资产（{{ diff.removed.length }}）</div>
          <div v-if="diff.removed.length" class="entry-list">
            <div v-for="e in diff.removed" :key="e.key" class="entry-item entry-item--rm">
              <span class="entry-name">{{ e.name }}</span>
              <a-tag v-if="e.algorithm" size="small" bordered>{{ e.algorithm }}</a-tag>
            </div>
          </div>
          <a-empty v-else description="无移除" :image-size="40" />
        </a-col>
      </a-row>

      <!-- 变更 -->
      <div class="sub-title sub-title--mt"><IconSwap /> 内容变更（{{ diff.changed.length }}）</div>
      <a-table
        :data="diff.changed"
        :columns="changedColumns"
        :pagination="{ pageSize: 8, hideOnSinglePage: true }"
        row-key="key"
        :scroll="{ x: 600 }"
      >
        <template #type="{ record }">
          <a-space :size="4">
            <a-tag :color="changeTypeMeta(record.type).color" size="small">
              {{ changeTypeMeta(record.type).label }}
            </a-tag>
            <a-tag
              v-if="record.type === 'algo_changed' && record.isProgress"
              color="green"
              size="small"
            >
              迁移进展
            </a-tag>
          </a-space>
        </template>
        <template #from="{ record }">
          <span class="mono dim">{{ record.from || '—' }}</span>
        </template>
        <template #to="{ record }">
          <span class="mono" :class="{ progress: record.isProgress }">
            {{ record.to || '—' }}
          </span>
        </template>
        <template #empty>
          <a-empty description="无内容变更" :image-size="40" />
        </template>
      </a-table>

      <!-- 算法分布环比 -->
      <div class="sub-title sub-title--mt"><IconApps /> 算法分布环比</div>
      <div v-if="algoDeltaRows.length" class="algo-delta">
        <div v-for="row in algoDeltaRows" :key="row.algo" class="algo-row">
          <span class="algo-name mono">{{ row.algo }}</span>
          <span
            class="algo-delta-val"
            :class="row.delta < 0 ? 'down' : row.delta > 0 ? 'up' : 'flat'"
          >
            <IconArrowFall v-if="row.delta < 0" />
            <IconArrowRise v-else-if="row.delta > 0" />
            {{ row.delta > 0 ? '+' : '' }}{{ row.delta }}
          </span>
        </div>
      </div>
      <a-empty v-else description="无分布变化" :image-size="40" />
    </a-card>

    <!-- 冻结快照 modal -->
    <a-modal
      v-model:visible="freezeOpen"
      title="冻结当前 CBOM 快照"
      :ok-loading="freezing"
      ok-text="冻结"
      cancel-text="取消"
      @ok="freeze"
    >
      <a-form :model="freezeForm" layout="vertical">
        <a-form-item label="快照名称" required>
          <a-input v-model="freezeForm.name" placeholder="如 2026Q2-baseline" allow-clear />
        </a-form-item>
        <a-form-item label="冻结范围（可选）">
          <a-input
            v-model="freezeForm.scope"
            placeholder="如 layer=L1 / system=核心区，留空＝全量"
            allow-clear
          />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.block-card {
  margin-bottom: 16px;
}
.card-title-icon {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.snap-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}
.muted {
  font-size: 12px;
  color: var(--clay-text-soft);
  font-weight: 400;
}
.dim {
  color: var(--clay-text-soft);
}
.mono {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
}
.snap-name {
  font-weight: 600;
  color: var(--clay-text);
}
.field-hint {
  font-size: 12px;
  color: var(--clay-text-soft);
  margin-top: 6px;
}
.arrow {
  color: var(--clay-text-soft);
}

/* diff 汇总卡 */
.diff-summary {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
  margin-bottom: 18px;
}
.diff-cell {
  border-top: 3px solid var(--clay-border);
  background: linear-gradient(160deg, #fffdfa 0%, #f8efe6 100%);
  border: 1px solid var(--clay-border);
  border-radius: 10px;
  padding: 12px 10px;
  text-align: center;
}
.diff-count {
  font-size: 24px;
  font-weight: 800;
  line-height: 1;
}
.diff-label {
  font-size: 11px;
  color: var(--clay-text-soft);
  margin-top: 6px;
}

.sub-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
  margin-bottom: 12px;
}
.sub-title--mt {
  margin-top: 18px;
}
.dot-add,
.dot-rm {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  display: inline-block;
}
.dot-add {
  background: #5a9367;
}
.dot-rm {
  background: var(--clay-text-soft);
}

.entry-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.entry-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 7px 12px;
  border-radius: 8px;
  border-left: 3px solid var(--clay-border);
  background: var(--clay-bg-soft);
}
.entry-item--add {
  border-left-color: #5a9367;
}
.entry-item--rm {
  border-left-color: var(--clay-text-soft);
  opacity: 0.8;
}
.entry-name {
  font-size: 13px;
  color: var(--clay-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.progress {
  color: #3f7150;
  font-weight: 600;
}

/* 算法分布环比 */
.algo-delta {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 10px;
}
.algo-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border: 1px solid var(--clay-border);
  border-radius: 8px;
  background: #fffdfa;
}
.algo-name {
  font-size: 13px;
  color: var(--clay-text);
}
.algo-delta-val {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-weight: 700;
  font-size: 14px;
}
.algo-delta-val.down {
  color: #5a9367;
}
.algo-delta-val.up {
  color: #cb4b3f;
}
.algo-delta-val.flat {
  color: var(--clay-text-soft);
}
</style>
