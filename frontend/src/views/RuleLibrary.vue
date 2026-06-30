<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Message, type TableData } from '@arco-design/web-vue'
import { IconBook, IconRefresh, IconFilter } from '@arco-design/web-vue/es/icon'
import { ruleApi } from '@/api'
import type { RuleQuery, RuleStats, ScanRule } from '@/api/types'
import { layerLabel } from '@/utils/format'
import CoverageMatrix from '@/components/CoverageMatrix.vue'

const tab = ref<'rules' | 'coverage'>('rules')

const loading = ref(false)
const rules = ref<ScanRule[]>([])
const stats = ref<RuleStats | null>(null)

const filters = reactive<RuleQuery>({
  layer: '',
  priority: '',
  risk: '',
  method: '',
})

// 详情抽屉
const drawerOpen = ref(false)
const active = ref<ScanRule | null>(null)

const columns = [
  { title: '规则号', slotName: 'ruleId', width: 110 },
  { title: '层级', slotName: 'layer', width: 84 },
  { title: '检查项', slotName: 'checkItem', minWidth: 180, ellipsis: true, tooltip: true },
  { title: '算法特征', dataIndex: 'algoFeature', minWidth: 180, ellipsis: true, tooltip: true },
  { title: '推荐工具', dataIndex: 'tools', width: 170, ellipsis: true, tooltip: true },
  { title: '风险', slotName: 'risk', width: 90, align: 'center' as const },
  { title: '优先级', slotName: 'priority', width: 90, align: 'center' as const },
  { title: '发现方式', slotName: 'methods', minWidth: 150 },
  { title: '状态', slotName: 'enabled', width: 80, align: 'center' as const },
]

/** 层级徽标配色（L1→蓝 / L2→青 / L3→紫 / L4→金）。 */
function layerColor(layer: string): string {
  switch (layer) {
    case 'L1':
      return 'arcoblue'
    case 'L2':
      return 'cyan'
    case 'L3':
      return 'purple'
    case 'L4':
      return 'gold'
    default:
      return 'gray'
  }
}

/** 风险提示三色（极高=红 / 高=橙 / 中=金，暖橙暖色体系）。 */
function riskColor(risk: string): string {
  switch (risk) {
    case '极高':
      return 'red'
    case '高':
      return 'orange'
    case '中':
      return 'gold'
    default:
      return 'gray'
  }
}

/** 优先级三色（P1=红 / P2=橙 / P3=灰）。 */
function priorityColor(p: string): string {
  switch (p) {
    case 'P1':
      return 'red'
    case 'P2':
      return 'orange'
    case 'P3':
      return 'gray'
    default:
      return 'gray'
  }
}

const statCards = computed(() => {
  const s = stats.value
  return [
    { key: 'total', label: '检查项总数', value: s?.total ?? 0, color: '#1D2129' },
    { key: 'p1', label: 'P1 高优规则', value: s?.p1High ?? 0, color: '#cb4b3f' },
    { key: 'critical', label: '极高风险规则', value: s?.critical ?? 0, color: '#cb4b3f' },
  ]
})

const byLayerChips = computed(() => {
  const b = stats.value?.byLayer
  if (!b) return []
  return [
    { layer: 'L1', count: b.L1 },
    { layer: 'L2', count: b.L2 },
    { layer: 'L3', count: b.L3 },
    { layer: 'L4', count: b.L4 },
  ]
})

async function load() {
  loading.value = true
  try {
    const params: RuleQuery = {}
    if (filters.layer) params.layer = filters.layer
    if (filters.priority) params.priority = filters.priority
    if (filters.risk) params.risk = filters.risk
    if (filters.method) params.method = filters.method
    const resp = await ruleApi.list(params)
    rules.value = resp.items ?? []
    // 统计头仅在无筛选时落库为权威值；带筛选也接受后端返回的 stats。
    if (resp.stats) stats.value = resp.stats
  } catch {
    Message.error('加载规则库失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

/** 「仅极高」快捷筛选。 */
function onlyCritical() {
  filters.layer = ''
  filters.priority = ''
  filters.method = ''
  filters.risk = filters.risk === '极高' ? '' : '极高'
  load()
}

function resetFilters() {
  filters.layer = ''
  filters.priority = ''
  filters.risk = ''
  filters.method = ''
  load()
}

function openDetail(record: TableData) {
  active.value = record as ScanRule
  drawerOpen.value = true
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1 class="page-title">规则库</h1>
      <p class="page-subtitle">
        内置 30 条密码学发现规则（L1 应用/会话 · L2 协议/传输 · L3 数据存储 · L4 硬件/根信任），
        每条规则定义检查项、目标算法特征、推荐工具与综合风险提示，扫描结果按规则命中标注、可追溯。
      </p>
    </div>

    <!-- 统计头 -->
    <div class="stat-row">
      <div
        v-for="c in statCards"
        :key="c.key"
        class="stat-cell"
        :style="{ borderTopColor: c.color }"
      >
        <div class="stat-value" :style="{ color: c.color }">{{ c.value }}</div>
        <div class="stat-label">{{ c.label }}</div>
      </div>
      <div class="stat-cell layer-cell">
        <div class="layer-chips">
          <a-tag
            v-for="l in byLayerChips"
            :key="l.layer"
            :color="layerColor(l.layer)"
            size="small"
          >
            {{ l.layer }} · {{ l.count }}
          </a-tag>
        </div>
        <div class="stat-label">按层级分布</div>
      </div>
    </div>

    <a-tabs v-model:active-key="tab" class="rule-tabs">
      <a-tab-pane key="rules" title="规则清单">
    <!-- 筛选条 -->
    <a-card class="filter-card">
      <a-row :gutter="12" align="center">
        <a-col flex="auto">
          <a-radio-group
            v-model="filters.layer"
            type="button"
            size="small"
            @change="load"
          >
            <a-radio value="">全部层级</a-radio>
            <a-radio value="L1">L1</a-radio>
            <a-radio value="L2">L2</a-radio>
            <a-radio value="L3">L3</a-radio>
            <a-radio value="L4">L4</a-radio>
          </a-radio-group>
        </a-col>
        <a-col flex="150px">
          <a-select v-model="filters.risk" placeholder="风险" allow-clear @change="load">
            <a-option value="极高">极高</a-option>
            <a-option value="高">高</a-option>
            <a-option value="中">中</a-option>
          </a-select>
        </a-col>
        <a-col flex="150px">
          <a-select v-model="filters.priority" placeholder="优先级" allow-clear @change="load">
            <a-option value="P1">P1</a-option>
            <a-option value="P2">P2</a-option>
            <a-option value="P3">P3</a-option>
          </a-select>
        </a-col>
        <a-col flex="150px">
          <a-select v-model="filters.method" placeholder="发现方式" allow-clear @change="load">
            <a-option value="M1">M1 主动</a-option>
            <a-option value="M2">M2 被动</a-option>
            <a-option value="M3">M3 Agent</a-option>
            <a-option value="M4">M4 SBOM</a-option>
            <a-option value="M5">M5 证书</a-option>
            <a-option value="M6">M6 配置</a-option>
            <a-option value="M7">M7 手录</a-option>
          </a-select>
        </a-col>
        <a-col flex="220px">
          <a-space>
            <a-button
              size="small"
              :type="filters.risk === '极高' ? 'primary' : 'outline'"
              status="danger"
              @click="onlyCritical"
            >
              <template #icon><IconFilter /></template>
              仅极高
            </a-button>
            <a-button size="small" @click="resetFilters">重置</a-button>
          </a-space>
        </a-col>
      </a-row>
    </a-card>

    <!-- 规则表 -->
    <a-card class="block-card">
      <template #title>
        <span class="card-title-icon">
          <IconBook /> 规则清单
          <span class="muted">（{{ rules.length }} 条）</span>
        </span>
      </template>
      <template #extra>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
          刷新
        </a-button>
      </template>
      <a-table
        :data="rules"
        :columns="columns"
        :loading="loading"
        :pagination="{ pageSize: 12, showTotal: true, hideOnSinglePage: false }"
        row-key="ruleId"
        :scroll="{ x: 1100 }"
        @row-click="openDetail"
      >
        <template #ruleId="{ record }">
          <a-link @click.stop="openDetail(record)">
            <span class="mono">{{ record.ruleId }}</span>
          </a-link>
        </template>
        <template #layer="{ record }">
          <a-tag :color="layerColor(record.layer)" size="small">{{ record.layer }}</a-tag>
        </template>
        <template #checkItem="{ record }">{{ record.checkItem }}</template>
        <template #risk="{ record }">
          <a-tag :color="riskColor(record.riskHint)" size="small">{{ record.riskHint }}</a-tag>
        </template>
        <template #priority="{ record }">
          <a-tag :color="priorityColor(record.priority)" size="small" bordered>
            {{ record.priority }}
          </a-tag>
        </template>
        <template #methods="{ record }">
          <a-space wrap :size="4">
            <a-tag
              v-for="m in record.methods"
              :key="m"
              size="small"
              bordered
              class="method-tag"
            >
              {{ m }}
            </a-tag>
            <span v-if="!record.methods?.length" class="dim">—</span>
          </a-space>
        </template>
        <template #enabled="{ record }">
          <a-tag :color="record.enabled ? 'green' : 'gray'" size="small">
            {{ record.enabled ? '启用' : '停用' }}
          </a-tag>
        </template>
        <template #empty>
          <a-empty description="无匹配规则，调整筛选" />
        </template>
      </a-table>
    </a-card>
      </a-tab-pane>

      <a-tab-pane key="coverage" title="覆盖度矩阵">
        <CoverageMatrix v-if="tab === 'coverage'" />
      </a-tab-pane>
    </a-tabs>

    <!-- 规则详情抽屉 -->
    <a-drawer
      v-model:visible="drawerOpen"
      :width="520"
      :footer="false"
      :title="active?.ruleId ?? '规则详情'"
    >
      <template v-if="active">
        <div class="rule-banner">
          <div class="rule-banner-id mono">{{ active.ruleId }}</div>
          <a-space>
            <a-tag :color="layerColor(active.layer)" size="medium">{{ active.layer }}</a-tag>
            <a-tag :color="riskColor(active.riskHint)" size="medium">{{ active.riskHint }}</a-tag>
            <a-tag :color="priorityColor(active.priority)" size="medium" bordered>
              {{ active.priority }}
            </a-tag>
          </a-space>
        </div>
        <a-descriptions :column="1" bordered size="medium" class="rule-desc">
          <a-descriptions-item label="检查项">{{ active.checkItem }}</a-descriptions-item>
          <a-descriptions-item label="所属层级">{{ layerLabel(active.layer) }}</a-descriptions-item>
          <a-descriptions-item label="目标算法特征">{{ active.algoFeature || '—' }}</a-descriptions-item>
          <a-descriptions-item label="推荐工具">{{ active.tools || '—' }}</a-descriptions-item>
          <a-descriptions-item label="默认发现方式">
            <a-space wrap :size="4">
              <a-tag v-for="m in active.methods" :key="m" size="small" bordered>{{ m }}</a-tag>
              <span v-if="!active.methods?.length">—</span>
            </a-space>
          </a-descriptions-item>
          <a-descriptions-item label="规则类型">
            <a-tag :color="active.builtin ? 'arcoblue' : 'green'" size="small">
              {{ active.builtin ? '内置（只可禁用）' : '自定义' }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="启用状态">
            <a-tag :color="active.enabled ? 'green' : 'gray'" size="small">
              {{ active.enabled ? '启用' : '停用' }}
            </a-tag>
          </a-descriptions-item>
        </a-descriptions>
      </template>
    </a-drawer>
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
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
}
.method-tag {
  font-size: 11px;
}

/* 统计头 */
.stat-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 16px;
}
.stat-cell {
  border-top: 3px solid var(--brand-border);
  background: linear-gradient(160deg, #FFFFFF 0%, #f8efe6 100%);
  border: 1px solid var(--brand-border);
  border-radius: 10px;
  padding: 14px 16px;
  text-align: center;
}
.stat-value {
  font-size: 28px;
  font-weight: 800;
  line-height: 1;
}
.stat-label {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 8px;
}
.layer-cell {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}
.layer-chips {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: center;
}

/* 筛选条 */
.filter-card {
  margin-bottom: 16px;
}
.filter-card :deep(.arco-card-body) {
  padding: 14px 16px;
}

/* 详情抽屉 */
.rule-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #E8F3FF, #F2F3F5);
  border: 1px solid var(--brand-border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 18px;
}
.rule-banner-id {
  font-size: 18px;
  font-weight: 800;
  color: var(--brand-accent);
}
.rule-desc :deep(.arco-descriptions-item-label) {
  background: var(--brand-bg-soft);
  width: 120px;
}
</style>
