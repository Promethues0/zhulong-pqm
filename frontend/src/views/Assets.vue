<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Message, Modal, type TableData } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconDownload,
  IconSearch,
  IconTool,
  IconPlus,
  IconEdit,
  IconDelete,
  IconBranch,
  IconImport,
  IconSafe,
  IconApps,
  IconFolder,
} from '@arco-design/web-vue/es/icon'
import { assetApi, cbomApi, groupApi } from '@/api'
import type {
  AssetByGroup,
  AssetEvidence,
  AssetGroup,
  AssetQuery,
  CryptoAsset,
} from '@/api/types'
import {
  layerLabel,
  levelColor,
  levelText,
  exposureMeta,
  fmtDay,
  fmtDate,
  certUrgency,
} from '@/utils/format'
import AssetFormDrawer from '@/components/AssetFormDrawer.vue'
import MergeModal from '@/components/MergeModal.vue'
import ScoreHistoryTimeline from '@/components/ScoreHistoryTimeline.vue'
import GroupManageModal from '@/components/GroupManageModal.vue'

const router = useRouter()
const loading = ref(false)
const exporting = ref(false)
const assets = ref<CryptoAsset[]>([])

// a-upload 自定义请求占位：用 @change 自行处理 File，不走内置上传。
const noopRequest = () => ({ abort() {} })

// ---- 新增/编辑表单抽屉 ----
const formOpen = ref(false)
const editing = ref<CryptoAsset | null>(null)

// ---- 合并重复 ----
const mergeOpen = ref(false)

// ---- 证据链 ----
const evidence = ref<AssetEvidence[]>([])
const evidenceLoading = ref(false)

// ---- 导入 CBOM ----
const importingCbom = ref(false)

function openCreate() {
  editing.value = null
  formOpen.value = true
}

function openEdit(asset: CryptoAsset) {
  editing.value = asset
  formOpen.value = true
}

function confirmDelete(asset: CryptoAsset) {
  Modal.warning({
    title: '删除资产',
    content: `确认删除「${asset.name}」？该操作不可撤销。`,
    okText: '删除',
    cancelText: '取消',
    hideCancel: false,
    onOk: async () => {
      try {
        await assetApi.remove(asset.id)
        Message.success('资产已删除')
        if (active.value?.id === asset.id) drawerOpen.value = false
        await load()
      } catch {
        Message.error('删除资产失败')
      }
    },
  })
}

async function loadEvidence(id: number) {
  evidenceLoading.value = true
  evidence.value = []
  try {
    evidence.value = await assetApi.evidence(id)
  } catch {
    /* 证据链为空也不阻断 */
  } finally {
    evidenceLoading.value = false
  }
}

function evidenceValid(e: AssetEvidence): boolean {
  // 后端可在 hash 中体现校验状态；前端仅以非空粗判。
  return !!e.hash
}

function confColor(c?: string): string {
  switch (c) {
    case '高':
      return 'green'
    case '中':
      return 'gold'
    case '低':
      return 'gray'
    default:
      return 'gray'
  }
}

async function importCbomFile(file: File) {
  importingCbom.value = true
  try {
    let body: unknown
    const text = await file.text()
    try {
      body = JSON.parse(text)
    } catch {
      Message.error('CBOM 文件不是合法 JSON')
      return
    }
    const r = await assetApi.importCbom({ cbom: body })
    const n = r.imported ?? r.results?.length ?? 0
    const m = r.merged ?? 0
    Message.success(`CBOM 导入完成：新增 ${n}，并入 ${m}`)
    await load()
  } catch {
    Message.error('导入 CBOM 失败')
  } finally {
    importingCbom.value = false
  }
}

function onSaved() {
  load()
  // 若正在查看详情，刷新该资产。
  if (active.value) refreshActive(active.value.id)
}

async function refreshActive(id: number) {
  try {
    active.value = await assetApi.get(id)
  } catch {
    /* 退化 */
  }
}

function onMerged() {
  load()
}

const filters = reactive<AssetQuery>({
  layer: '',
  level: '',
  system: '',
  hndl: '',
  q: '',
  group: '',
})

// ---- 资产分组（Wave C） ----
const groups = ref<AssetGroup[]>([])
const byGroup = ref<AssetByGroup[]>([])
const groupView = ref(false)
const groupViewLoading = ref(false)
const groupManageOpen = ref(false)

async function loadGroups() {
  try {
    groups.value = await groupApi.list()
  } catch {
    /* 分组缺失不阻断主清单 */
  }
}

async function loadByGroup() {
  groupViewLoading.value = true
  try {
    byGroup.value = await groupApi.byGroup()
  } catch {
    Message.error('加载分组聚合失败')
  } finally {
    groupViewLoading.value = false
  }
}

function toggleGroupView() {
  groupView.value = !groupView.value
  if (groupView.value && !byGroup.value.length) loadByGroup()
}

// 点击分组聚合卡 → 回到清单并按该分组筛选。
function filterByGroup(g: AssetByGroup) {
  filters.group = g.group
  groupView.value = false
  load()
}

function onGroupsChanged() {
  loadGroups()
  if (groupView.value) loadByGroup()
}

const drawerOpen = ref(false)
const detailLoading = ref(false)
const active = ref<CryptoAsset | null>(null)

const dims = [
  { key: 'd1', label: 'D1 算法脆弱性', weight: '30%' },
  { key: 'd2', label: 'D2 数据敏感度', weight: '25%' },
  { key: 'd3', label: 'D3 数据生命周期', weight: '20%' },
  { key: 'd4', label: 'D4 迁移复杂度', weight: '15%' },
  { key: 'd5', label: 'D5 暴露面', weight: '10%' },
] as const

const columns = [
  { title: '名称', slotName: 'name', minWidth: 180 },
  { title: '系统', dataIndex: 'system', width: 140, ellipsis: true, tooltip: true },
  { title: '层级', slotName: 'layer', width: 80 },
  { title: '算法', slotName: 'algorithm', width: 150 },
  { title: '暴露面', slotName: 'exposure', width: 90 },
  { title: '综合分', slotName: 'score', width: 90, align: 'center' as const },
  { title: '分级', slotName: 'level', width: 90, align: 'center' as const },
  { title: 'HNDL', slotName: 'hndl', width: 70, align: 'center' as const },
  { title: '操作', slotName: 'actions', width: 110, align: 'center' as const },
]

async function load() {
  loading.value = true
  try {
    // 过滤掉空字符串参数。
    const params: AssetQuery = {}
    if (filters.layer) params.layer = filters.layer
    if (filters.level) params.level = filters.level
    if (filters.system) params.system = filters.system
    if (filters.hndl) params.hndl = filters.hndl
    if (filters.q) params.q = filters.q
    if (filters.group) params.group = filters.group
    assets.value = await assetApi.list(params)
  } catch {
    Message.error('加载资产清单失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.layer = ''
  filters.level = ''
  filters.system = ''
  filters.hndl = ''
  filters.q = ''
  filters.group = ''
  load()
}

async function openDetail(record: TableData) {
  const asset = record as CryptoAsset
  drawerOpen.value = true
  detailLoading.value = true
  active.value = asset
  try {
    active.value = await assetApi.get(asset.id)
  } catch {
    // 退化为列表里的行数据。
  } finally {
    detailLoading.value = false
  }
  loadEvidence(asset.id)
}

async function exportCbom() {
  exporting.value = true
  try {
    const blob = await cbomApi.export()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const stamp = new Date().toISOString().slice(0, 10)
    a.download = `zhulong-pqm-cbom-${stamp}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    Message.success('CBOM (CycloneDX) 已导出')
  } catch {
    Message.error('导出 CBOM 失败')
  } finally {
    exporting.value = false
  }
}

function certColor(notAfter?: string | null): string {
  const u = certUrgency(notAfter)
  if (u === 'expired') return 'rgb(var(--red-6))'
  if (u === 'soon') return 'rgb(var(--orange-6))'
  return 'var(--clay-text)'
}

// 闭环联动：资产 → 改造编排，携带资产与建议算法，落地后自动打开新建改造 modal 预填。
function startRemediation(asset: CryptoAsset) {
  router.push({
    path: '/remediation',
    query: {
      assetId: asset.id,
      assetName: asset.name,
      algo: asset.suggestedAlgo || asset.algorithm || '',
    },
  })
}

onMounted(() => {
  load()
  loadGroups()
})
</script>

<template>
  <div class="page">
    <div class="page-header assets-head">
      <div>
        <h1 class="page-title">密码使用点清单 · CBOM</h1>
        <p class="page-subtitle">
          密码学资产清单（CycloneDX CBOM 口径）—— 算法、密钥、协议、证书与五维风险画像。
        </p>
      </div>
      <a-space>
        <a-button type="primary" @click="openCreate">
          <template #icon><IconPlus /></template>
          新增资产
        </a-button>
        <a-button @click="mergeOpen = true">
          <template #icon><IconBranch /></template>
          合并重复
        </a-button>
        <a-button @click="groupManageOpen = true">
          <template #icon><IconFolder /></template>
          分组管理
        </a-button>
        <a-button :type="groupView ? 'primary' : 'outline'" @click="toggleGroupView">
          <template #icon><IconApps /></template>
          按分组视图
        </a-button>
        <a-upload
          :auto-upload="false"
          :show-file-list="false"
          accept=".json"
          :custom-request="noopRequest"
          @change="(_: unknown, f: any) => f?.file && importCbomFile(f.file)"
        >
          <template #upload-button>
            <a-button :loading="importingCbom">
              <template #icon><IconImport /></template>
              导入 CBOM
            </a-button>
          </template>
        </a-upload>
        <a-button type="outline" :loading="exporting" @click="exportCbom">
          <template #icon><IconDownload /></template>
          导出 CBOM
        </a-button>
      </a-space>
    </div>

    <!-- 筛选条 -->
    <a-card class="filter-card" :bordered="true">
      <a-row :gutter="12" align="center">
        <a-col flex="170px">
          <a-select v-model="filters.layer" placeholder="层级" allow-clear @change="load">
            <a-option value="L1">L1 应用/会话层</a-option>
            <a-option value="L2">L2 协议/传输层</a-option>
            <a-option value="L3">L3 数据存储层</a-option>
            <a-option value="L4">L4 硬件/根信任层</a-option>
          </a-select>
        </a-col>
        <a-col flex="140px">
          <a-select v-model="filters.level" placeholder="分级" allow-clear @change="load">
            <a-option value="P1">P1 极高</a-option>
            <a-option value="P2">P2 高</a-option>
            <a-option value="P3">P3 中</a-option>
            <a-option value="P4">P4 低</a-option>
          </a-select>
        </a-col>
        <a-col flex="120px">
          <a-select v-model="filters.hndl" placeholder="HNDL" allow-clear @change="load">
            <a-option value="true">仅 HNDL</a-option>
            <a-option value="false">非 HNDL</a-option>
          </a-select>
        </a-col>
        <a-col flex="170px">
          <a-select v-model="filters.group" placeholder="分组" allow-clear @change="load">
            <a-option v-for="g in groups" :key="g.id" :value="g.name">
              {{ g.name }}
            </a-option>
          </a-select>
        </a-col>
        <a-col flex="auto">
          <a-input
            v-model="filters.q"
            placeholder="按名称 / 系统 / 算法 / 端点搜索"
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

    <!-- 按分组视图：聚合卡（每组 count/P1/HNDL） -->
    <a-card v-if="groupView" class="block-card">
      <template #title>
        <span class="card-title-icon">
          <IconApps /> 按分组视图
          <span class="muted">（{{ byGroup.length }} 组）</span>
        </span>
      </template>
      <template #extra>
        <a-space>
          <a-button size="small" @click="groupManageOpen = true">
            <template #icon><IconFolder /></template>
            分组管理
          </a-button>
          <a-button size="small" :loading="groupViewLoading" @click="loadByGroup">
            <template #icon><IconRefresh /></template>
          </a-button>
        </a-space>
      </template>
      <a-spin :loading="groupViewLoading" style="width: 100%">
        <div v-if="!byGroup.length" class="empty-inline">
          <a-empty description="暂无分组聚合数据，先在「分组管理」建分组并归属资产" />
        </div>
        <a-row v-else :gutter="16" class="group-grid">
          <a-col
            v-for="g in byGroup"
            :key="g.groupId ?? g.group"
            :xs="24"
            :sm="12"
            :md="8"
            :lg="6"
          >
            <div class="group-card" @click="filterByGroup(g)">
              <div class="group-name" :title="g.group">{{ g.group || '未分组' }}</div>
              <div class="group-count">{{ g.count }}</div>
              <div class="group-count-label">密码使用点</div>
              <div class="group-tags">
                <a-tag color="red" size="small">P1 {{ g.p1 }}</a-tag>
                <a-tag color="orange" size="small">HNDL {{ g.hndl }}</a-tag>
              </div>
            </div>
          </a-col>
        </a-row>
      </a-spin>
    </a-card>

    <!-- 资产表 -->
    <a-card v-else class="block-card">
      <template #title>
        资产清单 <span class="muted">（{{ assets.length }} 项）</span>
      </template>
      <template #extra>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><IconRefresh /></template>
          刷新
        </a-button>
      </template>
      <a-table
        :data="assets"
        :columns="columns"
        :loading="loading"
        :pagination="{ pageSize: 12, showTotal: true, hideOnSinglePage: false }"
        row-key="id"
        :scroll="{ x: 1020 }"
        @row-click="openDetail"
      >
        <template #name="{ record }">
          <a-link @click.stop="openDetail(record)">{{ record.name }}</a-link>
        </template>
        <template #layer="{ record }">
          <a-tag size="small" bordered>{{ record.layer || '—' }}</a-tag>
        </template>
        <template #algorithm="{ record }">
          {{ record.algorithm || '—'
          }}<span v-if="record.keySize" class="dim"> / {{ record.keySize }}</span>
        </template>
        <template #exposure="{ record }">
          <a-tag :color="exposureMeta(record.exposure).color" size="small">
            {{ exposureMeta(record.exposure).label }}
          </a-tag>
        </template>
        <template #score="{ record }">
          <span class="score-val">{{ record.riskScore }}</span>
        </template>
        <template #level="{ record }">
          <a-tag
            v-if="record.riskLevel"
            :color="levelColor(record.riskLevel)"
            size="small"
          >
            {{ record.riskLevel }} {{ record.riskLevelText || levelText(record.riskLevel) }}
          </a-tag>
          <span v-else class="dim">未评分</span>
        </template>
        <template #hndl="{ record }">
          <a-tag v-if="record.hndl" color="red" size="small">HNDL</a-tag>
          <span v-else class="dim">—</span>
        </template>
        <template #actions="{ record }">
          <a-space :size="2">
            <a-button size="mini" type="text" @click.stop="openEdit(record)">
              <template #icon><IconEdit /></template>
            </a-button>
            <a-button
              size="mini"
              type="text"
              status="danger"
              @click.stop="confirmDelete(record)"
            >
              <template #icon><IconDelete /></template>
            </a-button>
          </a-space>
        </template>
        <template #empty>
          <a-empty description="无匹配资产，调整筛选或先去发现页扫描">
            <a-button size="small" type="outline" @click="router.push('/discovery')">
              前往密码学发现 →
            </a-button>
          </a-empty>
        </template>
      </a-table>
    </a-card>

    <!-- 详情抽屉 -->
    <a-drawer
      v-model:visible="drawerOpen"
      :width="560"
      :footer="false"
      :title="active?.name ?? '资产详情'"
    >
      <a-spin :loading="detailLoading" style="width: 100%">
        <template v-if="active">
          <div class="detail-banner">
            <div>
              <div class="detail-score" :style="{ color: `rgb(var(--${levelColor(active.riskLevel)}-6))` }">
                {{ active.riskScore }}
              </div>
              <div class="detail-score-label">综合风险分</div>
            </div>
            <a-space direction="vertical" align="end" :size="10">
              <a-space>
                <a-tag
                  v-if="active.riskLevel"
                  :color="levelColor(active.riskLevel)"
                  size="large"
                >
                  {{ active.riskLevel }} ·
                  {{ active.riskLevelText || levelText(active.riskLevel) }}
                </a-tag>
                <a-tag v-if="active.hndl" color="red" size="large">HNDL 关注</a-tag>
              </a-space>
              <a-space>
                <a-button size="small" @click="openEdit(active)">
                  <template #icon><IconEdit /></template>
                  编辑
                </a-button>
                <a-button type="primary" size="small" @click="startRemediation(active)">
                  <template #icon><IconTool /></template>
                  发起改造
                </a-button>
              </a-space>
            </a-space>
          </div>

          <a-descriptions title="基础信息" :column="1" bordered size="medium" class="dd">
            <a-descriptions-item label="所属系统">{{ active.system || '—' }}</a-descriptions-item>
            <a-descriptions-item label="层级">{{ layerLabel(active.layer) }}</a-descriptions-item>
            <a-descriptions-item label="责任部门 / 责任人">
              {{ active.department || '—' }} / {{ active.owner || '—' }}
            </a-descriptions-item>
            <a-descriptions-item label="端点">{{ active.endpoint || '—' }}</a-descriptions-item>
            <a-descriptions-item label="暴露面">
              <a-tag :color="exposureMeta(active.exposure).color" size="small">
                {{ exposureMeta(active.exposure).label }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="来源 / 状态">
              {{ active.source || '—' }} / {{ active.status || '—' }}
            </a-descriptions-item>
          </a-descriptions>

          <a-descriptions title="密码学画像" :column="1" bordered size="medium" class="dd">
            <a-descriptions-item label="当前算法">
              {{ active.algorithm || '—'
              }}<span v-if="active.keySize"> / {{ active.keySize }} bit</span>
            </a-descriptions-item>
            <a-descriptions-item label="协议">{{ active.protocol || '—' }}</a-descriptions-item>
            <a-descriptions-item label="建议迁移算法">
              <a-tag v-if="active.suggestedAlgo" color="orange">{{ active.suggestedAlgo }}</a-tag>
              <span v-else>—</span>
            </a-descriptions-item>
            <a-descriptions-item label="证书到期">
              <span :style="{ color: certColor(active.certNotAfter), fontWeight: 600 }">
                {{ fmtDay(active.certNotAfter) }}
                <span v-if="certUrgency(active.certNotAfter) === 'expired'">（已过期）</span>
                <span v-else-if="certUrgency(active.certNotAfter) === 'soon'">（90 天内到期）</span>
              </span>
            </a-descriptions-item>
          </a-descriptions>

          <div class="dd">
            <div class="dd-title">五维评分</div>
            <div v-for="d in dims" :key="d.key" class="dim-row">
              <span class="dim-name">{{ d.label }}<span class="dim-w">{{ d.weight }}</span></span>
              <a-progress
                :percent="(active[d.key] ?? 0) / 100"
                :stroke-width="10"
                :show-text="false"
                color="#b4552d"
                class="dim-bar"
              />
              <span class="dim-val">{{ active[d.key] ?? 0 }}</span>
            </div>
          </div>

          <a-alert v-if="active.riskHint" type="warning" class="dd">
            {{ active.riskHint }}
          </a-alert>

          <!-- 证据链 -->
          <div class="dd">
            <div class="dd-title evidence-title">
              <span><IconSafe /> 证据链</span>
              <a-space>
                <span class="muted">{{ evidence.length }} 条</span>
                <a-upload
                  :auto-upload="false"
                  :show-file-list="false"
                  accept=".json"
                  :custom-request="noopRequest"
                  @change="(_: unknown, f: any) => f?.file && importCbomFile(f.file)"
                >
                  <template #upload-button>
                    <a-button size="mini" type="outline" :loading="importingCbom">
                      <template #icon><IconImport /></template>
                      导入 CBOM
                    </a-button>
                  </template>
                </a-upload>
              </a-space>
            </div>
            <a-spin :loading="evidenceLoading" style="width: 100%">
              <div v-if="!evidence.length" class="evidence-empty">
                <a-empty description="暂无证据，扫描/导入会自动累积证据来源" :image-size="40" />
              </div>
              <div v-else class="evidence-list">
                <div v-for="(e, i) in evidence" :key="i" class="evidence-item">
                  <div class="evidence-head">
                    <a-space :size="6" wrap>
                      <a-tag size="small" bordered>{{ e.source || '—' }}</a-tag>
                      <a-tag v-if="e.ruleRef" color="orange" size="small" class="mono">
                        {{ e.ruleRef }}
                      </a-tag>
                      <a-tag :color="confColor(e.confidence)" size="small">
                        置信度 {{ e.confidence || '—' }}
                      </a-tag>
                      <a-tag
                        :color="evidenceValid(e) ? 'green' : 'gray'"
                        size="small"
                      >
                        {{ evidenceValid(e) ? '已固化' : '未校验' }}
                      </a-tag>
                    </a-space>
                    <span class="evidence-time">{{ fmtDate(e.scannedAt || e.createdAt) }}</span>
                  </div>
                  <div v-if="e.raw" class="evidence-raw mono">{{ e.raw }}</div>
                  <div v-if="e.hash" class="evidence-hash mono">
                    SHA-256：{{ e.hash }}
                  </div>
                </div>
              </div>
            </a-spin>
          </div>

          <!-- 评分历史（③ 评估深化） -->
          <div class="dd">
            <div class="dd-title">评分历史</div>
            <ScoreHistoryTimeline :key="active.id" :asset-id="active.id" />
          </div>
        </template>
      </a-spin>
    </a-drawer>

    <!-- 新增/编辑资产 -->
    <AssetFormDrawer v-model:visible="formOpen" :asset="editing" @saved="onSaved" />

    <!-- 合并重复资产 -->
    <MergeModal v-model:visible="mergeOpen" @merged="onMerged" />

    <!-- 资产分组管理 -->
    <GroupManageModal v-model:visible="groupManageOpen" @changed="onGroupsChanged" />
  </div>
</template>

<style scoped>
.assets-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
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
  color: var(--clay-text-soft);
  font-weight: 400;
}
.dim {
  color: var(--clay-text-soft);
}
.score-val {
  font-weight: 700;
  color: var(--clay-text);
}
.card-title-icon {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.empty-inline {
  padding: 18px 0;
}
.group-grid {
  row-gap: 16px;
}
.group-card {
  border: 1px solid var(--clay-border);
  border-left: 3px solid var(--clay-accent-2);
  border-radius: 12px;
  padding: 14px 16px;
  background: #fffdfa;
  cursor: pointer;
  transition:
    box-shadow 0.18s,
    transform 0.18s;
  height: 100%;
}
.group-card:hover {
  box-shadow: 0 6px 16px rgba(180, 85, 45, 0.12);
  transform: translateY(-2px);
}
.group-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.group-count {
  font-size: 28px;
  font-weight: 800;
  color: var(--clay-accent);
  line-height: 1.1;
  margin-top: 8px;
}
.group-count-label {
  font-size: 11px;
  color: var(--clay-text-soft);
  margin-top: 2px;
}
.group-tags {
  display: flex;
  gap: 8px;
  margin-top: 10px;
}

.detail-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #fbeee2, #f6ece0);
  border: 1px solid var(--clay-border);
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 18px;
}
.detail-score {
  font-size: 34px;
  font-weight: 800;
  line-height: 1;
}
.detail-score-label {
  font-size: 12px;
  color: var(--clay-text-soft);
  margin-top: 4px;
}

.dd {
  margin-top: 18px;
}
.dd-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
  margin-bottom: 12px;
}
.dim-row {
  display: grid;
  grid-template-columns: 170px 1fr 36px;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.dim-name {
  font-size: 13px;
  color: var(--clay-text);
}
.dim-w {
  color: var(--clay-text-soft);
  font-size: 11px;
  margin-left: 6px;
}
.dim-bar {
  flex: 1;
}
.dim-val {
  text-align: right;
  font-weight: 600;
}

/* 证据链 */
.muted {
  font-size: 12px;
  color: var(--clay-text-soft);
  font-weight: 400;
}
.mono {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
}
.evidence-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.evidence-title > span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.evidence-empty {
  padding: 14px 0;
}
.evidence-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.evidence-item {
  border: 1px solid var(--clay-border);
  border-radius: 10px;
  padding: 10px 12px;
  background: #fffdfa;
  border-left: 3px solid var(--clay-accent-2);
}
.evidence-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}
.evidence-time {
  font-size: 11px;
  color: var(--clay-text-soft);
  flex-shrink: 0;
}
.evidence-raw {
  margin-top: 8px;
  padding: 8px 10px;
  background: var(--clay-bg-soft);
  border-radius: 6px;
  color: var(--clay-text);
  white-space: pre-wrap;
}
.evidence-hash {
  margin-top: 6px;
  font-size: 11px;
  color: var(--clay-text-soft);
}
</style>
