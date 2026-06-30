<script setup lang="ts">
import { onMounted, ref, computed, reactive } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconSave, IconThunderbolt, IconRefresh } from '@arco-design/web-vue/es/icon'
import { assetApi, scoreApi } from '@/api'
import type {
  CryptoAsset,
  ScoreOptions,
  ScorePreset,
  ScoreSummary,
} from '@/api/types'
import { levelColor, levelText, scoreLevel, scoreColor } from '@/utils/format'

const WEIGHTS = { d1: 0.3, d2: 0.25, d3: 0.2, d4: 0.15, d5: 0.1 } as const

const dimMeta = [
  { key: 'd1', label: 'D1 算法脆弱性', weight: '30%' },
  { key: 'd2', label: 'D2 数据敏感度', weight: '25%' },
  { key: 'd3', label: 'D3 数据生命周期', weight: '20%' },
  { key: 'd4', label: 'D4 迁移复杂度', weight: '15%' },
  { key: 'd5', label: 'D5 暴露面', weight: '10%' },
] as const

type DimKey = (typeof dimMeta)[number]['key']

const loading = ref(false)
const saving = ref(false)
const assets = ref<CryptoAsset[]>([])
const options = ref<ScoreOptions | null>(null)
const presets = ref<ScorePreset[]>([])
const summary = ref<ScoreSummary | null>(null)

const selectedId = ref<number | null>(null)
const dims = reactive<Record<DimKey, number>>({ d1: 0, d2: 0, d3: 0, d4: 0, d5: 0 })

const selectedAsset = computed(() =>
  assets.value.find((a) => a.id === selectedId.value),
)

// 实时综合分（与后端口径一致：D1×30%+D2×25%+D3×20%+D4×15%+D5×10%）。
const liveScore = computed(() =>
  Math.round(
    dims.d1 * WEIGHTS.d1 +
      dims.d2 * WEIGHTS.d2 +
      dims.d3 * WEIGHTS.d3 +
      dims.d4 * WEIGHTS.d4 +
      dims.d5 * WEIGHTS.d5,
  ),
)
const liveLevel = computed(() => scoreLevel(liveScore.value))
// HNDL 规则：D2≥60 且 D3≥60。
const liveHndl = computed(() => dims.d2 >= 60 && dims.d3 >= 60)

const summaryCards = computed(() => {
  const s = summary.value
  return [
    { key: 'P1', label: 'P1 极高', color: '#cb4b3f', bucket: s?.p1 },
    { key: 'P2', label: 'P2 高', color: '#FF7D00', bucket: s?.p2 },
    { key: 'P3', label: 'P3 中', color: '#d6a93f', bucket: s?.p3 },
    { key: 'P4', label: 'P4 低', color: '#5a9367', bucket: s?.p4 },
  ]
})

function optionsFor(key: DimKey) {
  return options.value?.[key] ?? []
}

function applyAssetDims(a: CryptoAsset) {
  dims.d1 = a.d1 ?? 0
  dims.d2 = a.d2 ?? 0
  dims.d3 = a.d3 ?? 0
  dims.d4 = a.d4 ?? 0
  dims.d5 = a.d5 ?? 0
}

function onSelectAsset(id: number | undefined) {
  if (id == null) return
  selectedId.value = id
  const a = assets.value.find((x) => x.id === id)
  if (a) applyAssetDims(a)
}

function applyPreset(p: ScorePreset) {
  dims.d1 = p.dims[0] ?? 0
  dims.d2 = p.dims[1] ?? 0
  dims.d3 = p.dims[2] ?? 0
  dims.d4 = p.dims[3] ?? 0
  dims.d5 = p.dims[4] ?? 0
  Message.info(`已套用预设画像「${p.name}」`)
}

async function loadAll() {
  loading.value = true
  try {
    const [a, o, p, s] = await Promise.all([
      assetApi.list(),
      scoreApi.options(),
      scoreApi.presets(),
      scoreApi.summary().catch(() => null),
    ])
    assets.value = a
    options.value = o
    presets.value = p
    summary.value = s
    if (!selectedId.value && a.length) {
      onSelectAsset(a[0].id)
    }
  } catch {
    Message.error('加载评估元数据失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function refreshSummary() {
  try {
    summary.value = await scoreApi.summary()
  } catch {
    /* 忽略 */
  }
}

async function save() {
  if (selectedId.value == null) {
    Message.warning('请先选择一个资产')
    return
  }
  saving.value = true
  try {
    const updated = await assetApi.score(selectedId.value, {
      d1: dims.d1,
      d2: dims.d2,
      d3: dims.d3,
      d4: dims.d4,
      d5: dims.d5,
    })
    // 用返回值更新本地列表。
    const idx = assets.value.findIndex((x) => x.id === updated.id)
    if (idx >= 0) assets.value[idx] = updated
    Message.success(
      `已保存：综合分 ${updated.riskScore} · ${updated.riskLevel} ${
        updated.riskLevelText || ''
      }`,
    )
    await refreshSummary()
  } catch {
    Message.error('保存评分失败')
  } finally {
    saving.value = false
  }
}

onMounted(loadAll)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1 class="page-title">风险评估</h1>
      <p class="page-subtitle">
        五维加权评分：综合分 = D1×30% + D2×25% + D3×20% + D4×15% + D5×10% ·
        自动分级 P1–P4 · D2≥60 且 D3≥60 自动标记 HNDL。
      </p>
    </div>

    <a-spin :loading="loading" style="width: 100%">
      <a-row :gutter="16">
        <!-- 评分主面板 -->
        <a-col :xs="24" :lg="16">
          <a-card class="block-card">
            <template #title>
              <span class="card-title-icon"><IconThunderbolt /> 五维评分</span>
            </template>
            <template #extra>
              <a-button size="small" :loading="loading" @click="loadAll">
                <template #icon><IconRefresh /></template>
                重载
              </a-button>
            </template>

            <a-form :model="dims" layout="vertical">
              <a-form-item label="选择资产">
                <a-select
                  :model-value="selectedId ?? undefined"
                  placeholder="选择一个密码使用点进行评分"
                  allow-search
                  :filter-option="true"
                  @change="(v) => onSelectAsset(v as number)"
                >
                  <a-option v-for="a in assets" :key="a.id" :value="a.id" :label="a.name">
                    {{ a.name }}
                    <span class="opt-sub">· {{ a.system || '未分类' }} · {{ a.layer || '—' }}</span>
                  </a-option>
                </a-select>
              </a-form-item>

              <a-row :gutter="16">
                <a-col v-for="d in dimMeta" :key="d.key" :xs="24" :sm="12">
                  <a-form-item>
                    <template #label>
                      {{ d.label }} <span class="weight-badge">{{ d.weight }}</span>
                    </template>
                    <a-select
                      v-model="dims[d.key]"
                      :disabled="selectedId == null"
                      placeholder="选择等级"
                    >
                      <a-option
                        v-for="opt in optionsFor(d.key)"
                        :key="opt.value"
                        :value="opt.value"
                      >
                        {{ opt.label }} <span class="opt-sub">（{{ opt.value }}）</span>
                      </a-option>
                    </a-select>
                  </a-form-item>
                </a-col>
              </a-row>
            </a-form>

            <a-divider style="margin: 8px 0 18px" />

            <!-- 预设画像 -->
            <div class="preset-block">
              <div class="preset-title">预设画像（一键填入）</div>
              <a-space wrap>
                <a-button
                  v-for="p in presets"
                  :key="p.name"
                  size="small"
                  :disabled="selectedId == null"
                  class="preset-btn"
                  @click="applyPreset(p)"
                >
                  <span
                    class="preset-dot"
                    :style="{ background: `rgb(var(--${levelColor(p.level)}-6))` }"
                  />
                  {{ p.name }}
                  <a-tag size="small" :color="levelColor(p.level)" class="preset-tag">
                    {{ p.level }}
                  </a-tag>
                </a-button>
              </a-space>
              <a-empty
                v-if="!presets.length"
                description="暂无预设画像"
                style="margin-top: 12px"
              />
            </div>
          </a-card>
        </a-col>

        <!-- 右侧：实时结果 + 汇总看板 -->
        <a-col :xs="24" :lg="8">
          <a-card class="block-card live-card">
            <div class="live-score" :style="{ color: `rgb(var(--${scoreColor(liveScore)}-6))` }">
              {{ liveScore }}
            </div>
            <div class="live-label">实时综合风险分</div>
            <div class="live-badges">
              <a-tag :color="levelColor(liveLevel)" size="large" bordered>
                {{ liveLevel }} · {{ levelText(liveLevel) }}
              </a-tag>
              <a-tag v-if="liveHndl" color="red" size="large">HNDL</a-tag>
            </div>
            <div v-if="selectedAsset" class="live-asset">
              当前：{{ selectedAsset.name }}
            </div>
            <a-button
              type="primary"
              long
              :loading="saving"
              :disabled="selectedId == null"
              style="margin-top: 18px"
              @click="save"
            >
              <template #icon><IconSave /></template>
              保存评分
            </a-button>
          </a-card>

          <a-card title="优先级汇总" class="block-card">
            <template #extra>
              <span class="muted">已评分 {{ summary?.scoredCount ?? 0 }} · 均分 {{ summary?.avgScore ?? 0 }}</span>
            </template>
            <div class="sum-grid">
              <div
                v-for="c in summaryCards"
                :key="c.key"
                class="sum-cell"
                :style="{ borderLeftColor: c.color }"
              >
                <div class="sum-count" :style="{ color: c.color }">
                  {{ c.bucket?.count ?? 0 }}
                </div>
                <div class="sum-label">{{ c.label }}</div>
                <div class="sum-avg">均分 {{ c.bucket?.avg ?? 0 }}</div>
              </div>
            </div>
            <a-divider style="margin: 14px 0" />
            <div class="sum-extra">
              <span>HNDL 资产</span>
              <strong>{{ summary?.hndlCount ?? 0 }}</strong>
            </div>
            <div class="sum-extra">
              <span>极高风险</span>
              <strong style="color: var(--brand-accent)">{{ summary?.criticalCount ?? 0 }}</strong>
            </div>
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
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
.weight-badge {
  font-size: 11px;
  color: #fff;
  background: var(--brand-accent-2);
  border-radius: 6px;
  padding: 1px 6px;
  margin-left: 4px;
}
.opt-sub {
  color: var(--brand-text-soft);
  font-size: 12px;
}
.muted {
  font-size: 12px;
  color: var(--brand-text-soft);
}

.preset-block {
  padding-top: 2px;
}
.preset-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--brand-text);
  margin-bottom: 12px;
}
.preset-btn {
  display: inline-flex;
  align-items: center;
}
.preset-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}
.preset-tag {
  margin-left: 6px;
}

.live-card {
  text-align: center;
  padding: 8px 0;
  background: linear-gradient(160deg, #FFFFFF 0%, #f8efe6 100%);
}
.live-score {
  font-size: 56px;
  font-weight: 800;
  line-height: 1;
}
.live-label {
  font-size: 13px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}
.live-badges {
  display: flex;
  gap: 8px;
  justify-content: center;
  margin-top: 14px;
}
.live-asset {
  margin-top: 12px;
  font-size: 12px;
  color: var(--brand-text-soft);
}

.sum-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.sum-cell {
  border-left: 4px solid;
  background: #FFFFFF;
  border-radius: 8px;
  padding: 10px 12px;
}
.sum-count {
  font-size: 22px;
  font-weight: 700;
}
.sum-label {
  font-size: 12px;
  color: var(--brand-text);
  margin-top: 2px;
}
.sum-avg {
  font-size: 11px;
  color: var(--brand-text-soft);
}
.sum-extra {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  color: var(--brand-text);
  padding: 3px 0;
}
</style>
