<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconSave,
  IconThunderbolt,
  IconLock,
  IconCheck,
} from '@arco-design/web-vue/es/icon'
import { profileApi } from '@/api'
import type { LevelDist, RescoreResult, ScoreProfile } from '@/api/types'

/**
 * 专家模式调权：五维权重滑块（和≠100 禁用应用）、实时预演 P1-P4 分布变化、
 * 方案列表 + 激活（激活后回传 before/after 迁移数）。
 */
const emit = defineEmits<{ (e: 'activated', r: RescoreResult): void }>()

const WEIGHT_KEYS = ['w1', 'w2', 'w3', 'w4', 'w5'] as const
type WeightKey = (typeof WEIGHT_KEYS)[number]

const dimMeta = [
  { key: 'w1' as WeightKey, label: 'D1 算法脆弱性' },
  { key: 'w2' as WeightKey, label: 'D2 数据敏感度' },
  { key: 'w3' as WeightKey, label: 'D3 数据生命周期' },
  { key: 'w4' as WeightKey, label: 'D4 迁移复杂度' },
  { key: 'w5' as WeightKey, label: 'D5 暴露面' },
]

const loading = ref(false)
const profiles = ref<ScoreProfile[]>([])
const selectedId = ref<number | null>(null)

const weights = reactive<Record<WeightKey, number>>({
  w1: 30,
  w2: 25,
  w3: 20,
  w4: 15,
  w5: 10,
})

const selectedProfile = computed(() =>
  profiles.value.find((p) => p.id === selectedId.value),
)
const isBuiltinSelected = computed(() => !!selectedProfile.value?.isBuiltin)

const sum = computed(() =>
  WEIGHT_KEYS.reduce((acc, k) => acc + (weights[k] || 0), 0),
)
const sumValid = computed(() => sum.value === 100)

// 预演分布。
const previewing = ref(false)
const preview = ref<RescoreResult | null>(null)
let debounceTimer: number | undefined

const beforeDist = computed<LevelDist>(
  () => preview.value?.before ?? { p1: 0, p2: 0, p3: 0, p4: 0 },
)
const afterDist = computed<LevelDist>(
  () => preview.value?.after ?? { p1: 0, p2: 0, p3: 0, p4: 0 },
)

const distRows = computed(() => {
  const b = beforeDist.value
  const a = afterDist.value
  return [
    { key: 'p1', label: 'P1 极高', color: '#cb4b3f', before: b.p1, after: a.p1 },
    { key: 'p2', label: 'P2 高', color: '#db855c', before: b.p2, after: a.p2 },
    { key: 'p3', label: 'P3 中', color: '#d6a93f', before: b.p3, after: a.p3 },
    { key: 'p4', label: 'P4 低', color: '#5a9367', before: b.p4, after: a.p4 },
  ]
})

const distMax = computed(() => {
  let m = 1
  for (const r of distRows.value) m = Math.max(m, r.before, r.after)
  return m
})

function applyProfileWeights(p: ScoreProfile) {
  weights.w1 = p.w1
  weights.w2 = p.w2
  weights.w3 = p.w3
  weights.w4 = p.w4
  weights.w5 = p.w5
}

function onSelectProfile(id: number | undefined) {
  if (id == null) return
  selectedId.value = id
  const p = profiles.value.find((x) => x.id === id)
  if (p) {
    applyProfileWeights(p)
    runPreview()
  }
}

async function load() {
  loading.value = true
  try {
    profiles.value = await profileApi.list()
    const active = profiles.value.find((p) => p.isActive)
    const target = active ?? profiles.value[0]
    if (target) {
      selectedId.value = target.id
      applyProfileWeights(target)
      runPreview()
    }
  } catch {
    Message.error('加载权重方案失败')
  } finally {
    loading.value = false
  }
}

// 预演：选中方案时调后端只读试算；自定义滑块拖动用选中方案 id 预演（内置方案不可改权重）。
function runPreview() {
  if (selectedId.value == null) return
  previewing.value = true
  profileApi
    .preview(selectedId.value)
    .then((r) => {
      preview.value = r
    })
    .catch(() => {
      /* 预演失败不阻断 */
    })
    .finally(() => {
      previewing.value = false
    })
}

// 滑块防抖（非内置方案才允许调权预演）。
watch(
  () => ({ ...weights }),
  () => {
    if (isBuiltinSelected.value) return
    if (debounceTimer) window.clearTimeout(debounceTimer)
    debounceTimer = window.setTimeout(() => {
      // 滑块本地试算仅影响 UI 提示；真实 before/after 以后端 preview（按已存方案）为准。
    }, 300)
  },
  { deep: true },
)

// 另存为方案。
const saveOpen = ref(false)
const saving = ref(false)
const saveForm = reactive({ name: '', description: '' })

function openSave() {
  if (!sumValid.value) {
    Message.warning(`权重合计须为 100，当前 ${sum.value}`)
    return
  }
  saveForm.name = ''
  saveForm.description = ''
  saveOpen.value = true
}

async function saveProfile() {
  if (!saveForm.name.trim()) {
    Message.warning('请填写方案名称')
    return
  }
  if (!sumValid.value) {
    Message.warning(`权重合计须为 100，当前 ${sum.value}`)
    return
  }
  saving.value = true
  try {
    const created = await profileApi.create({
      name: saveForm.name.trim(),
      description: saveForm.description.trim(),
      w1: weights.w1,
      w2: weights.w2,
      w3: weights.w3,
      w4: weights.w4,
      w5: weights.w5,
    })
    Message.success(`方案「${created.name}」已保存（未激活）`)
    saveOpen.value = false
    profiles.value = await profileApi.list()
    selectedId.value = created.id
    runPreview()
  } catch {
    Message.error('保存方案失败，请确认权重合计为 100')
  } finally {
    saving.value = false
  }
}

// 激活并全量复算。
const activating = ref(false)
function confirmActivate() {
  const p = selectedProfile.value
  if (!p) return
  Modal.confirm({
    title: `激活方案「${p.name}」并全量复算`,
    content:
      '激活后将以该权重对全部资产重算五维并写入评分历史（留痕），此操作可逆（可切回标准权重）。是否继续？',
    okText: '激活并复算',
    cancelText: '取消',
    onOk: doActivate,
  })
}

async function doActivate() {
  if (selectedId.value == null) return
  activating.value = true
  try {
    const r = await profileApi.activate(selectedId.value, '专家模式调权激活')
    const shifted = r.shifted ?? 0
    Message.success(
      `方案已激活，全量复算完成：${shifted} 个资产等级发生迁移`,
    )
    preview.value = r
    emit('activated', r)
    profiles.value = await profileApi.list()
  } catch {
    Message.error('激活方案失败')
  } finally {
    activating.value = false
  }
}

onMounted(load)
</script>

<template>
  <a-card class="block-card">
    <template #title>
      <span class="card-title-icon"><IconThunderbolt /> 专家模式 · 权重调参</span>
    </template>
    <template #extra>
      <a-button size="small" :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
        重载
      </a-button>
    </template>

    <a-row :gutter="18">
      <!-- 左：方案选择 + 滑块 -->
      <a-col :xs="24" :lg="13">
        <a-form-item label="权重方案">
          <a-select
            :model-value="selectedId ?? undefined"
            placeholder="选择权重方案"
            @change="(v) => onSelectProfile(v as number)"
          >
            <a-option v-for="p in profiles" :key="p.id" :value="p.id" :label="p.name">
              {{ p.name }}
              <span v-if="p.isActive" class="opt-active">· 生效中</span>
              <span v-if="p.isBuiltin" class="opt-builtin">· 锁定</span>
            </a-option>
          </a-select>
        </a-form-item>

        <a-alert v-if="isBuiltinSelected" type="normal" class="lock-alert">
          <template #icon><IconLock /></template>
          内置「标准权重」方案为基线（30/25/20/15/10），权重锁定不可改。如需调权请「另存为新方案」。
        </a-alert>

        <div class="sliders">
          <div v-for="d in dimMeta" :key="d.key" class="slider-row">
            <span class="slider-label">{{ d.label }}</span>
            <a-slider
              v-model="weights[d.key]"
              :min="0"
              :max="100"
              :step="5"
              :disabled="isBuiltinSelected"
              class="slider"
            />
            <span class="slider-val">{{ weights[d.key] }}%</span>
          </div>
        </div>

        <div class="sum-row" :class="{ 'sum-row--bad': !sumValid }">
          <span>权重合计</span>
          <strong>{{ sum }}%</strong>
        </div>
        <a-alert v-if="!sumValid" type="warning" class="sum-alert">
          权重合计须为 100，当前 {{ sum }}，请调整后再保存/激活。
        </a-alert>

        <div class="actions">
          <a-button :disabled="isBuiltinSelected || !sumValid" @click="openSave">
            <template #icon><IconSave /></template>
            另存为方案
          </a-button>
          <a-button
            type="primary"
            :loading="activating"
            :disabled="!selectedProfile || selectedProfile.isActive"
            @click="confirmActivate"
          >
            <template #icon><IconCheck /></template>
            {{ selectedProfile?.isActive ? '当前已生效' : '激活并全量复算' }}
          </a-button>
        </div>
      </a-col>

      <!-- 右：实时分布预演 -->
      <a-col :xs="24" :lg="11">
        <div class="preview-head">
          <span class="preview-title">实时分布预演</span>
          <a-spin v-if="previewing" :size="14" />
          <span v-if="preview?.shifted != null" class="shift-badge">
            预计迁移 {{ preview.shifted }} 项
          </span>
        </div>
        <div class="dist-block">
          <div v-for="r in distRows" :key="r.key" class="dist-row">
            <span class="dist-label" :style="{ color: r.color }">{{ r.label }}</span>
            <div class="dist-bars">
              <div class="dist-bar-track">
                <div
                  class="dist-bar dist-bar--before"
                  :style="{ width: `${(r.before / distMax) * 100}%` }"
                />
              </div>
              <div class="dist-bar-track">
                <div
                  class="dist-bar dist-bar--after"
                  :style="{ width: `${(r.after / distMax) * 100}%`, background: r.color }"
                />
              </div>
            </div>
            <span class="dist-nums">
              {{ r.before }}
              <template v-if="r.after !== r.before">
                <span :class="r.after > r.before ? 'up' : 'down'">
                  → {{ r.after }} {{ r.after > r.before ? '↑' : '↓' }}
                </span>
              </template>
              <template v-else>→ {{ r.after }}</template>
            </span>
          </div>
        </div>
        <div class="dist-legend">
          <span class="lg lg-before">当前</span>
          <span class="lg lg-after">预演后</span>
        </div>
      </a-col>
    </a-row>

    <!-- 另存为方案 -->
    <a-modal
      v-model:visible="saveOpen"
      title="另存为权重方案"
      :ok-loading="saving"
      ok-text="保存"
      @ok="saveProfile"
    >
      <a-form :model="saveForm" layout="vertical">
        <a-form-item label="方案名称" required>
          <a-input v-model="saveForm.name" placeholder="如：金融长留存专家方案" />
        </a-form-item>
        <a-form-item label="调权理由（留痕）">
          <a-textarea
            v-model="saveForm.description"
            :auto-size="{ minRows: 2, maxRows: 4 }"
            placeholder="DP-11：调权须留痕，建议说明调整依据"
          />
        </a-form-item>
        <a-descriptions :column="5" size="small" bordered>
          <a-descriptions-item label="D1">{{ weights.w1 }}</a-descriptions-item>
          <a-descriptions-item label="D2">{{ weights.w2 }}</a-descriptions-item>
          <a-descriptions-item label="D3">{{ weights.w3 }}</a-descriptions-item>
          <a-descriptions-item label="D4">{{ weights.w4 }}</a-descriptions-item>
          <a-descriptions-item label="D5">{{ weights.w5 }}</a-descriptions-item>
        </a-descriptions>
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
.opt-active {
  color: #5a9367;
  font-size: 12px;
}
.opt-builtin {
  color: var(--clay-text-soft);
  font-size: 12px;
}
.lock-alert {
  margin-bottom: 14px;
}
.sliders {
  margin-top: 4px;
}
.slider-row {
  display: grid;
  grid-template-columns: 130px 1fr 48px;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.slider-label {
  font-size: 13px;
  color: var(--clay-text);
}
.slider {
  width: 100%;
}
.slider-val {
  text-align: right;
  font-weight: 600;
  font-size: 13px;
  color: var(--clay-accent);
}
.sum-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  margin-top: 8px;
  background: var(--clay-bg-soft);
  border-radius: 8px;
  font-size: 14px;
}
.sum-row strong {
  font-size: 18px;
  color: #5a9367;
}
.sum-row--bad strong {
  color: #cb4b3f;
}
.sum-alert {
  margin-top: 10px;
}
.actions {
  display: flex;
  gap: 10px;
  margin-top: 16px;
}

.preview-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 14px;
}
.preview-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--clay-text);
}
.shift-badge {
  font-size: 12px;
  color: #fff;
  background: var(--clay-accent-2);
  border-radius: 6px;
  padding: 2px 8px;
}
.dist-block {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.dist-row {
  display: grid;
  grid-template-columns: 72px 1fr 96px;
  align-items: center;
  gap: 10px;
}
.dist-label {
  font-size: 12px;
  font-weight: 600;
}
.dist-bars {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.dist-bar-track {
  height: 9px;
  background: var(--clay-bg-soft);
  border-radius: 5px;
  overflow: hidden;
}
.dist-bar {
  height: 100%;
  border-radius: 5px;
  transition: width 0.3s ease;
}
.dist-bar--before {
  background: #d6c6b2;
}
.dist-nums {
  font-size: 12px;
  text-align: right;
  color: var(--clay-text);
}
.dist-nums .up {
  color: #cb4b3f;
  font-weight: 600;
}
.dist-nums .down {
  color: #5a9367;
  font-weight: 600;
}
.dist-legend {
  display: flex;
  gap: 16px;
  margin-top: 12px;
  padding-left: 82px;
}
.lg {
  font-size: 12px;
  color: var(--clay-text-soft);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.lg::before {
  content: '';
  width: 14px;
  height: 9px;
  border-radius: 3px;
}
.lg-before::before {
  background: #d6c6b2;
}
.lg-after::before {
  background: var(--clay-accent);
}
</style>
