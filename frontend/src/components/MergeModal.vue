<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconBranch, IconRefresh } from '@arco-design/web-vue/es/icon'
import { dedupApi } from '@/api'
import type { CryptoAsset, DedupCluster } from '@/api/types'

const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'merged'): void
}>()

const loading = ref(false)
const merging = ref(false)
const clusters = ref<DedupCluster[]>([])

// 当前选中的簇下标
const activeIdx = ref(0)
// 选中的主资产 ID 与被并入的资产 ID 集合
const primaryId = ref<number | undefined>(undefined)
const mergeIds = ref<number[]>([])
// 合并表单为纯布局（v-model 直绑 ref），a-form 仍需 model 占位。
const mergeFormModel = reactive({})

const KEYTYPE_LABEL: Record<string, string> = {
  certFingerprint: '证书指纹',
  endpoint: '端点+协议',
  name: '名称模糊',
}

const activeCluster = computed<DedupCluster | null>(
  () => clusters.value[activeIdx.value] ?? null,
)

function keyTypeLabel(t: string): string {
  return KEYTYPE_LABEL[t] ?? t
}

async function load() {
  loading.value = true
  try {
    clusters.value = await dedupApi.candidates()
    activeIdx.value = 0
    resetSelection()
  } catch {
    Message.error('加载重复资产候选失败')
  } finally {
    loading.value = false
  }
}

function resetSelection() {
  const c = activeCluster.value
  if (c && c.assets.length) {
    // 默认主资产＝来源置信度最高/最早的一条（取第一条）。
    primaryId.value = c.assets[0].id
    mergeIds.value = c.assets.slice(1).map((a) => a.id)
  } else {
    primaryId.value = undefined
    mergeIds.value = []
  }
}

function selectCluster(idx: number) {
  activeIdx.value = idx
  resetSelection()
}

// 主资产变更时，被并入集合＝该簇其余项默认全选，但允许手动取消。
function onPrimaryChange(id: number) {
  primaryId.value = id
  const c = activeCluster.value
  if (c) {
    mergeIds.value = c.assets
      .filter((a) => a.id !== id && mergeIds.value.includes(a.id))
      .map((a) => a.id)
    // 若全空则默认把其余项纳入。
    if (!mergeIds.value.length) {
      mergeIds.value = c.assets.filter((a) => a.id !== id).map((a) => a.id)
    }
  }
}

const mergeOptions = computed(() => {
  const c = activeCluster.value
  if (!c) return []
  return c.assets.filter((a) => a.id !== primaryId.value)
})

function assetLabel(a: CryptoAsset): string {
  const parts = [a.name]
  if (a.algorithm) parts.push(a.algorithm)
  if (a.source) parts.push(`来源:${a.source}`)
  return parts.join(' · ')
}

async function confirm() {
  if (primaryId.value == null) {
    Message.warning('请选择主资产')
    return
  }
  if (!mergeIds.value.length) {
    Message.warning('请至少选择一个被合并资产')
    return
  }
  merging.value = true
  try {
    await dedupApi.merge({ primaryId: primaryId.value, mergeIds: mergeIds.value })
    Message.success(`已合并 ${mergeIds.value.length} 个重复资产`)
    emit('merged')
    emit('update:visible', false)
  } catch {
    Message.error('合并失败')
  } finally {
    merging.value = false
  }
}

watch(
  () => props.visible,
  (v) => {
    if (v) load()
  },
)
</script>

<template>
  <a-modal
    :visible="visible"
    title="合并重复资产"
    :width="720"
    :ok-loading="merging"
    ok-text="确认合并"
    cancel-text="取消"
    :ok-button-props="{ disabled: !activeCluster }"
    @ok="confirm"
    @cancel="emit('update:visible', false)"
  >
    <a-spin :loading="loading" style="width: 100%">
      <div v-if="!clusters.length" class="empty-inline">
        <a-empty description="未发现重复资产簇，无需合并" />
      </div>

      <template v-else>
        <div class="merge-hint">
          <IconBranch />
          按去重主键（证书指纹 → 端点+协议 → 名称模糊）发现 {{ clusters.length }} 个重复簇。
          选择一个簇，指定保留的主资产与被并入的资产，确认后被并资产置「已合并」并保留证据链。
          <a-button size="mini" type="text" :loading="loading" @click="load">
            <template #icon><IconRefresh /></template>
          </a-button>
        </div>

        <!-- 簇选择 -->
        <div class="cluster-tabs">
          <div
            v-for="(c, idx) in clusters"
            :key="c.key"
            class="cluster-tab"
            :class="{ 'cluster-tab--active': idx === activeIdx }"
            @click="selectCluster(idx)"
          >
            <a-tag size="small" :color="idx === activeIdx ? 'orange' : undefined" bordered>
              {{ keyTypeLabel(c.keyType) }}
            </a-tag>
            <span class="cluster-count">{{ c.assets.length }} 项</span>
          </div>
        </div>

        <template v-if="activeCluster">
          <a-form :model="mergeFormModel" layout="vertical" class="merge-form">
            <a-form-item label="保留为主资产">
              <a-radio-group
                :model-value="primaryId"
                direction="vertical"
                @change="onPrimaryChange($event as number)"
              >
                <a-radio
                  v-for="a in activeCluster.assets"
                  :key="a.id"
                  :value="a.id"
                  class="asset-radio"
                >
                  {{ assetLabel(a) }}
                </a-radio>
              </a-radio-group>
            </a-form-item>

            <a-form-item label="并入主资产（被合并）">
              <a-checkbox-group v-model="mergeIds" direction="vertical">
                <a-checkbox
                  v-for="a in mergeOptions"
                  :key="a.id"
                  :value="a.id"
                  class="asset-radio"
                >
                  {{ assetLabel(a) }}
                </a-checkbox>
              </a-checkbox-group>
              <div v-if="!mergeOptions.length" class="field-hint">
                该簇仅一条资产，请切换主资产或换簇。
              </div>
            </a-form-item>
          </a-form>
        </template>
      </template>
    </a-spin>
  </a-modal>
</template>

<style scoped>
.empty-inline {
  padding: 24px 0;
}
.merge-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--brand-text-soft);
  background: var(--brand-bg-soft);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 14px;
}
.cluster-tabs {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}
.cluster-tab {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 1px solid var(--brand-border);
  border-radius: 8px;
  padding: 6px 10px;
  cursor: pointer;
  transition: all 0.18s;
  background: #FFFFFF;
}
.cluster-tab:hover {
  border-color: var(--brand-accent-2);
}
.cluster-tab--active {
  border-color: var(--brand-accent);
  background: #E8F3FF;
}
.cluster-count {
  font-size: 12px;
  color: var(--brand-text-soft);
}
.merge-form {
  margin-top: 4px;
}
.asset-radio {
  display: flex;
  margin-bottom: 8px;
  font-size: 13px;
}
.field-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
}
</style>
