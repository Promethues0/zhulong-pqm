<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { Message } from '@arco-design/web-vue'
import type { AxiosError } from 'axios'
import { assetApi } from '@/api'
import type { CryptoAsset, CryptoAssetInput } from '@/api/types'

const props = defineProps<{
  visible: boolean
  /** 传入则编辑模式，否则新建。 */
  asset?: CryptoAsset | null
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'saved'): void
}>()

const saving = ref(false)

const isEdit = computed(() => !!props.asset?.id)

const form = reactive<{
  name: string
  system: string
  layer: string
  department: string
  owner: string
  algorithm: string
  keySize: number | undefined
  protocol: string
  endpoint: string
  exposure: string
  status: string
  suggestedAlgo: string
}>({
  name: '',
  system: '',
  layer: 'L1',
  department: '',
  owner: '',
  algorithm: '',
  keySize: undefined,
  protocol: '',
  endpoint: '',
  exposure: 'internal',
  status: 'discovered',
  suggestedAlgo: '',
})

// 状态机合法迁移白名单（FR-4.4.1）；新建无此约束。
const STATUS_TRANSITIONS: Record<string, string[]> = {
  discovered: ['discovered', 'confirmed', 'archived'],
  confirmed: ['confirmed', 'archived'],
  archived: ['archived', 'confirmed'],
  merged: ['merged'],
}

const STATUS_LABEL: Record<string, string> = {
  discovered: '已发现',
  confirmed: '已确认',
  archived: '已归档',
  merged: '已合并',
}

// 编辑时，状态下拉仅显示从当前状态合法可达的目标。
const statusOptions = computed(() => {
  if (!isEdit.value) return ['discovered', 'confirmed', 'archived']
  const from = props.asset?.status ?? 'discovered'
  return STATUS_TRANSITIONS[from] ?? [from]
})

function fillFromAsset(a?: CryptoAsset | null) {
  if (a) {
    form.name = a.name ?? ''
    form.system = a.system ?? ''
    form.layer = a.layer || 'L1'
    form.department = a.department ?? ''
    form.owner = a.owner ?? ''
    form.algorithm = a.algorithm ?? ''
    form.keySize = a.keySize || undefined
    form.protocol = a.protocol ?? ''
    form.endpoint = a.endpoint ?? ''
    form.exposure = a.exposure || 'internal'
    form.status = a.status || 'discovered'
    form.suggestedAlgo = a.suggestedAlgo ?? ''
  } else {
    form.name = ''
    form.system = ''
    form.layer = 'L1'
    form.department = ''
    form.owner = ''
    form.algorithm = ''
    form.keySize = undefined
    form.protocol = ''
    form.endpoint = ''
    form.exposure = 'internal'
    form.status = 'discovered'
    form.suggestedAlgo = ''
  }
}

async function save() {
  if (!form.name.trim()) {
    Message.warning('请填写资产名称')
    return
  }
  const payload: CryptoAssetInput = {
    name: form.name.trim(),
    system: form.system.trim(),
    layer: form.layer,
    department: form.department.trim(),
    owner: form.owner.trim(),
    algorithm: form.algorithm.trim(),
    keySize: form.keySize || 0,
    protocol: form.protocol.trim(),
    endpoint: form.endpoint.trim(),
    exposure: form.exposure,
    status: form.status,
    suggestedAlgo: form.suggestedAlgo.trim(),
  }
  saving.value = true
  try {
    if (isEdit.value && props.asset) {
      await assetApi.update(props.asset.id, payload)
      Message.success('资产已更新')
    } else {
      await assetApi.create(payload)
      Message.success('资产已创建')
    }
    emit('saved')
    emit('update:visible', false)
  } catch (e) {
    const err = e as AxiosError<{ error?: string }>
    if (err.response?.status === 422) {
      // 非法状态迁移：后端 422 + error 文案。
      Message.error(err.response.data?.error || '非法状态迁移，已被后端拒绝')
    } else {
      Message.error(isEdit.value ? '更新资产失败' : '创建资产失败')
    }
  } finally {
    saving.value = false
  }
}

watch(
  () => props.visible,
  (v) => {
    if (v) fillFromAsset(props.asset)
  },
)
</script>

<template>
  <a-drawer
    :visible="visible"
    :width="480"
    :title="isEdit ? `编辑资产 · ${asset?.name}` : '新增资产'"
    :ok-loading="saving"
    ok-text="保存"
    cancel-text="取消"
    @ok="save"
    @cancel="emit('update:visible', false)"
  >
    <a-form :model="form" layout="vertical">
      <a-form-item label="资产名称" required>
        <a-input v-model="form.name" placeholder="如 api.example.com:443" allow-clear />
      </a-form-item>
      <a-row :gutter="12">
        <a-col :span="12">
          <a-form-item label="所属系统">
            <a-input v-model="form.system" placeholder="系统名" allow-clear />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item label="层级">
            <a-select v-model="form.layer">
              <a-option value="L1">L1 应用/会话层</a-option>
              <a-option value="L2">L2 协议/传输层</a-option>
              <a-option value="L3">L3 数据存储层</a-option>
              <a-option value="L4">L4 硬件/根信任层</a-option>
            </a-select>
          </a-form-item>
        </a-col>
      </a-row>
      <a-row :gutter="12">
        <a-col :span="12">
          <a-form-item label="责任部门">
            <a-input v-model="form.department" placeholder="部门" allow-clear />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item label="责任人">
            <a-input v-model="form.owner" placeholder="责任人" allow-clear />
          </a-form-item>
        </a-col>
      </a-row>
      <a-row :gutter="12">
        <a-col :span="14">
          <a-form-item label="当前算法">
            <a-input v-model="form.algorithm" placeholder="如 RSA-2048 / ECDSA / SM2" allow-clear />
          </a-form-item>
        </a-col>
        <a-col :span="10">
          <a-form-item label="密钥长度">
            <a-input-number v-model="form.keySize" placeholder="bit" :min="0" />
          </a-form-item>
        </a-col>
      </a-row>
      <a-row :gutter="12">
        <a-col :span="12">
          <a-form-item label="协议">
            <a-input v-model="form.protocol" placeholder="如 TLS 1.3 / IKEv2" allow-clear />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item label="暴露面">
            <a-select v-model="form.exposure">
              <a-option value="internal">内网 internal</a-option>
              <a-option value="dmz">DMZ</a-option>
              <a-option value="public">公网 public</a-option>
            </a-select>
          </a-form-item>
        </a-col>
      </a-row>
      <a-form-item label="端点">
        <a-input v-model="form.endpoint" placeholder="host:port" allow-clear />
      </a-form-item>
      <a-form-item label="建议迁移算法">
        <a-input
          v-model="form.suggestedAlgo"
          placeholder="如 X25519+ML-KEM-768 / ML-DSA-65"
          allow-clear
        />
      </a-form-item>
      <a-form-item label="状态">
        <a-select v-model="form.status">
          <a-option v-for="s in statusOptions" :key="s" :value="s">
            {{ STATUS_LABEL[s] ?? s }}
          </a-option>
        </a-select>
        <div v-if="isEdit" class="field-hint">
          仅可迁移到合法状态；非法迁移会被后端拒绝（422）。
        </div>
      </a-form-item>
    </a-form>
  </a-drawer>
</template>

<style scoped>
.field-hint {
  font-size: 12px;
  color: var(--clay-text-soft);
  margin-top: 6px;
}
</style>
