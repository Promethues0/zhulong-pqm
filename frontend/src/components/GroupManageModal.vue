<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import {
  IconRefresh,
  IconPlus,
  IconEdit,
  IconDelete,
} from '@arco-design/web-vue/es/icon'
import { groupApi } from '@/api'
import type { AssetGroup, AssetGroupInput } from '@/api/types'
import { groupKindMeta } from '@/utils/format'

/**
 * 资产分组管理：增删改 AssetGroup。
 * 受控 visible，关闭时若有变更 emit('changed') 通知父页刷新分组下拉与聚合卡。
 */
const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'changed'): void
}>()

const loading = ref(false)
const submitting = ref(false)
const groups = ref<AssetGroup[]>([])
let dirty = false

// ---- 编辑/新增表单（同一弹层内联） ----
const editing = ref<AssetGroup | null>(null)
const form = reactive<AssetGroupInput>({
  name: '',
  kind: 'business',
  description: '',
})

const kindOptions = [
  { value: 'business', label: '业务线' },
  { value: 'system', label: '系统' },
  { value: 'department', label: '部门' },
  { value: 'custom', label: '自定义' },
]

const columns = [
  { title: '名称', slotName: 'name', minWidth: 140 },
  { title: '类型', slotName: 'kind', width: 110 },
  { title: '描述', dataIndex: 'description', minWidth: 160, ellipsis: true, tooltip: true },
  { title: '操作', slotName: 'actions', width: 100, align: 'center' as const },
]

function resetForm() {
  editing.value = null
  form.name = ''
  form.kind = 'business'
  form.description = ''
}

async function load() {
  loading.value = true
  try {
    groups.value = await groupApi.list()
  } catch {
    Message.error('加载分组失败')
  } finally {
    loading.value = false
  }
}

function startEdit(g: AssetGroup) {
  editing.value = g
  form.name = g.name
  form.kind = g.kind
  form.description = g.description ?? ''
}

async function submit() {
  if (!form.name.trim()) {
    Message.warning('请填写分组名称')
    return
  }
  submitting.value = true
  try {
    const payload: AssetGroupInput = {
      name: form.name.trim(),
      kind: form.kind,
      description: form.description?.trim() || '',
    }
    if (editing.value) {
      await groupApi.update(editing.value.id, payload)
      Message.success('分组已更新')
    } else {
      await groupApi.create(payload)
      Message.success('分组已创建')
    }
    dirty = true
    resetForm()
    await load()
  } catch {
    Message.error('保存分组失败（名称可能重复）')
  } finally {
    submitting.value = false
  }
}

function confirmDelete(g: AssetGroup) {
  Modal.warning({
    title: '删除分组',
    content: `确认删除分组「${g.name}」？分组下资产不会被删除，仅解除归属。`,
    okText: '删除',
    cancelText: '取消',
    hideCancel: false,
    onOk: async () => {
      try {
        await groupApi.remove(g.id)
        Message.success('分组已删除')
        dirty = true
        if (editing.value?.id === g.id) resetForm()
        await load()
      } catch {
        Message.error('删除分组失败')
      }
    },
  })
}

function onClose() {
  emit('update:visible', false)
  if (dirty) {
    emit('changed')
    dirty = false
  }
}

watch(
  () => props.visible,
  (v) => {
    if (v) {
      dirty = false
      resetForm()
      load()
    }
  },
)
</script>

<template>
  <a-modal
    :visible="visible"
    title="资产分组管理"
    :width="640"
    :footer="false"
    unmount-on-close
    @cancel="onClose"
    @update:visible="(v: boolean) => !v && onClose()"
  >
    <!-- 新增/编辑表单 -->
    <a-form :model="form" layout="inline" class="group-form">
      <a-form-item label="名称" required>
        <a-input v-model="form.name" placeholder="分组名称" allow-clear style="width: 150px" />
      </a-form-item>
      <a-form-item label="类型">
        <a-select v-model="form.kind" style="width: 120px">
          <a-option v-for="k in kindOptions" :key="k.value" :value="k.value">
            {{ k.label }}
          </a-option>
        </a-select>
      </a-form-item>
      <a-form-item label="描述">
        <a-input v-model="form.description" placeholder="可选" allow-clear style="width: 140px" />
      </a-form-item>
      <a-form-item>
        <a-space>
          <a-button type="primary" :loading="submitting" @click="submit">
            <template #icon><IconPlus v-if="!editing" /><IconEdit v-else /></template>
            {{ editing ? '更新' : '新增' }}
          </a-button>
          <a-button v-if="editing" @click="resetForm">取消</a-button>
        </a-space>
      </a-form-item>
    </a-form>

    <a-divider style="margin: 12px 0" />

    <div class="list-head">
      <span class="muted">共 {{ groups.length }} 个分组</span>
      <a-button size="small" :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
      </a-button>
    </div>

    <a-table
      :data="groups"
      :columns="columns"
      :loading="loading"
      :pagination="{ pageSize: 6, hideOnSinglePage: true }"
      row-key="id"
      :scroll="{ x: 480 }"
    >
      <template #name="{ record }">
        <span class="g-name">{{ record.name }}</span>
      </template>
      <template #kind="{ record }">
        <a-tag :color="groupKindMeta(record.kind).color" size="small">
          {{ groupKindMeta(record.kind).label }}
        </a-tag>
      </template>
      <template #actions="{ record }">
        <a-space :size="2">
          <a-button size="mini" type="text" @click="startEdit(record)">
            <template #icon><IconEdit /></template>
          </a-button>
          <a-button size="mini" type="text" status="danger" @click="confirmDelete(record)">
            <template #icon><IconDelete /></template>
          </a-button>
        </a-space>
      </template>
      <template #empty>
        <a-empty description="暂无分组，先在上方新增" />
      </template>
    </a-table>
  </a-modal>
</template>

<style scoped>
.group-form {
  row-gap: 10px;
}
.list-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.muted {
  font-size: 12px;
  color: var(--brand-text-soft);
}
.g-name {
  font-weight: 500;
  color: var(--brand-text);
}
</style>
