<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import { IconPlus, IconRefresh } from '@arco-design/web-vue/es/icon'
import { agentApi } from '@/api'
import type { Agent } from '@/api/types'

const loading = ref(false)
const agents = ref<Agent[]>([])

async function load() {
  loading.value = true
  try {
    agents.value = await agentApi.list()
  } catch {
    Message.error('加载 Agent 列表失败')
  } finally {
    loading.value = false
  }
}
onMounted(load)

// 注册抽屉
const drawer = ref(false)
const form = reactive<{ hostname: string; kind: string; labels: string[]; os: string }>({
  hostname: '',
  kind: 'host',
  labels: [],
  os: '',
})
function openDrawer() {
  form.hostname = ''
  form.kind = 'host'
  form.labels = []
  form.os = ''
  drawer.value = true
}

// 一次性 apiKey 弹窗
const keyModal = ref(false)
const newKey = ref('')
const newAgentId = ref('')

async function submit() {
  if (!form.hostname) {
    Message.warning('主机名必填')
    return
  }
  try {
    const resp = await agentApi.create({
      hostname: form.hostname,
      kind: form.kind,
      labels: form.labels,
      os: form.os,
    })
    drawer.value = false
    newKey.value = resp.apiKey
    newAgentId.value = resp.agent.agentId
    keyModal.value = true
    load()
  } catch {
    Message.error('注册失败')
  }
}

function revoke(a: Agent) {
  Modal.warning({
    title: '撤销 Agent',
    content: `撤销 ${a.agentId} 后其 apiKey 立即失效，确认？`,
    hideCancel: false,
    onOk: async () => {
      await agentApi.revoke(a.id)
      Message.success('已撤销')
      load()
    },
  })
}

function kindColor(k: string) {
  return k === 'probe' ? 'purple' : k === 'both' ? 'arcoblue' : 'green'
}
function copyKey() {
  navigator.clipboard?.writeText(newKey.value)
  Message.success('已复制')
}
</script>

<template>
  <div class="page">
    <div class="bar">
      <div class="title">Agent / 探针管理</div>
      <a-space>
        <a-button @click="load"><template #icon><IconRefresh /></template>刷新</a-button>
        <a-button type="primary" @click="openDrawer"><template #icon><IconPlus /></template>注册 Agent</a-button>
      </a-space>
    </div>

    <a-table :data="agents" :loading="loading" :pagination="{ pageSize: 15 }" row-key="id">
      <template #columns>
        <a-table-column title="Agent ID" data-index="agentId" :width="150" />
        <a-table-column title="主机名" data-index="hostname" />
        <a-table-column title="种类" :width="90">
          <template #cell="{ record }">
            <a-tag :color="kindColor(record.kind)">{{ record.kind }}</a-tag>
          </template>
        </a-table-column>
        <a-table-column title="标签" :width="200">
          <template #cell="{ record }">
            <a-space wrap>
              <a-tag v-for="l in record.labels || []" :key="l" size="small">{{ l }}</a-tag>
              <span v-if="!(record.labels || []).length" class="dim">—</span>
            </a-space>
          </template>
        </a-table-column>
        <a-table-column title="状态" :width="90">
          <template #cell="{ record }">
            <a-tag :color="record.status === 'active' ? 'green' : 'gray'">{{ record.status === 'active' ? '活跃' : '已撤销' }}</a-tag>
          </template>
        </a-table-column>
        <a-table-column title="OS" data-index="os" :width="120" />
        <a-table-column title="最近上报" :width="170">
          <template #cell="{ record }">{{ record.lastSeenAt ? String(record.lastSeenAt).slice(0, 19).replace('T', ' ') : '—' }}</template>
        </a-table-column>
        <a-table-column title="操作" :width="90">
          <template #cell="{ record }">
            <a-button v-if="record.status === 'active'" status="danger" size="mini" @click="revoke(record)">撤销</a-button>
          </template>
        </a-table-column>
      </template>
    </a-table>

    <!-- 注册抽屉 -->
    <a-drawer v-model:visible="drawer" title="注册 Agent / 探针" :width="420" @ok="submit">
      <a-form :model="form" layout="vertical">
        <a-form-item label="主机名" required>
          <a-input v-model="form.hostname" placeholder="如 web-01" />
        </a-form-item>
        <a-form-item label="种类">
          <a-radio-group v-model="form.kind">
            <a-radio value="host">host 主机发现</a-radio>
            <a-radio value="probe">probe 抓包探针</a-radio>
            <a-radio value="both">both</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="标签（用于抓包任务分发）">
          <a-input-tag v-model="form.labels" placeholder="回车添加，如 机房A / 核心网段" allow-clear />
        </a-form-item>
        <a-form-item label="操作系统（可选）">
          <a-input v-model="form.os" placeholder="如 Ubuntu 24.04 / UOS" />
        </a-form-item>
      </a-form>
    </a-drawer>

    <!-- 一次性 apiKey 弹窗 -->
    <a-modal v-model:visible="keyModal" title="Agent 已注册" :footer="false" :width="560">
      <a-alert type="warning" style="margin-bottom: 12px">apiKey 仅显示一次，平台只存哈希，请立即保存并配置到 Agent</a-alert>
      <div class="kv"><span>Agent ID</span><b>{{ newAgentId }}</b></div>
      <div class="kv"><span>apiKey</span><a-typography-text code copyable :copy-text="newKey">{{ newKey }}</a-typography-text></div>
      <a-button style="margin-top: 12px" type="primary" long @click="copyKey">复制 apiKey</a-button>
    </a-modal>
  </div>
</template>

<style scoped>
.page { padding: 16px; }
.bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
.title { font-size: 18px; font-weight: 600; }
.dim { color: var(--color-text-3); }
.kv { display: flex; gap: 12px; margin: 8px 0; align-items: center; }
.kv > span { width: 80px; color: var(--color-text-3); }
</style>
