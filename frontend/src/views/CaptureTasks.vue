<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import { IconPlus, IconRefresh } from '@arco-design/web-vue/es/icon'
import { agentApi, captureApi } from '@/api'
import type { Agent, CaptureTask } from '@/api/types'

const loading = ref(false)
const tasks = ref<CaptureTask[]>([])
const agents = ref<Agent[]>([])

// 标签选项 = 所有 agent 的 labels 并集
const labelOptions = computed(() => {
  const set = new Set<string>()
  agents.value.forEach((a) => (a.labels || []).forEach((l) => set.add(l)))
  return [...set]
})

async function load() {
  loading.value = true
  try {
    tasks.value = await captureApi.list()
  } catch {
    Message.error('加载抓包任务失败')
  } finally {
    loading.value = false
  }
}

let timer: number | undefined
onMounted(async () => {
  await load()
  try {
    agents.value = await agentApi.list()
  } catch {
    /* 标签选项非关键 */
  }
  timer = window.setInterval(load, 2500)
})
onUnmounted(() => timer && window.clearInterval(timer))

// 新建抽屉
const drawer = ref(false)
const form = reactive<{
  name: string
  labelSelector: string[]
  iface: string
  bpf: string
  duration: number
  maxPackets: number
  scheduleEnabled: boolean
  schedule: string
}>({
  name: '',
  labelSelector: [],
  iface: '',
  bpf: 'tcp',
  duration: 30,
  maxPackets: 100000,
  scheduleEnabled: false,
  schedule: '',
})
function openDrawer() {
  Object.assign(form, {
    name: '',
    labelSelector: [],
    iface: '',
    bpf: 'tcp',
    duration: 30,
    maxPackets: 100000,
    scheduleEnabled: false,
    schedule: '',
  })
  drawer.value = true
}

async function submit() {
  if (!form.name) {
    Message.warning('任务名必填')
    return
  }
  try {
    await captureApi.create({ ...form })
    drawer.value = false
    Message.success('任务已下发')
    load()
  } catch {
    Message.error('建任务失败')
  }
}

function cancel(t: CaptureTask) {
  Modal.warning({
    title: '取消任务',
    content: `取消「${t.name}」？周期任务将停止再入队。`,
    hideCancel: false,
    onOk: async () => {
      await captureApi.cancel(t.id)
      load()
    },
  })
}
function remove(t: CaptureTask) {
  Modal.warning({
    title: '删除任务',
    content: `删除「${t.name}」？`,
    hideCancel: false,
    onOk: async () => {
      await captureApi.remove(t.id)
      load()
    },
  })
}

const statusColor: Record<string, string> = {
  pending: 'gray',
  leased: 'arcoblue',
  done: 'green',
  failed: 'red',
  cancelled: 'gray',
}
const statusText: Record<string, string> = {
  pending: '待领取',
  leased: '抓包中',
  done: '完成',
  failed: '失败',
  cancelled: '已取消',
}
function fmt(t?: string | null) {
  return t ? String(t).slice(0, 19).replace('T', ' ') : '—'
}
</script>

<template>
  <div class="page">
    <div class="bar">
      <div>
        <div class="title">抓包任务</div>
        <div class="sub">控制台一处建任务，按标签选择器自动分发给一类探针（拉取式租约领取）</div>
      </div>
      <a-space>
        <a-button @click="load"><template #icon><IconRefresh /></template>刷新</a-button>
        <a-button type="primary" @click="openDrawer"><template #icon><IconPlus /></template>新建抓包任务</a-button>
      </a-space>
    </div>

    <a-table :data="tasks" :loading="loading" :pagination="{ pageSize: 15 }" row-key="id">
      <template #columns>
        <a-table-column title="名称" data-index="name" :width="160" />
        <a-table-column title="标签选择器" :width="180">
          <template #cell="{ record }">
            <a-space wrap>
              <a-tag v-for="l in record.labelSelector || []" :key="l" size="small" color="arcoblue">{{ l }}</a-tag>
              <span v-if="!(record.labelSelector || []).length" class="dim">任意探针</span>
            </a-space>
          </template>
        </a-table-column>
        <a-table-column title="状态" :width="100">
          <template #cell="{ record }">
            <a-tag :color="statusColor[record.status] || 'gray'">{{ statusText[record.status] || record.status }}</a-tag>
          </template>
        </a-table-column>
        <a-table-column title="领取探针" :width="130">
          <template #cell="{ record }">{{ record.leasedBy || '—' }}</template>
        </a-table-column>
        <a-table-column title="网卡/BPF/时长" :width="160">
          <template #cell="{ record }">{{ record.iface || 'any' }} / {{ record.bpf }} / {{ record.duration }}s</template>
        </a-table-column>
        <a-table-column title="结果/次数" :width="100">
          <template #cell="{ record }">{{ record.resultCount ?? 0 }} / {{ record.runCount ?? 0 }}</template>
        </a-table-column>
        <a-table-column title="周期" :width="150">
          <template #cell="{ record }">
            <span v-if="record.scheduleEnabled">{{ record.schedule }}（下次 {{ fmt(record.nextRunAt) }}）</span>
            <span v-else class="dim">一次性</span>
          </template>
        </a-table-column>
        <a-table-column title="操作" :width="130">
          <template #cell="{ record }">
            <a-space>
              <a-button
                v-if="record.status === 'pending' || record.status === 'leased'"
                size="mini"
                @click="cancel(record)"
                >取消</a-button
              >
              <a-button size="mini" status="danger" @click="remove(record)">删除</a-button>
            </a-space>
          </template>
        </a-table-column>
      </template>
    </a-table>

    <!-- 新建抽屉 -->
    <a-drawer v-model:visible="drawer" title="新建抓包任务" :width="460" @ok="submit">
      <a-form :model="form" layout="vertical">
        <a-form-item label="任务名" required>
          <a-input v-model="form.name" placeholder="如 核心网段-PQC 监测" />
        </a-form-item>
        <a-form-item label="标签选择器（空=任意探针可领；探针标签需含全部所选）">
          <a-select v-model="form.labelSelector" multiple allow-create placeholder="选或输入标签" :options="labelOptions.map((l) => ({ label: l, value: l }))" />
        </a-form-item>
        <a-form-item label="网卡（空=探针默认/any）">
          <a-input v-model="form.iface" placeholder="如 eth0" />
        </a-form-item>
        <a-form-item label="BPF 过滤（tcpdump 回退用）">
          <a-input v-model="form.bpf" placeholder="tcp" />
        </a-form-item>
        <a-form-item label="抓包时长（秒）">
          <a-input-number v-model="form.duration" :min="1" :max="3600" />
        </a-form-item>
        <a-form-item label="抓包数上限">
          <a-input-number v-model="form.maxPackets" :min="100" :step="10000" />
        </a-form-item>
        <a-form-item label="周期性">
          <a-switch v-model="form.scheduleEnabled" />
        </a-form-item>
        <a-form-item v-if="form.scheduleEnabled" label="cron 表达式">
          <a-input v-model="form.schedule" placeholder="如 0 * * * *（每小时）" />
        </a-form-item>
      </a-form>
    </a-drawer>
  </div>
</template>

<style scoped>
.page { padding: 16px; }
.bar { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.title { font-size: 18px; font-weight: 600; }
.sub { color: var(--color-text-3); font-size: 12px; margin-top: 4px; }
.dim { color: var(--color-text-3); }
</style>
