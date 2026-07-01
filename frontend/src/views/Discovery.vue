<script setup lang="ts">
import { onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import {
  IconScan,
  IconRefresh,
  IconEye,
  IconStorage,
  IconImport,
  IconBook,
} from '@arco-design/web-vue/es/icon'
import { scanApi, importApi } from '@/api'
import type { ImportResult, ScanJob, ScanResult } from '@/api/types'
import { fmtDate, jobStatusMeta, exposureMeta } from '@/utils/format'

const router = useRouter()
const submitting = ref(false)
const loading = ref(false)
const jobs = ref<ScanJob[]>([])

// a-upload 自定义请求占位：我们用 @change 自行处理 File，不走内置上传。
const noopRequest = () => ({ abort() {} })

// ---- 导入证据（PEM 证书 / SBOM / 被动流量 pcap）----
const importTab = ref<'pem' | 'sbom' | 'pcap'>('pem')
const importing = ref(false)
const importForm = reactive({
  name: '',
  pem: '',
  sbomText: '',
})

/** 命中规则风险三色（极高=红 / 高=橙 / 中=金）。 */
function hitRiskColor(risk?: string): string {
  switch (risk) {
    case '极高':
      return 'red'
    case '高':
      return 'orange'
    case '中':
      return 'gold'
    default:
      return 'arcoblue'
  }
}

function gotoRules() {
  router.push('/rules')
}

function summarizeImport(r: ImportResult): string {
  const n = r.results?.length ?? r.imported ?? 0
  return `导入完成，新增/命中 ${n} 项密码使用点`
}

async function importPem() {
  if (!importForm.pem.trim()) {
    Message.warning('请粘贴 PEM 证书文本')
    return
  }
  importing.value = true
  try {
    const r = await importApi.pem({
      name: importForm.name.trim() || undefined,
      pem: importForm.pem.trim(),
    })
    Message.success(summarizeImport(r))
    importForm.pem = ''
    await loadJobs()
  } catch {
    Message.error('PEM 证书导入失败')
  } finally {
    importing.value = false
  }
}

async function importSbom() {
  if (!importForm.sbomText.trim()) {
    Message.warning('请粘贴 SBOM（CycloneDX/Syft）JSON')
    return
  }
  let body: unknown
  try {
    body = JSON.parse(importForm.sbomText)
  } catch {
    Message.error('SBOM 不是合法 JSON')
    return
  }
  importing.value = true
  try {
    const r = await importApi.sbom(body)
    Message.success(summarizeImport(r))
    importForm.sbomText = ''
    await loadJobs()
  } catch {
    Message.error('SBOM 导入失败')
  } finally {
    importing.value = false
  }
}

async function onSbomFile(file: File) {
  importing.value = true
  try {
    const fd = new FormData()
    fd.append('file', file)
    if (importForm.name.trim()) fd.append('name', importForm.name.trim())
    const r = await importApi.sbom(fd)
    Message.success(summarizeImport(r))
    await loadJobs()
  } catch {
    Message.error('SBOM 文件导入失败')
  } finally {
    importing.value = false
  }
}

async function onPemFile(file: File) {
  importing.value = true
  try {
    const fd = new FormData()
    fd.append('file', file)
    if (importForm.name.trim()) fd.append('name', importForm.name.trim())
    const r = await importApi.pem(fd)
    Message.success(summarizeImport(r))
    await loadJobs()
  } catch {
    Message.error('证书文件导入失败')
  } finally {
    importing.value = false
  }
}

async function onPcapFile(file: File) {
  importing.value = true
  try {
    const fd = new FormData()
    fd.append('file', file)
    if (importForm.name.trim()) fd.append('name', importForm.name.trim())
    const r = await importApi.pcap(fd)
    const st = (r as unknown as { stats?: { handshakes?: number; endpoints?: number } }).stats
    Message.success(
      st
        ? `被动解析完成：TLS 握手 ${st.handshakes ?? 0} 个 → 服务端点 ${st.endpoints ?? 0} 个`
        : summarizeImport(r),
    )
    await loadJobs()
  } catch (e: unknown) {
    const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
    Message.error(msg || 'pcap 解析失败（仅支持 classic .pcap）')
  } finally {
    importing.value = false
  }
}

// 记录上一轮各任务状态，用于检测「刚刚完成」以提示发现→清单的闭环交接。
const prevStatus = new Map<number, string>()
const lastDone = ref<{ name: string; count: number; error?: string } | null>(null)

const form = reactive({
  name: '',
  targetsText: '',
  exposure: 'internal' as 'internal' | 'dmz' | 'public',
})

// 结果抽屉
const drawerOpen = ref(false)
const detailLoading = ref(false)
const activeJob = ref<ScanJob | null>(null)
const results = ref<ScanResult[]>([])

let pollTimer: number | undefined

const jobColumns = [
  { title: 'ID', dataIndex: 'id', width: 64 },
  { title: '任务名称', dataIndex: 'name' },
  { title: '暴露面', slotName: 'exposure', width: 100 },
  { title: '目标数', slotName: 'targets', width: 90, align: 'right' as const },
  { title: '状态', slotName: 'status', width: 110 },
  { title: '命中数', slotName: 'count', width: 90, align: 'right' as const },
  { title: '完成时间', slotName: 'time', width: 170 },
  { title: '操作', slotName: 'actions', width: 100 },
]

const resultColumns = [
  { title: '主机', dataIndex: 'host', width: 150 },
  { title: '端口', dataIndex: 'port', width: 70 },
  { title: '状态', slotName: 'status', width: 250 },
  { title: 'TLS', dataIndex: 'tlsVersion', width: 84 },
  { title: '密钥算法', slotName: 'keyAlgo', width: 140 },
  { title: '签名算法', dataIndex: 'sigAlgo', width: 120 },
  { title: '命中规则', slotName: 'hits', minWidth: 160 },
  { title: '证书到期', slotName: 'cert', width: 120 },
]

const hasRunning = () =>
  jobs.value.some((j) => j.status === 'pending' || j.status === 'running')

// applyJobs 更新任务列表，并检测「刚刚完成」的任务，提示发现→清单的闭环交接。
function applyJobs(list: ScanJob[]) {
  for (const j of list) {
    const prev = prevStatus.get(j.id)
    if (prev && prev !== 'done' && j.status === 'done') {
      lastDone.value = { name: j.name, count: j.resultCount, error: j.error }
      if (j.resultCount > 0) {
        Message.success(`扫描「${j.name}」完成，新增 ${j.resultCount} 项密码使用点`)
      } else {
        Message.warning(`扫描「${j.name}」完成，但未发现密码学使用点${j.error ? '：' + j.error : ''}`)
      }
    }
    prevStatus.set(j.id, j.status)
  }
  jobs.value = list
}

async function loadJobs() {
  loading.value = true
  try {
    applyJobs(await scanApi.list())
  } catch {
    Message.error('加载扫描任务失败')
  } finally {
    loading.value = false
  }
  schedulePoll()
}

function schedulePoll() {
  if (pollTimer) {
    window.clearTimeout(pollTimer)
    pollTimer = undefined
  }
  if (hasRunning()) {
    pollTimer = window.setTimeout(async () => {
      try {
        applyJobs(await scanApi.list())
      } catch {
        /* 静默轮询失败 */
      }
      schedulePoll()
    }, 2500)
  }
}

function gotoAssets() {
  router.push('/assets')
}

async function submit() {
  const targets = form.targetsText
    .split('\n')
    .map((t) => t.trim())
    .filter(Boolean)
  if (!form.name.trim()) {
    Message.warning('请填写任务名称')
    return
  }
  if (targets.length === 0) {
    Message.warning('请至少填写一个扫描目标')
    return
  }
  submitting.value = true
  try {
    await scanApi.create({
      name: form.name.trim(),
      targets,
      exposure: form.exposure,
    })
    Message.success('扫描任务已创建，正在 Agentless 探测…')
    form.name = ''
    form.targetsText = ''
    await loadJobs()
  } catch {
    Message.error('创建扫描任务失败')
  } finally {
    submitting.value = false
  }
}

async function openResults(job: ScanJob) {
  activeJob.value = job
  drawerOpen.value = true
  detailLoading.value = true
  results.value = []
  try {
    const detail = await scanApi.get(job.id)
    activeJob.value = detail.job
    results.value = detail.results ?? []
  } catch {
    Message.error('加载扫描结果失败')
  } finally {
    detailLoading.value = false
  }
}

onMounted(loadJobs)
onBeforeUnmount(() => {
  if (pollTimer) window.clearTimeout(pollTimer)
})
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1 class="page-title">密码学发现</h1>
      <p class="page-subtitle">
        Agentless 网络扫描，无需在目标主机部署 Agent —— 对指定 IP/域名/端口主动探测 TLS 版本、密码套件、密钥交换与证书签名算法。
      </p>
    </div>

    <a-alert
      v-if="lastDone"
      :type="lastDone.count > 0 ? 'success' : 'warning'"
      closable
      class="handoff-alert"
      @close="lastDone = null"
    >
      <template v-if="lastDone.count > 0">
        扫描「{{ lastDone.name }}」完成，新增 <strong>{{ lastDone.count }}</strong> 项密码使用点并已自动评分入档。
        <a-link @click="gotoAssets">前往密码使用点清单 →</a-link>
      </template>
      <template v-else>
        扫描「{{ lastDone.name }}」完成，但<strong>未发现密码学使用点</strong>。{{ lastDone.error || '请检查目标是否可达、端口是否为 HTTPS/TLS 服务。' }}
      </template>
    </a-alert>

    <a-row :gutter="16">
      <!-- 新建扫描 -->
      <a-col :xs="24" :lg="9">
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconScan /> 新建扫描</span>
          </template>
          <a-form :model="form" layout="vertical">
            <a-form-item label="任务名称" required>
              <a-input v-model="form.name" placeholder="如：核心区对外服务摸底" allow-clear />
            </a-form-item>
            <a-form-item label="扫描目标">
              <a-textarea
                v-model="form.targetsText"
                placeholder="每行一个目标，例如：&#10;10.50.91.133:443&#10;gw.example.com:443&#10;192.168.1.0/24"
                :auto-size="{ minRows: 5, maxRows: 10 }"
              />
              <div class="field-hint">每行一个 host:port / 域名 / 网段，提交时自动转为数组。</div>
            </a-form-item>
            <a-form-item label="暴露面">
              <a-select v-model="form.exposure">
                <a-option value="internal">内网 internal</a-option>
                <a-option value="dmz">DMZ</a-option>
                <a-option value="public">公网 public</a-option>
              </a-select>
            </a-form-item>
            <a-button type="primary" long :loading="submitting" @click="submit">
              <template #icon><IconScan /></template>
              发起 Agentless 扫描
            </a-button>
          </a-form>
        </a-card>

        <!-- 导入证据：PEM 证书 / SBOM -->
        <a-card class="block-card">
          <template #title>
            <span class="card-title-icon"><IconImport /> 导入证据</span>
          </template>
          <template #extra>
            <a-tooltip content="非主动扫描的离线发现入口：导入证书或软件物料清单生成密码使用点">
              <a-link @click="gotoRules">
                <IconBook /> 规则库
              </a-link>
            </a-tooltip>
          </template>
          <a-tabs v-model:active-key="importTab" size="small">
            <a-tab-pane key="pem" title="证书（PEM）">
              <a-form :model="importForm" layout="vertical">
                <a-form-item label="资产名称（可选）">
                  <a-input v-model="importForm.name" placeholder="如 核心区根 CA" allow-clear />
                </a-form-item>
                <a-form-item label="PEM 证书文本">
                  <a-textarea
                    v-model="importForm.pem"
                    placeholder="粘贴 -----BEGIN CERTIFICATE----- … 文本"
                    :auto-size="{ minRows: 4, maxRows: 8 }"
                  />
                </a-form-item>
                <a-space>
                  <a-button type="primary" :loading="importing" @click="importPem">
                    <template #icon><IconImport /></template>
                    解析并导入
                  </a-button>
                  <a-upload
                    :auto-upload="false"
                    :show-file-list="false"
                    accept=".pem,.crt,.cer,.p12"
                    :custom-request="noopRequest"
                    @change="(_: unknown, f: any) => f?.file && onPemFile(f.file)"
                  >
                    <template #upload-button>
                      <a-button :loading="importing">上传 .pem/.crt</a-button>
                    </template>
                  </a-upload>
                </a-space>
                <div class="field-hint">解析 x509 → 命中证书类规则 → 生成资产（M5）。</div>
              </a-form>
            </a-tab-pane>
            <a-tab-pane key="sbom" title="SBOM">
              <a-form :model="importForm" layout="vertical">
                <a-form-item label="资产名称（可选）">
                  <a-input v-model="importForm.name" placeholder="如 网关镜像 SBOM" allow-clear />
                </a-form-item>
                <a-form-item label="CycloneDX / Syft JSON">
                  <a-textarea
                    v-model="importForm.sbomText"
                    placeholder="粘贴 SBOM JSON，或下方上传文件"
                    :auto-size="{ minRows: 4, maxRows: 8 }"
                  />
                </a-form-item>
                <a-space>
                  <a-button type="primary" :loading="importing" @click="importSbom">
                    <template #icon><IconImport /></template>
                    解析并导入
                  </a-button>
                  <a-upload
                    :auto-upload="false"
                    :show-file-list="false"
                    accept=".json"
                    :custom-request="noopRequest"
                    @change="(_: unknown, f: any) => f?.file && onSbomFile(f.file)"
                  >
                    <template #upload-button>
                      <a-button :loading="importing">上传 .json</a-button>
                    </template>
                  </a-upload>
                </a-space>
                <div class="field-hint">提取加密库组件 → 命中库类规则（M4）。</div>
              </a-form>
            </a-tab-pane>
            <a-tab-pane key="pcap" title="被动流量 (pcap)">
              <a-form :model="importForm" layout="vertical">
                <a-form-item label="资产名称（可选）">
                  <a-input v-model="importForm.name" placeholder="如 办公区镜像抓包" allow-clear />
                </a-form-item>
                <a-space>
                  <a-upload
                    :auto-upload="false"
                    :show-file-list="false"
                    accept=".pcap,.cap"
                    :custom-request="noopRequest"
                    @change="(_: unknown, f: any) => f?.file && onPcapFile(f.file)"
                  >
                    <template #upload-button>
                      <a-button type="primary" :loading="importing">
                        <template #icon><IconImport /></template>
                        上传 .pcap 抓包
                      </a-button>
                    </template>
                  </a-upload>
                </a-space>
                <div class="field-hint">
                  旁路镜像 / tcpdump 抓包 → 解析 TLS 握手（SNI·版本·套件·证书）→ 按服务端点建档（M2）。
                  仅 classic .pcap（pcapng 请另存为 pcap）。
                </div>
              </a-form>
            </a-tab-pane>
          </a-tabs>
        </a-card>
      </a-col>

      <!-- 任务列表 -->
      <a-col :xs="24" :lg="15">
        <a-card class="block-card">
          <template #title>扫描任务</template>
          <template #extra>
            <a-space>
              <a-tag v-if="hasRunning()" color="arcoblue" size="small">
                <template #icon><icon-loading /></template>
                轮询刷新中
              </a-tag>
              <a-button size="small" :loading="loading" @click="loadJobs">
                <template #icon><IconRefresh /></template>
                刷新
              </a-button>
            </a-space>
          </template>
          <a-table
            :data="jobs"
            :columns="jobColumns"
            :pagination="{ pageSize: 8, hideOnSinglePage: true }"
            row-key="id"
            :scroll="{ x: 800 }"
          >
            <template #exposure="{ record }">
              <a-tag :color="exposureMeta(record.exposure).color" size="small">
                {{ exposureMeta(record.exposure).label }}
              </a-tag>
            </template>
            <template #targets="{ record }">{{ record.targets?.length ?? 0 }}</template>
            <template #status="{ record }">
              <a-tag :color="jobStatusMeta(record.status).color" size="small">
                {{ jobStatusMeta(record.status).label }}
              </a-tag>
            </template>
            <template #count="{ record }">
              <span :class="{ hit: record.resultCount > 0 }">{{ record.resultCount }}</span>
            </template>
            <template #time="{ record }">{{ fmtDate(record.finishedAt) }}</template>
            <template #actions="{ record }">
              <a-button
                size="mini"
                type="text"
                :disabled="record.status === 'pending'"
                @click="openResults(record)"
              >
                <template #icon><IconEye /></template>
                结果
              </a-button>
            </template>
            <template #empty>
              <a-empty description="暂无扫描任务，左侧发起第一次 Agentless 探测" />
            </template>
          </a-table>
        </a-card>
      </a-col>
    </a-row>

    <!-- 结果抽屉 -->
    <a-drawer
      v-model:visible="drawerOpen"
      :width="720"
      :footer="false"
      :title="`扫描结果 · ${activeJob?.name ?? ''}`"
    >
      <a-spin :loading="detailLoading" style="width: 100%">
        <a-descriptions
          v-if="activeJob"
          :column="2"
          size="medium"
          bordered
          class="result-desc"
        >
          <a-descriptions-item label="任务状态">
            <a-tag :color="jobStatusMeta(activeJob.status).color" size="small">
              {{ jobStatusMeta(activeJob.status).label }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="命中数">{{ activeJob.resultCount }}</a-descriptions-item>
          <a-descriptions-item label="开始时间">{{ fmtDate(activeJob.startedAt) }}</a-descriptions-item>
          <a-descriptions-item label="完成时间">{{ fmtDate(activeJob.finishedAt) }}</a-descriptions-item>
          <a-descriptions-item v-if="activeJob.error" label="错误" :span="2">
            <span style="color: rgb(var(--red-6))">{{ activeJob.error }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <a-table
          :data="results"
          :columns="resultColumns"
          :pagination="{ pageSize: 10, hideOnSinglePage: true }"
          row-key="id"
          style="margin-top: 16px"
          :scroll="{ x: 1000 }"
        >
          <template #status="{ record }">
            <template v-if="record.status === 'failed'">
              <a-tag color="red" size="small">失败</a-tag>
              <span class="fail-reason">{{ record.error || '探测失败' }}</span>
            </template>
            <a-tag v-else color="green" size="small">成功</a-tag>
          </template>
          <template #keyAlgo="{ record }">
            {{ record.keyAlgo || '—' }}<span v-if="record.keySize"> / {{ record.keySize }}</span>
          </template>
          <template #hits="{ record }">
            <a-space v-if="record.hits?.length" wrap :size="4">
              <a-tooltip
                v-for="(h, i) in record.hits"
                :key="i"
                :content="`${h.evidence || ''}${h.confidence ? ' · 置信度' + h.confidence : ''}`"
              >
                <a-tag
                  :color="hitRiskColor(h.riskHint)"
                  size="small"
                  class="hit-tag"
                  @click.stop="gotoRules"
                >
                  {{ h.ruleId }}
                </a-tag>
              </a-tooltip>
            </a-space>
            <span v-else class="dim">—</span>
          </template>
          <template #cert="{ record }">{{ fmtDate(record.certNotAfter) }}</template>
          <template #empty>
            <a-empty description="该任务暂无探测结果" />
          </template>
        </a-table>

        <div v-if="results.length" class="drawer-actions">
          <span class="drawer-hint">探测结果已归并去重为密码使用点并自动评分。</span>
          <a-button type="outline" size="small" @click="gotoAssets">
            <template #icon><IconStorage /></template>
            在密码使用点清单中查看
          </a-button>
        </div>
      </a-spin>
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
.field-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
  margin-top: 6px;
}
.hit {
  color: var(--brand-accent);
  font-weight: 600;
}
.hit-tag {
  cursor: pointer;
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
}
.dim {
  color: var(--brand-text-soft);
}
.fail-reason {
  margin-left: 6px;
  font-size: 12px;
  color: rgb(var(--red-6));
}
.handoff-alert {
  margin-bottom: 16px;
}
.drawer-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--brand-border);
}
.drawer-hint {
  font-size: 12px;
  color: var(--brand-text-soft);
}
.result-desc :deep(.arco-descriptions-item-label) {
  background: var(--brand-bg-soft);
}
</style>
