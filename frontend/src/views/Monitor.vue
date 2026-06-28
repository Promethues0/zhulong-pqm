<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconClockCircle, IconThunderbolt, IconCheckCircle, IconExport, IconDown } from '@arco-design/web-vue/es/icon'
import { monitorApi } from '@/api'
import type { MonitorDashboard, MonitorEvent, SloSummary } from '@/api/types'
import { fmtDate, severityMeta, sloUnitSuffix } from '@/utils/format'
import SloTrendChart from '@/components/SloTrendChart.vue'
import LegacyRiskTable from '@/components/LegacyRiskTable.vue'
import ThreatIntelFeed from '@/components/ThreatIntelFeed.vue'

const loading = ref(false)
const dash = ref<MonitorDashboard | null>(null)
const events = ref<MonitorEvent[]>([])
const sloCode = ref<string>('')

// SLO 卡片状态色：越界=红，临界(≥阈值90%)=橙，否则=绿。证书/覆盖率类按 breached。
function sloColor(s: SloSummary): string {
  if (s.breached) return '#c62828'
  if (s.threshold > 0 && s.value >= s.threshold * 0.9) return '#e8772e'
  return '#2e7d32'
}

const slos = computed(() => dash.value?.sloSummary ?? [])
const certExpiring = computed(() => dash.value?.certExpiring ?? [])
const reassessQueue = computed(() => dash.value?.reassessQueue ?? [])
const alertCounts = computed(() => dash.value?.alertsBySeverity ?? {})

function certColor(days: number): string {
  if (days < 0) return 'red'
  if (days <= 30) return 'red'
  if (days <= 90) return 'orange'
  return 'gold'
}

async function load() {
  loading.value = true
  try {
    const [d, ev] = await Promise.all([
      monitorApi.dashboard(),
      monitorApi.events({ status: 'open' }).catch(() => [] as MonitorEvent[]),
    ])
    dash.value = d
    events.value = ev
    if (!sloCode.value && d.sloSummary?.length) sloCode.value = d.sloSummary[0].code
  } catch {
    Message.error('加载监测仪表板失败，请确认后端 :8099 已启动')
  } finally {
    loading.value = false
  }
}

async function act(e: MonitorEvent, action: 'ack' | 'resolve' | 'reassess') {
  try {
    if (action === 'ack') await monitorApi.ack(e.id)
    else if (action === 'resolve') await monitorApi.resolve(e.id)
    else {
      const r = await monitorApi.reassess(e.id)
      Message.success(`已开复评批次${r.reassessTaskId ? ' #' + r.reassessTaskId : ''}`)
    }
    if (action !== 'reassess') Message.success(action === 'ack' ? '已确认' : '已闭合')
    await load()
  } catch {
    Message.error('操作失败')
  }
}

const exportingSiem = ref(false)

/** 告警台账外推 SIEM：CEF / JSON 下载。 */
async function exportSiem(format: 'cef' | 'json') {
  exportingSiem.value = true
  try {
    const blob = await monitorApi.exportEvents(format)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const stamp = new Date().toISOString().slice(0, 10)
    a.download = `zhulong-pqm-events-${stamp}.${format === 'cef' ? 'cef' : 'json'}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    Message.success(`告警已外推为 ${format.toUpperCase()}`)
  } catch {
    Message.error('导出 SIEM 失败')
  } finally {
    exportingSiem.value = false
  }
}

const eventColumns = [
  { title: '级别', slotName: 'severity', width: 90 },
  { title: '类型', dataIndex: 'kind', width: 110 },
  { title: '标题', slotName: 'title', minWidth: 200 },
  { title: '关联', dataIndex: 'ruleSLO', width: 100 },
  { title: '发生时间', slotName: 'time', width: 160 },
  { title: '处置', slotName: 'actions', width: 170 },
]

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header dash-head">
      <div>
        <h1 class="page-title">持续监测</h1>
        <p class="page-subtitle">
          闭环第五环 —— SLO 守护 · 密码漂移检测 · 证书到期预警 · 量子威胁情报 · 复评回灌。CBOM 新鲜度 {{ dash?.cbomFreshnessDays ?? '—' }} 天。
        </p>
      </div>
      <a-button :loading="loading" @click="load">
        <template #icon><IconRefresh /></template>
        刷新
      </a-button>
    </div>

    <a-spin :loading="loading" style="width: 100%">
      <!-- SLO 八卡 -->
      <a-row :gutter="12" class="slo-row">
        <a-col v-for="s in slos" :key="s.code" :xs="12" :sm="8" :md="6" :lg="3">
          <div class="slo-card" :style="{ borderTopColor: sloColor(s) }">
            <div class="slo-code">{{ s.code }}</div>
            <div class="slo-val" :style="{ color: sloColor(s) }">
              {{ s.value }}<span class="slo-unit">{{ sloUnitSuffix(s.unit) }}</span>
            </div>
            <div class="slo-name">{{ s.name || '' }}</div>
            <div class="slo-th">阈值 {{ s.threshold }}{{ sloUnitSuffix(s.unit) }}</div>
          </div>
        </a-col>
        <a-col v-if="!slos.length" :span="24">
          <a-empty description="暂无 SLO 数据，运行监测策略复扫后生成" />
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <!-- 告警台账 -->
        <a-col :xs="24" :lg="15">
          <a-card class="block-card">
            <template #title><IconThunderbolt /> 告警台账</template>
            <template #extra>
              <a-space>
                <a-tag color="red" size="small">P1 {{ alertCounts.p1 ?? 0 }}</a-tag>
                <a-tag color="orange" size="small">警告 {{ alertCounts.warning ?? 0 }}</a-tag>
                <a-tag color="gold" size="small">观察 {{ alertCounts.inspect ?? 0 }}</a-tag>
                <a-dropdown @select="(v: unknown) => exportSiem(v as 'cef' | 'json')">
                  <a-button size="small" :loading="exportingSiem">
                    <template #icon><IconExport /></template>
                    导出 SIEM
                    <IconDown />
                  </a-button>
                  <template #content>
                    <a-doption value="cef">CEF（ArcSight/通用）</a-doption>
                    <a-doption value="json">JSON</a-doption>
                  </template>
                </a-dropdown>
              </a-space>
            </template>
            <a-table :data="events" :columns="eventColumns" :pagination="{ pageSize: 6, hideOnSinglePage: true }" row-key="id" :scroll="{ x: 760 }">
              <template #severity="{ record }">
                <a-tag :color="severityMeta(record.severity).color" size="small">{{ severityMeta(record.severity).label }}</a-tag>
              </template>
              <template #title="{ record }">
                <div>{{ record.title }}</div>
                <div v-if="record.assetName" class="muted">{{ record.assetName }}</div>
              </template>
              <template #time="{ record }">{{ fmtDate(record.occurredAt) }}</template>
              <template #actions="{ record }">
                <a-space>
                  <a-button size="mini" type="text" @click="act(record, 'ack')">确认</a-button>
                  <a-button size="mini" type="text" @click="act(record, 'reassess')">复评</a-button>
                  <a-button size="mini" type="text" status="success" @click="act(record, 'resolve')">闭合</a-button>
                </a-space>
              </template>
              <template #empty><a-empty description="无开放告警" /></template>
            </a-table>
          </a-card>
        </a-col>

        <!-- 证书到期 + 复评队列 -->
        <a-col :xs="24" :lg="9">
          <a-card class="block-card">
            <template #title><IconClockCircle /> 证书到期（90 天内）</template>
            <div v-if="!certExpiring.length" class="empty-inline"><a-empty description="近 90 天无临期证书" /></div>
            <div v-for="c in certExpiring" :key="c.assetId ?? c.name" class="cert-row">
              <div class="cert-name">
                {{ c.name }}
                <a-tag v-if="c.noOta" color="red" size="small">无 OTA</a-tag>
                <span v-if="c.certKind" class="muted"> · {{ c.certKind }}</span>
              </div>
              <a-tag :color="certColor(c.daysLeft)" size="small">{{ c.daysLeft < 0 ? '已过期' : c.daysLeft + ' 天' }}</a-tag>
            </div>
          </a-card>
          <a-card class="block-card">
            <template #title><IconCheckCircle /> 复评队列</template>
            <div v-if="!reassessQueue.length" class="empty-inline"><a-empty description="复评队列为空" /></div>
            <div v-for="q in reassessQueue" :key="q.assetId" class="cert-row">
              <div class="cert-name">{{ q.name }}<span v-if="q.reason" class="muted"> · {{ q.reason }}</span></div>
              <a-tag size="small">{{ q.level || '待评' }}</a-tag>
            </div>
          </a-card>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :xs="24" :lg="14">
          <a-card class="block-card">
            <template #title>SLO 趋势</template>
            <template #extra>
              <a-select v-model="sloCode" size="small" style="width: 220px">
                <a-option v-for="s in slos" :key="s.code" :value="s.code">{{ s.code }} {{ s.name }}</a-option>
              </a-select>
            </template>
            <SloTrendChart :code="sloCode" />
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="10">
          <a-card class="block-card">
            <template #title>遗留风险登记（R-00x）</template>
            <LegacyRiskTable />
          </a-card>
        </a-col>
      </a-row>

      <a-card class="block-card">
        <template #title>量子威胁情报</template>
        <ThreatIntelFeed @reassessed="load" />
      </a-card>
    </a-spin>
  </div>
</template>

<style scoped>
.dash-head { display: flex; align-items: flex-end; justify-content: space-between; }
.slo-row { margin-bottom: 4px; row-gap: 12px; }
.slo-card {
  background: #fffdfa; border: 1px solid var(--clay-border); border-top: 3px solid;
  border-radius: 10px; padding: 12px 14px; height: 100%;
}
.slo-code { font-size: 11px; color: var(--clay-text-soft); font-weight: 600; }
.slo-val { font-size: 24px; font-weight: 700; line-height: 1.1; margin-top: 2px; }
.slo-unit { font-size: 12px; font-weight: 500; margin-left: 2px; }
.slo-name { font-size: 11px; color: var(--clay-text); margin-top: 2px; min-height: 15px; }
.slo-th { font-size: 10px; color: var(--clay-text-tertiary); margin-top: 4px; }
.block-card { margin-top: 16px; }
.muted { font-size: 12px; color: var(--clay-text-soft); }
.empty-inline { padding: 14px 0; }
.cert-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--clay-border);
}
.cert-row:last-child { border-bottom: none; }
.cert-name { font-size: 13px; color: var(--clay-text); }
</style>
