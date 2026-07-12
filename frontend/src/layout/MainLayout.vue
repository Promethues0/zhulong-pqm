<script setup lang="ts">
import { ref, computed, type Component } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Message, Modal } from '@arco-design/web-vue'
import {
  IconDashboard,
  IconScan,
  IconBook,
  IconStorage,
  IconDesktop,
  IconWifi,
  IconArchive,
  IconThunderbolt,
  IconList,
  IconTool,
  IconCheckCircle,
  IconClockCircle,
  IconFile,
  IconHistory,
  IconSettings,
  IconMenuFold,
  IconMenuUnfold,
  IconPoweroff,
  IconUser,
} from '@arco-design/web-vue/es/icon'
import { useAuthStore } from '@/store/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const collapsed = ref(false)

interface MenuItem {
  key: string
  path: string
  label: string
  icon: Component
  adminOnly?: boolean
}

const menuItems: MenuItem[] = [
  { key: 'dashboard', path: '/dashboard', label: '进度仪表板', icon: IconDashboard },
  { key: 'discovery', path: '/discovery', label: '密码学发现', icon: IconScan },
  { key: 'rules', path: '/rules', label: '规则库', icon: IconBook },
  { key: 'assets', path: '/assets', label: '密码使用点清单', icon: IconStorage },
  { key: 'snapshots', path: '/snapshots', label: 'CBOM 快照', icon: IconArchive },
  { key: 'risk', path: '/risk', label: '风险评估', icon: IconThunderbolt },
  { key: 'risk-register', path: '/risk-register', label: '风险登记', icon: IconList },
  { key: 'agents', path: '/agents', label: 'Agent / 探针', icon: IconDesktop },
  { key: 'captures', path: '/captures', label: '抓包任务', icon: IconWifi },
  { key: 'remediation', path: '/remediation', label: '改造编排', icon: IconTool },
  { key: 'acceptance', path: '/acceptance', label: '验收自动化', icon: IconCheckCircle },
  { key: 'monitor', path: '/monitor', label: '持续监测', icon: IconClockCircle },
  { key: 'reports', path: '/reports', label: '摸底报告', icon: IconFile },
  { key: 'audit-logs', path: '/audit-logs', label: '审计日志', icon: IconHistory, adminOnly: true },
  { key: 'settings', path: '/settings', label: '系统设置', icon: IconSettings },
]

// 审计日志仅 admin 可见；其余项对所有已登录用户显示。
const visibleMenu = computed(() =>
  menuItems.filter((m) => !m.adminOnly || auth.role === 'admin'),
)

const selectedKeys = computed(() => {
  // 先精确匹配，再取最长前缀，避免 /risk 误命中 /risk-register。
  const exact = visibleMenu.value.find((m) => m.path === route.path)
  if (exact) return [exact.key]
  const pref = [...visibleMenu.value]
    .filter((m) => route.path.startsWith(m.path + '/'))
    .sort((a, b) => b.path.length - a.path.length)[0]
  return [pref?.key ?? 'dashboard']
})

const currentTitle = computed(
  () => (route.meta.title as string) ?? '烛龙 PQM',
)

function onMenuClick(key: string) {
  const item = menuItems.find((m) => m.key === key)
  if (item && item.path !== route.path) {
    router.push(item.path)
  }
}

function logout() {
  Modal.confirm({
    title: '退出登录',
    content: '确认退出当前会话？',
    okText: '退出',
    cancelText: '取消',
    onOk: () => {
      auth.logout()
      Message.success('已退出登录')
      router.push('/login')
    },
  })
}
</script>

<template>
  <a-layout class="app-shell">
    <a-layout-sider
      :collapsed="collapsed"
      :width="232"
      :collapsed-width="64"
      class="app-sider"
      breakpoint="lg"
    >
      <div class="brand" :class="{ 'brand--collapsed': collapsed }">
        <div class="brand-mark">烛</div>
        <div v-show="!collapsed" class="brand-text">
          <div class="brand-name">烛龙 PQM</div>
          <div class="brand-sub">后量子迁移治理</div>
        </div>
      </div>

      <a-menu
        :selected-keys="selectedKeys"
        :style="{ border: 'none', background: 'transparent' }"
        @menu-item-click="onMenuClick"
      >
        <a-menu-item v-for="m in visibleMenu" :key="m.key">
          <template #icon><component :is="m.icon" /></template>
          {{ m.label }}
        </a-menu-item>
      </a-menu>
    </a-layout-sider>

    <a-layout>
      <a-layout-header class="app-header">
        <div class="header-left">
          <a-button
            class="collapse-btn"
            type="text"
            shape="circle"
            @click="collapsed = !collapsed"
          >
            <template #icon>
              <IconMenuUnfold v-if="collapsed" />
              <IconMenuFold v-else />
            </template>
          </a-button>
          <span class="header-title">{{ currentTitle }}</span>
        </div>

        <div class="header-right">
          <a-dropdown trigger="click">
            <div class="user-chip">
              <a-avatar :size="28" class="user-avatar">
                <IconUser />
              </a-avatar>
              <span class="user-name">{{ auth.user?.username ?? '用户' }}</span>
              <a-tag size="small" color="orange">{{ auth.user?.role ?? '—' }}</a-tag>
            </div>
            <template #content>
              <a-doption @click="logout">
                <template #icon><IconPoweroff /></template>
                退出登录
              </a-doption>
            </template>
          </a-dropdown>
        </div>
      </a-layout-header>

      <a-layout-content class="app-content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<style scoped>
.app-shell {
  min-height: 100vh;
}

.app-sider {
  background: linear-gradient(180deg, #fffdf9 0%, #f6efe6 100%);
  border-right: 1px solid var(--brand-border);
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px 18px 14px;
  margin-bottom: 6px;
}
.brand--collapsed {
  justify-content: center;
  padding: 18px 0 14px;
}
.brand-mark {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: var(--brand-accent);
  color: #F7F8FA;
  font-weight: 700;
  font-size: 19px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(22, 93, 255, 0.28);
}
.brand-name {
  font-size: 16px;
  font-weight: 700;
  color: var(--brand-text);
  line-height: 1.2;
}
.brand-sub {
  font-size: 11px;
  color: var(--brand-text-soft);
  margin-top: 2px;
}

.app-header {
  height: 60px;
  background: rgba(255, 255, 255, 0.86);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--brand-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  position: sticky;
  top: 0;
  z-index: 10;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
.header-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--brand-text);
}
.header-right {
  display: flex;
  align-items: center;
}
.user-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 999px;
  transition: background 0.2s;
}
.user-chip:hover {
  background: var(--brand-bg-soft);
}
.user-avatar {
  background: var(--brand-accent-2);
}
.user-name {
  font-size: 14px;
  color: var(--brand-text);
  font-weight: 500;
}

.app-content {
  background: var(--brand-bg);
  overflow-y: auto;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.18s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
