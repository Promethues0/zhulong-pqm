import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { TOKEN_KEY } from '@/api/client'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/Login.vue'),
    meta: { public: true, title: '登录' },
  },
  {
    path: '/',
    component: () => import('@/layout/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '进度仪表板' },
      },
      {
        path: 'discovery',
        name: 'discovery',
        component: () => import('@/views/Discovery.vue'),
        meta: { title: '密码学发现' },
      },
      {
        path: 'rules',
        name: 'rules',
        component: () => import('@/views/RuleLibrary.vue'),
        meta: { title: '规则库' },
      },
      {
        path: 'assets',
        name: 'assets',
        component: () => import('@/views/Assets.vue'),
        meta: { title: '密码使用点清单' },
      },
      {
        path: 'snapshots',
        name: 'snapshots',
        component: () => import('@/views/Snapshots.vue'),
        meta: { title: 'CBOM 快照' },
      },
      {
        path: 'risk',
        name: 'risk',
        component: () => import('@/views/RiskAssessment.vue'),
        meta: { title: '风险评估' },
      },
      {
        path: 'remediation',
        name: 'remediation',
        component: () => import('@/views/Remediation.vue'),
        meta: { title: '改造编排' },
      },
      {
        path: 'acceptance',
        name: 'acceptance',
        component: () => import('@/views/Acceptance.vue'),
        meta: { title: '验收自动化' },
      },
      {
        path: 'risk-register',
        name: 'risk-register',
        component: () => import('@/views/RiskRegister.vue'),
        meta: { title: '风险登记' },
      },
      {
        path: 'monitor',
        name: 'monitor',
        component: () => import('@/views/Monitor.vue'),
        meta: { title: '持续监测' },
      },
      {
        path: 'reports',
        name: 'reports',
        component: () => import('@/views/Reports.vue'),
        meta: { title: '摸底报告' },
      },
      {
        path: 'audit-logs',
        name: 'audit-logs',
        component: () => import('@/views/AuditLog.vue'),
        meta: { title: '审计日志', roles: ['admin'] },
      },
      {
        path: 'settings',
        name: 'settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: '系统设置' },
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

/** 从 localStorage 读取当前用户角色（避免在守卫里耦合 pinia 初始化顺序）。 */
function currentRole(): string {
  try {
    const raw = localStorage.getItem('zpqm_user')
    if (!raw) return ''
    return (JSON.parse(raw) as { role?: string }).role ?? ''
  } catch {
    return ''
  }
}

// 登录守卫：无 token 跳 /login；已登录访问 /login 跳首页；角色不足跳首页。
router.beforeEach((to) => {
  const authed = !!localStorage.getItem(TOKEN_KEY)
  if (!to.meta.public && !authed) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.path === '/login' && authed) {
    return { path: '/' }
  }
  // 角色守卫：路由声明 meta.roles 时，已登录但角色不匹配 → 回首页。
  const roles = to.meta.roles as string[] | undefined
  if (authed && roles && roles.length && !roles.includes(currentRole())) {
    return { path: '/dashboard' }
  }
  return true
})

router.afterEach((to) => {
  const base = '烛龙 PQM'
  document.title = to.meta.title ? `${to.meta.title} · ${base}` : base
})

export default router
