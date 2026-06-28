import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi } from '@/api'
import { TOKEN_KEY } from '@/api/client'
import type { User } from '@/api/types'

const USER_KEY = 'zpqm_user'

function loadUser(): User | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as User
  } catch {
    return null
  }
}

/** 认证状态：token / 当前用户，登录登出，localStorage 持久化。 */
export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>(localStorage.getItem(TOKEN_KEY) ?? '')
  const user = ref<User | null>(loadUser())

  const isAuthed = computed(() => !!token.value)

  /** 当前用户角色（admin / operator / viewer），未登录为空串。 */
  const role = computed(() => user.value?.role ?? '')

  /** 角色命中判断：传入允许角色集，命中其一即 true。 */
  function hasRole(...roles: string[]): boolean {
    return roles.includes(role.value)
  }

  /** 便捷：是否管理员。 */
  const isAdmin = computed(() => role.value === 'admin')

  function persist() {
    if (token.value) {
      localStorage.setItem(TOKEN_KEY, token.value)
    } else {
      localStorage.removeItem(TOKEN_KEY)
    }
    if (user.value) {
      localStorage.setItem(USER_KEY, JSON.stringify(user.value))
    } else {
      localStorage.removeItem(USER_KEY)
    }
  }

  async function login(username: string, password: string) {
    const resp = await authApi.login(username, password)
    token.value = resp.token
    user.value = resp.user
    persist()
    return resp
  }

  function logout() {
    token.value = ''
    user.value = null
    persist()
  }

  return { token, user, isAuthed, role, isAdmin, hasRole, login, logout }
})
