<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import { IconUser, IconLock } from '@arco-design/web-vue/es/icon'
import { useAuthStore } from '@/store/auth'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const form = reactive({
  username: 'admin',
  password: 'admin@1234',
})
const loading = ref(false)

async function handleLogin() {
  if (!form.username || !form.password) {
    Message.warning('请输入用户名与密码')
    return
  }
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    Message.success('登录成功')
    const redirect = (route.query.redirect as string) || '/dashboard'
    router.push(redirect)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { message?: string; error?: string } } }
    const msg =
      err.response?.data?.message ||
      err.response?.data?.error ||
      '登录失败，请检查用户名或密码'
    Message.error(msg)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-bg-glow" />
    <a-card class="login-card" :bordered="false">
      <div class="login-brand">
        <div class="login-mark">烛</div>
        <div class="login-title">烛龙 PQM</div>
        <div class="login-sub">后量子迁移治理平台</div>
      </div>

      <a-form :model="form" layout="vertical" @submit-success="handleLogin">
        <a-form-item field="username" hide-label>
          <a-input
            v-model="form.username"
            placeholder="用户名"
            size="large"
            allow-clear
          >
            <template #prefix><IconUser /></template>
          </a-input>
        </a-form-item>

        <a-form-item field="password" hide-label>
          <a-input-password
            v-model="form.password"
            placeholder="密码"
            size="large"
            allow-clear
            @keyup.enter="handleLogin"
          >
            <template #prefix><IconLock /></template>
          </a-input-password>
        </a-form-item>

        <a-button
          type="primary"
          long
          size="large"
          :loading="loading"
          class="login-btn"
          @click="handleLogin"
        >
          登 录
        </a-button>
      </a-form>

      <div class="login-hint">默认账号 admin / admin@1234</div>
    </a-card>

    <div class="login-foot">
      烛龙·统一安全接入平台 · 国密零信任 · CycloneDX CBOM
    </div>
  </div>
</template>

<style scoped>
.login-page {
  position: relative;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background:
    radial-gradient(1200px 600px at 50% -10%, #fbeee2 0%, transparent 60%),
    var(--clay-bg);
  overflow: hidden;
}
.login-bg-glow {
  position: absolute;
  width: 520px;
  height: 520px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(219, 133, 92, 0.22), transparent 70%);
  top: 12%;
  filter: blur(8px);
  pointer-events: none;
}
.login-card {
  width: 388px;
  padding: 14px 18px 26px;
  border-radius: 18px;
  box-shadow: 0 24px 60px rgba(122, 52, 24, 0.14);
  background: rgba(255, 253, 250, 0.96);
  z-index: 1;
}
.login-brand {
  text-align: center;
  margin: 12px 0 24px;
}
.login-mark {
  width: 56px;
  height: 56px;
  border-radius: 16px;
  background: var(--clay-accent);
  color: #faf7f2;
  font-size: 30px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 14px;
  box-shadow: 0 8px 22px rgba(180, 85, 45, 0.32);
}
.login-title {
  font-size: 24px;
  font-weight: 700;
  color: var(--clay-text);
  letter-spacing: 0.5px;
}
.login-sub {
  margin-top: 6px;
  font-size: 13px;
  color: var(--clay-text-soft);
}
.login-btn {
  margin-top: 4px;
  letter-spacing: 4px;
  font-weight: 600;
}
.login-hint {
  margin-top: 18px;
  text-align: center;
  font-size: 12px;
  color: var(--clay-text-soft);
}
.login-foot {
  margin-top: 26px;
  font-size: 12px;
  color: var(--clay-text-soft);
  opacity: 0.8;
  z-index: 1;
}
</style>
