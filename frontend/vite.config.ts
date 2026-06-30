import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
// base：生产构建走 '/pqm/' 子路径（nginx alias /pqm/ → /opt/zhulong-pqm/web/，
// 资源须引用 /pqm/assets/，否则根路径 /assets/ 会被 console 的 location / 截胡成 HTML，
// 导致 PQM 前端 JS 加载失败白屏）；本地 dev/preview 仍用 '/' 便于直接访问根路径。
// router 用 import.meta.env.BASE_URL 自适应两种 base。
export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/pqm/' : '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5390,
    proxy: {
      '/api': {
        target: 'http://localhost:8099',
        changeOrigin: true,
      },
    },
  },
}))
