import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'

const TOKEN_KEY = 'zpqm_token'

/** axios 实例：所有请求走 /api/v1（vite dev 代理到后端 :8099）。 */
const client: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 20000,
})

// 请求拦截器：自动注入 Bearer token。
client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    config.headers.set('Authorization', `Bearer ${token}`)
  }
  return config
})

// 响应拦截器：401 清理凭据并跳转登录。
client.interceptors.response.use(
  (resp) => resp,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      // 避免在登录页重复跳转。
      if (window.location.pathname !== '/login') {
        window.location.assign('/login')
      }
    }
    return Promise.reject(error)
  },
)

export { TOKEN_KEY }
export default client
