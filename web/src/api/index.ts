import axios, { type AxiosInstance } from 'axios'
import { ElMessage } from 'element-plus'

export const TOKEN_KEY = 'frpfirewall_token'

export const http: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    cfg.headers.Authorization = `Bearer ${token}`
  }
  return cfg
})

http.interceptors.response.use(
  (res) => {
    const body = res.data
    // 后端统一返回 {ok, data} / {ok:false, error}
    if (body && typeof body === 'object' && 'ok' in body) {
      return body.data
    }
    return body
  },
  (err) => {
    const status = err.response?.status
    const msg =
      err.response?.data?.error ||
      err.response?.data?.message ||
      err.message ||
      '请求失败'

    if (status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      // 初始化令牌错误也会返回 401，那种情况不该把人踢到登录页
      const url = String(err.config?.url || '')
      if (!url.includes('/auth/setup') && !location.hash.includes('/login')) {
        location.hash = '#/login'
      }
    }
    ElMessage.error(msg)
    return Promise.reject(err)
  }
)

export const api = {
  // ---- 认证 ----
  authStatus: () => http.get('/auth/status'),
  setup: (body: { token: string; username: string; password: string }) =>
    http.post('/auth/setup', body),
  login: (username: string, password: string) =>
    http.post('/auth/login', { username, password }),
  me: () => http.get('/auth/me'),
  logout: () => http.post('/auth/logout'),
  changePassword: (old_password: string, new_password: string) =>
    http.post('/auth/password', { old_password, new_password }),

  // ---- 配置 ----
  getConfig: () => http.get('/config'),
  updateConfig: (body: Record<string, unknown>) => http.put('/config', body),

  // ---- 系统 ----
  systemInfo: () => http.get('/system/info'),
  systemDetect: () => http.get('/system/detect'),

  // 版本更新：status 只读服务端缓存，check 才会真正联网查 GitHub
  updateStatus: () => http.get('/system/update'),
  checkUpdate: (force = false) =>
    http.post('/system/update/check', { force }, { timeout: 40000 }),
  switchBackend: (backend: string) =>
    http.post('/system/firewall/mode', { backend }),

  // ---- 防火墙 ----
  managedRules: () => http.get('/firewall/managed'),
  // 防火墙拦截统计。hours 决定趋势窗口，服务端上限 720 小时（30 天）。
  counters: (hours = 24) => http.get('/firewall/counters', { params: { hours } }),
  systemRules: () => http.get('/firewall/system'),
  preview: () => http.post('/firewall/preview'),
  reconcile: () => http.post('/firewall/reconcile'),

  // ---- 黑白名单 ----
  listACL: (kind: string, params: Record<string, unknown>) =>
    http.get(`/acl/${kind}`, { params }),
  createACL: (kind: string, body: Record<string, unknown>) =>
    http.post(`/acl/${kind}`, body),
  updateACL: (kind: string, id: number, body: Record<string, unknown>) =>
    http.put(`/acl/${kind}/${id}`, body),
  deleteACL: (kind: string, id: number) => http.delete(`/acl/${kind}/${id}`),
  batchACL: (kind: string, body: Record<string, unknown>) =>
    http.post(`/acl/${kind}/batch`, body),
  importACL: (kind: string, body: Record<string, unknown>) =>
    http.post(`/acl/${kind}/import`, body),
  exportACLURL: (kind: string) =>
    `/api/v1/acl/${kind}/export?token=${localStorage.getItem(TOKEN_KEY) || ''}`,

  // ---- 封禁 ----
  listBans: (params: Record<string, unknown>) => http.get('/bans', { params }),
  activeBans: (params: Record<string, unknown> = {}) => http.get('/bans/active', { params }),
  createBan: (body: Record<string, unknown>) => http.post('/bans', body),
  deleteBan: (id: number) => http.delete(`/bans/${id}`),
  batchDeleteBan: (ids: number[]) =>
    http.post('/bans/batch-delete', { ids }),
  lookup: (target: string) => http.post('/bans/lookup', { target }),

  // ---- 策略 ----
  getPolicy: () => http.get('/policy'),
  // 细分规则与全局策略一起保存（后端在同一个事务里落盘），
  // 所以写入走 updatePolicy 的 rules 字段，没有单独的写接口。
  updatePolicy: (body: Record<string, unknown>) => http.put('/policy', body),
  listRateRules: () => http.get('/policy/rules'),
  // 最近出现过的代理（隧道）名，只作候选 —— 手填的值同样有效。
  proxyNames: (limit?: number) =>
    http.get('/events/proxy-names', { params: limit ? { limit } : {} }),

  // ---- GeoIP ----
  geoLookup: (ip: string) => http.post('/geoip/lookup', { ip }),
  geoStatus: () => http.get('/geoip/status'),
  geoCountries: () => http.get('/geoip/countries'),
  geoProvinces: () => http.get('/geoip/provinces'),
  geoUpload: (name: string, file: File) => {
    const fd = new FormData()
    fd.append('name', name)
    fd.append('file', file)
    return http.post('/geoip/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    })
  },
  // 可下载的库清单 + 可选加速源。加速源列表由后端给，前端不自己存一份。
  geoSources: () => http.get('/geoip/sources'),
  // 同步下载：GeoLite2-City 有 64MB，走不到加速源时还要依次切源重试，
  // 可能拖几分钟。这里不设超时，把节奏交给后端 —— 前端抢在后端前面断开，
  // 用户只会看到一个没头没尾的错误，还以为是网络问题。
  geoDownload: (name: string, mirror: string) =>
    http.post('/geoip/download', { name, mirror }, { timeout: 0 }),

  // ---- 事件 ----
  listEvents: (params: Record<string, unknown>) =>
    http.get('/events', { params }),
  eventStats: (hours: number) =>
    http.get('/events/stats', { params: { hours } }),
  listRuleChanges: (params: Record<string, unknown>) =>
    http.get('/events/changes', { params }),

  // ---- frps 集成 ----
  frpsSnippet: () => http.get('/frps/snippet'),
  frpsHealth: () => http.get('/frps/health'),
  frpsConfig: () => http.get('/frps/config'),
  // 受保护端口（bind_port ∪ proxy_ports）。写接口只改代理端口那一半，
  // 保存后后端立即重算内核规则，不需要重启 —— 与 PUT /config 的区别只在生效时机。
  frpsProtectPorts: () => http.get('/frps/protect-ports'),
  updateFrpsProtectPorts: (body: Record<string, unknown>) =>
    http.put('/frps/protect-ports', body),
}

export default api
