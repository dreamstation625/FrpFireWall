import { defineStore } from 'pinia'
import { ref } from 'vue'
import api, { TOKEN_KEY } from '@/api'

const USER_KEY = 'frpfirewall_user'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem(TOKEN_KEY) || '')
  const username = ref(localStorage.getItem(USER_KEY) || '')

  function setSession(res: any) {
    token.value = res.token
    username.value = res.username
    localStorage.setItem(TOKEN_KEY, res.token)
    localStorage.setItem(USER_KEY, res.username)
  }

  async function login(u: string, p: string) {
    const res: any = await api.login(u, p)
    setSession(res)
    return res
  }

  // 首次初始化：设置完密码后直接拿到登录态
  async function setup(body: { token: string; username: string; password: string }) {
    const res: any = await api.setup(body)
    setSession(res)
    return res
  }

  function logout() {
    api.logout().catch(() => {})
    token.value = ''
    username.value = ''
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
  }

  return { token, username, login, setup, logout }
})
