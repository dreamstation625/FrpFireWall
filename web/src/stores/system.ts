import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '@/api'

// 系统状态在多处用到（顶栏徽标、概览页、防火墙页），
// 集中在这里避免每个页面各拉一次。
export const useSystemStore = defineStore('system', () => {
  const info = ref<any>(null)
  const loading = ref(false)
  const lastError = ref('')

  async function load() {
    loading.value = true
    try {
      info.value = await api.systemInfo()
      lastError.value = ''
    } catch (e: any) {
      lastError.value = e?.message || '获取系统信息失败'
    } finally {
      loading.value = false
    }
  }

  async function detect() {
    const rep = await api.systemDetect()
    await load()
    return rep
  }

  return { info, loading, lastError, load, detect }
})
