<template>
  <el-container class="layout">
    <el-aside width="212px" class="aside">
      <div class="brand">
        <div class="brand-name">FrpFireWall</div>
        <div class="brand-sub">frps 服务端防火墙</div>
      </div>

      <el-menu :default-active="activeMenu" router class="menu">
        <el-menu-item v-for="m in menuItems" :key="m.path" :index="m.path">
          <el-icon><component :is="m.icon" /></el-icon>
          <span>{{ m.title }}</span>
        </el-menu-item>
      </el-menu>

      <div class="aside-footer">
        <div class="ver-entry" title="查看版本与检查更新" @click="updateVisible = true">
          <span class="hint">{{ versionText || '版本未知' }}</span>
          <el-tag v-if="updateAvailable" type="danger" size="small" effect="light">
            有新版本
          </el-tag>
        </div>
      </div>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="badges">
          <el-tag :type="backendTag.type" size="small" effect="light">
            后端：{{ backendTag.text }}
          </el-tag>
          <el-tag :type="geoTag.type" size="small" effect="light">
            属地库：{{ geoTag.text }}
          </el-tag>
          <el-tag :type="bansTag.type" size="small" effect="light">
            活跃封禁：{{ bansTag.text }}
          </el-tag>
          <el-tag v-if="sys.info?.guard?.dry_run" type="warning" size="small" effect="light">
            观察模式
          </el-tag>
          <el-tag v-if="sys.info?.guard?.last_sync_err" type="danger" size="small" effect="light">
            规则同步异常
          </el-tag>
          <el-tag
            v-if="updateAvailable"
            class="up-badge"
            type="danger"
            size="small"
            effect="light"
            @click="updateVisible = true"
          >
            新版本 {{ updateInfo?.latest }}
          </el-tag>
        </div>

        <div class="spacer" />

        <el-button :icon="Refresh" text size="small" @click="reload">刷新</el-button>

        <el-dropdown @command="onUserCommand">
          <span class="user">
            <el-icon><UserFilled /></el-icon>
            {{ auth.username || 'admin' }}
            <el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">修改密码</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>

      <el-main class="main">
        <router-view v-slot="{ Component }">
          <component :is="Component" />
        </router-view>
      </el-main>
    </el-container>

    <el-dialog v-model="pwdVisible" title="修改密码" width="420px">
      <el-form label-width="80px">
        <el-form-item label="原密码">
          <el-input v-model="pwdForm.old" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.next" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwdLoading" @click="submitPassword">确定</el-button>
      </template>
    </el-dialog>

    <UpdateDialog
      v-model="updateVisible"
      :version="sys.info?.version"
      :commit="sys.info?.commit"
      :build-time="sys.info?.build_time"
      :is-prerelease="sys.info?.is_prerelease"
      @checked="onUpdateChecked"
    />
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  ArrowDown,
  Menu,
  Refresh,
  UserFilled,
} from '@element-plus/icons-vue'
import api from '@/api'
import UpdateDialog from '@/components/UpdateDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const sys = useSystemStore()

const activeMenu = computed(() => route.path)

const menuItems = computed(() => {
  const root = router.options.routes.find((r) => r.path === '/')
  return (root?.children || []).map((c: any) => ({
    path: '/' + c.path,
    title: c.meta?.title || c.path,
    icon: c.meta?.icon || Menu,
  }))
})

const backendTag = computed(() => {
  const backend = sys.info?.guard?.backend
  if (!backend) return { type: 'info' as const, text: '未就绪' }
  return { type: 'success' as const, text: backend }
})

const geoTag = computed(() => {
  const g = sys.info?.geoip
  if (!g) return { type: 'info' as const, text: '未知' }
  if (g.stale) return { type: 'warning' as const, text: '已过期' }
  if (g.country_loaded || g.region_loaded) return { type: 'success' as const, text: '已加载' }
  return { type: 'info' as const, text: '未加载' }
})

const bansTag = computed(() => {
  const n = sys.info?.guard?.active_bans ?? 0
  return { type: n > 0 ? ('danger' as const) : ('info' as const), text: String(n) }
})

const versionText = computed(() => {
  const v = sys.info?.version
  return v ? `版本 ${v}` : ''
})

// ---- 版本更新 ----
// 每个浏览器会话只自动检查一次；服务端另有 1 小时缓存，
// 所以打开多少次面板都不会真的打很多次 GitHub。
const UPDATE_CHECKED_KEY = 'frpfirewall_update_checked'

const updateVisible = ref(false)
const updateInfo = ref<any>(null)

const updateAvailable = computed(() => !!updateInfo.value?.has_update)

function applyUpdate(res: any) {
  if (!res) return
  updateInfo.value = res
}

function onUpdateChecked(hasUpdate: boolean) {
  // 对话框里手动查完，把结论同步到顶栏徽标
  if (hasUpdate && !updateInfo.value?.has_update) {
    updateInfo.value = { ...(updateInfo.value || {}), has_update: true }
  } else if (!hasUpdate) {
    updateInfo.value = null
  }
}

async function autoCheckUpdate() {
  // 先吃服务端已有的缓存结论，能立刻出徽标
  const cached = sys.info?.update
  if (cached?.checked && cached?.result) {
    applyUpdate(cached.result)
    return
  }
  if (sys.info?.update?.enabled === false) return
  if (sessionStorage.getItem(UPDATE_CHECKED_KEY) === '1') return

  sessionStorage.setItem(UPDATE_CHECKED_KEY, '1')
  try {
    const r: any = await api.checkUpdate(false)
    if (r?.enabled !== false) applyUpdate(r?.result)
  } catch {
    // 离线 / 被墙时静默失败，不能因为检查更新失败就打扰用户
  }
}

async function reload() {
  await sys.load()
  ElMessage.success('已刷新')
}

// ---- 修改密码 ----
const pwdVisible = ref(false)
const pwdLoading = ref(false)
const pwdForm = reactive({ old: '', next: '' })

function onUserCommand(cmd: string) {
  if (cmd === 'password') {
    pwdForm.old = ''
    pwdForm.next = ''
    pwdVisible.value = true
    return
  }
  if (cmd === 'logout') {
    ElMessageBox.confirm('确定要退出登录吗？', '提示', { type: 'warning' })
      .then(() => {
        auth.logout()
        router.push('/login')
      })
      .catch(() => {})
  }
}

async function submitPassword() {
  if (!pwdForm.old || !pwdForm.next) {
    ElMessage.warning('请填写完整')
    return
  }
  pwdLoading.value = true
  try {
    await api.changePassword(pwdForm.old, pwdForm.next)
    pwdVisible.value = false
    ElMessage.success('密码已更新，请重新登录')
    auth.logout()
    router.push('/login')
  } finally {
    pwdLoading.value = false
  }
}

onMounted(async () => {
  await sys.load()
  autoCheckUpdate()
})
</script>

<style scoped>
.layout {
  height: 100vh;
}

.aside {
  background: #fff;
  border-right: 1px solid #e9ecf2;
  display: flex;
  flex-direction: column;
}

.brand {
  padding: 18px 20px 14px;
}

.brand-name {
  font-size: 17px;
  font-weight: 500;
  letter-spacing: 0.3px;
}

.brand-sub {
  font-size: 12px;
  color: #8a919f;
  margin-top: 4px;
}

.menu {
  border-right: none;
  flex: 1;
  overflow-y: auto;
}

.aside-footer {
  padding: 12px 20px;
  border-top: 1px solid #f0f2f5;
}

.ver-entry {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
}

.ver-entry:hover .hint {
  color: #1f6feb;
}

.up-badge {
  cursor: pointer;
}

.header {
  background: #fff;
  border-bottom: 1px solid #e9ecf2;
  display: flex;
  align-items: center;
  gap: 12px;
  height: 56px;
}

.badges {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.spacer {
  flex: 1;
}

.user {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #1f2329;
  outline: none;
}

.main {
  background: #f5f7fa;
  padding: 16px;
  overflow-y: auto;
}
</style>
