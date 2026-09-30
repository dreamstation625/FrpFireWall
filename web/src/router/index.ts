import { createRouter, createWebHashHistory } from 'vue-router'
import {
  CircleClose,
  Document,
  Files,
  Link,
  Location,
  Odometer,
  SetUp,
  Setting,
  Timer,
} from '@element-plus/icons-vue'
import api, { TOKEN_KEY } from '@/api'

// meta.icon 直接放组件而不是名字字符串，
// 这样图标可以按需打包，不必把整个图标库注册成全局组件。
const routes = [
  {
    path: '/setup',
    name: 'setup',
    component: () => import('@/views/Setup.vue'),
    meta: { public: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/Login.vue'),
    meta: { public: true },
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
        meta: { title: '概览', icon: Odometer },
      },
      {
        path: 'firewall',
        name: 'firewall',
        component: () => import('@/views/Firewall.vue'),
        meta: { title: '防火墙配置', icon: SetUp },
      },
      {
        path: 'acl',
        name: 'acl',
        component: () => import('@/views/ACL.vue'),
        meta: { title: '黑白名单', icon: Files },
      },
      {
        path: 'bans',
        name: 'bans',
        component: () => import('@/views/Bans.vue'),
        meta: { title: '封禁记录', icon: CircleClose },
      },
      {
        path: 'policy',
        name: 'policy',
        component: () => import('@/views/Policy.vue'),
        meta: { title: '频控策略', icon: Timer },
      },
      {
        path: 'geoip',
        name: 'geoip',
        component: () => import('@/views/GeoIP.vue'),
        meta: { title: 'IP 属地', icon: Location },
      },
      {
        path: 'frps',
        name: 'frps',
        component: () => import('@/views/Frps.vue'),
        meta: { title: 'frp 接入', icon: Link },
      },
      {
        path: 'events',
        name: 'events',
        component: () => import('@/views/Events.vue'),
        meta: { title: '事件日志', icon: Document },
      },
      {
        path: 'settings',
        name: 'settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: '系统设置', icon: Setting },
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

// 面板是否已完成初始化，只在首次导航时问一次后端。
let initialized: boolean | null = null

async function checkInitialized(): Promise<boolean> {
  if (initialized !== null) return initialized
  try {
    const r: any = await api.authStatus()
    initialized = !!r.initialized
  } catch {
    // 接口不通时不拦人，交给登录页处理
    initialized = true
  }
  return initialized
}

// 初始化成功后由 Setup 页调用，避免守卫再把人送回初始化页
export function markInitialized() {
  initialized = true
}

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const ready = await checkInitialized()
  if (!ready) {
    return to.path === '/setup' ? true : { path: '/setup' }
  }
  if (to.path === '/setup') {
    return { path: '/' }
  }

  const token = localStorage.getItem(TOKEN_KEY)
  if (!to.meta.public && !token) {
    return { path: '/login' }
  }
  if (to.path === '/login' && token) {
    return { path: '/dashboard' }
  }
  return true
})

export default router
