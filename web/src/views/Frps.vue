<template>
  <div v-loading="loading">
    <div class="page-card panel">
      <div class="panel-head">
        <span class="section-title">插件链路状态</span>
        <el-button size="small" :loading="checking" @click="doHealth">连通性检测</el-button>
      </div>

      <el-alert
        v-if="health"
        :type="health.ok ? 'success' : 'error'"
        :closable="false"
        show-icon
        style="margin-bottom: 14px"
      >
        <template #title>
          {{ health.ok ? '插件服务可达，frps 可以正常调用' : '插件服务不可达' }}
        </template>
        <div style="font-size: 12.5px; line-height: 1.7">
          <div v-if="health.url">探测地址：<span class="mono">{{ health.url }}</span></div>
          <div v-if="health.status">HTTP 状态码：{{ health.status }}</div>
          <div v-if="health.error">{{ health.error }}</div>
        </div>
      </el-alert>

      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="插件监听地址">
          <span class="mono">{{ snippet?.addr || info?.plugin_listen || '—' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="插件路径">
          <span class="mono">{{ snippet?.path || info?.plugin_path || '—' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="订阅的 op">
          <el-tag v-for="o in snippet?.ops || []" :key="o" size="small" style="margin-right: 6px">
            {{ o }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="受保护端口">
          <span class="mono">{{ protectedPorts }}</span>
        </el-descriptions-item>
      </el-descriptions>

      <div class="hint" style="margin-top: 10px">
        插件只监听回环地址，frps 必须与本程序同机。
        防火墙规则只针对 <span class="mono">bind_port</span> 与
        <span class="mono">proxy_ports</span> 下发。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">frps.toml 需要增加的配置</span>
        <el-button size="small" @click="copy(snippetText)">复制</el-button>
      </div>

      <pre class="code-block">{{ snippetText }}</pre>

      <div class="alert-danger" style="margin-top: 12px">
        <div v-for="(w, i) in snippet?.warnings || []" :key="i">· {{ w }}</div>
      </div>

      <div class="hint" style="margin-top: 10px">
        改完执行 <span class="mono">systemctl restart frps</span>，重启期间隧道会断开几秒。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">可选加固项</span>
        <el-button size="small" @click="copy(hardening)">复制</el-button>
      </div>
      <pre class="code-block">{{ hardening }}</pre>
      <div class="hint" style="margin-top: 10px">
        非必需项。<span class="mono">auth.additionalScopes</span> 加到
        <span class="mono">HeartBeats</span> 或 <span class="mono">NewWorkConns</span>
        会让插件调用量随客户端数上升，非必要不要开。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">拦截判定链路</span>
      </div>
      <div class="flow">
        <div class="flow-node">frpc 发起连接</div>
        <div class="flow-arrow">→</div>
        <div class="flow-node">frps 回调插件</div>
        <div class="flow-arrow">→</div>
        <div class="flow-node accent">本程序判定</div>
        <div class="flow-arrow">→</div>
        <div class="flow-node">放行 / 拒绝</div>
      </div>
      <div class="hint" style="margin-top: 10px">
        <strong>Login</strong> 回调带 frpc 源 IP，用于识别连接方；
        <strong>NewUserConn</strong> 回调带访问者 IP，用于记录谁在访问隧道。
        两者走同一套白名单 → 黑名单 → 频次判定。
      </div>
      <div class="alert-note" style="margin-top: 10px">
        插件调用是<strong>同步阻塞</strong>的：判定必须在 100ms 内返回，超时按
        fail_mode 处理（默认放行）。因此判定路径上不做任何慢操作。
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const checking = ref(false)
const snippet = ref<any>(null)
const info = ref<any>(null)
const hardening = ref('')
const health = ref<any>(null)

const snippetText = computed(() => snippet.value?.snippet || '（加载中…）')

const protectedPorts = computed(() => {
  const ports: number[] = []
  const bp = snippet.value?.bind_port ?? info.value?.bind_port
  if (bp) ports.push(bp)
  for (const p of info.value?.proxy_ports || []) {
    if (p && !ports.includes(p)) ports.push(p)
  }
  return ports.length ? ports.join(', ') : '未配置'
})

async function load() {
  loading.value = true
  try {
    const [s, i] = await Promise.all([api.frpsSnippet() as any, api.systemInfo() as any])
    snippet.value = s
    info.value = i
    try {
      const c: any = await api.frpsConfig()
      hardening.value = c?.hardening || ''
    } catch {
      hardening.value = ''
    }
  } finally {
    loading.value = false
  }
}

async function doHealth() {
  checking.value = true
  try {
    health.value = await api.frpsHealth()
  } finally {
    checking.value = false
  }
}

async function copy(text: string) {
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    // 非 https 场景下 clipboard API 不可用，退回旧方案
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try {
      document.execCommand('copy')
      ElMessage.success('已复制')
    } catch {
      ElMessage.error('复制失败，请手动选中')
    }
    document.body.removeChild(ta)
  }
}

onMounted(load)
</script>

<style scoped>
.panel {
  padding: 16px 18px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  gap: 12px;
  flex-wrap: wrap;
}

.panel-head .section-title {
  margin: 0;
}

.mt {
  margin-top: 12px;
}

.flow {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.flow-node {
  padding: 8px 16px;
  border: 1px solid #dfe5ef;
  border-radius: 8px;
  background: #f8fafd;
  font-size: 13px;
  color: #1f2329;
}

.flow-node.accent {
  border-color: #b9d0fb;
  background: #eef4ff;
  color: #2f6fed;
  font-weight: 500;
}

.flow-arrow {
  color: #a8b0bd;
}

:deep(.el-descriptions__label) {
  width: 130px;
}
</style>
