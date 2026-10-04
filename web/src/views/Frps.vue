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
        <!-- 跨两列：这一行要能改，挤在半列里连端口串都看不全 -->
        <el-descriptions-item label="受保护端口" :span="2">
          <div class="protect-row">
            <span class="protect-bind">
              bindPort
              <span class="mono">{{ bindPort ?? '—' }}</span>
            </span>
            <el-input
              v-model="proxyPortsText"
              size="small"
              class="protect-input"
              placeholder="80,443,20000-30000"
              @keyup.enter="saveProtectPorts"
            />
            <el-button
              size="small"
              type="primary"
              :loading="savingPorts"
              :disabled="!portsDirty"
              @click="saveProtectPorts"
            >
              保存
            </el-button>
            <el-button v-if="portsDirty" size="small" @click="resetPorts">还原</el-button>
          </div>
          <div class="hint" style="margin-top: 6px">
            实际生效：<span class="mono">{{ effectivePorts }}</span>
            <template v-if="portsDirty">
              —— 改动后点保存立即生效，不需要重启（<span class="mono">bindPort</span> 始终
              包含在内，改不了，它属于 frps 自己的配置）
            </template>
          </div>
        </el-descriptions-item>
      </el-descriptions>

      <div class="hint" style="margin-top: 10px">
        插件只监听回环地址，frps 必须与本程序同机。
        防火墙规则只针对上面这个受保护端口集合下发：<span class="mono">bind_port</span> 与
        <span class="mono">proxy_ports</span> 的并集。「仅 frp 端口」的封禁范围、
        以及全局限速的兜底规则，用的都是它。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">{{ cfgFile }} 需要增加的配置</span>
        <div class="head-actions">
          <el-radio-group v-model="fmt" size="small">
            <el-radio-button value="toml">TOML</el-radio-button>
            <el-radio-button value="json">JSON</el-radio-button>
          </el-radio-group>
          <el-button size="small" @click="copy(snippetText)">复制</el-button>
        </div>
      </div>

      <pre class="code-block">{{ snippetText }}</pre>

      <div v-if="fmt === 'json'" class="alert-note" style="margin-top: 12px">
        JSON 没有「追加一段」的语法：要把上面这串里的
        <span class="mono">httpPlugins</span> 元素合并进你现有的
        <span class="mono">frps.json</span>，别拿它整个覆盖 —— 那会丢掉
        <span class="mono">bindPort</span> 等已有配置。另外标准 JSON 不支持注释，
        TOML 版本里的说明文字带不过来，看下面那几条提醒。
      </div>

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
        <div class="head-actions">
          <el-radio-group v-model="fmt" size="small">
            <el-radio-button value="toml">TOML</el-radio-button>
            <el-radio-button value="json">JSON</el-radio-button>
          </el-radio-group>
          <el-button size="small" @click="copy(hardeningText)">复制</el-button>
        </div>
      </div>
      <pre class="code-block">{{ hardeningText }}</pre>
      <div v-if="fmt === 'json'" class="alert-note" style="margin-top: 12px">
        JSON 版本比 TOML 少一项 <span class="mono">auth.additionalScopes</span>：
        TOML 里它是被注释掉的可选项，而 JSON 没有注释语法，写进文件就等于打开。
        确实需要的话，自己往顶层加
        <span class="mono">"auth": { "additionalScopes": ["HeartBeats"] }</span>。
      </div>
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
const cfg = ref<any>(null)
const health = ref<any>(null)

// 配置文件格式。frp 从 v0.52.0 起同时支持 TOML / YAML / JSON，
// 用哪一份取决于用户手上那个文件的后缀 —— 所以两份都下发，由用户自己切。
// 两个卡片共用这一个状态：用户「用的是 json 配置」是这个人的属性，不是某张卡片的属性，
// 分成两个开关迟早会出现一张卡片 TOML、另一张 JSON 的错配。
const fmt = ref<'toml' | 'json'>('toml')

const cfgFile = computed(() => (fmt.value === 'json' ? 'frps.json' : 'frps.toml'))

const snippetText = computed(() => {
  const s = snippet.value
  if (!s) return '（加载中…）'
  return (fmt.value === 'json' ? s.snippet_json : s.snippet) || '（加载中…）'
})

const hardeningText = computed(() => {
  const c = cfg.value
  if (!c) return ''
  return (fmt.value === 'json' ? c.hardening_json : c.hardening) || ''
})

// 受保护端口 = bindPort ∪ 代理端口。这里不再自己拼：后端把三段（bindPort、
// 代理端口、合并后的受保护端口）一起回给界面，"改完端口后 7000 从哪来的"
// 这个问题只有一个答案，两边各拼一次迟早会对不上。
const bindPort = ref<number | null>(null)
const proxyPortsText = ref('')
// 上一次保存成功的值，用来判断有没有改动（决定"保存"按钮是否可点）
const savedProxyPorts = ref('')
const effectivePorts = ref('未配置')
const savingPorts = ref(false)

const portsDirty = computed(() => proxyPortsText.value.trim() !== savedProxyPorts.value)

async function load() {
  loading.value = true
  try {
    const [s, i] = await Promise.all([api.frpsSnippet() as any, api.systemInfo() as any])
    snippet.value = s
    info.value = i
    try {
      cfg.value = await api.frpsConfig()
    } catch {
      // 加固项拿不到不影响主流程（接入片段才是必须的），降级成空即可
      cfg.value = null
    }
    // 受保护端口单独取一次：写接口改的也是它，用同一个来源读写才不会出现
    // "刚保存完却显示旧值"。拿不到就退回 systemInfo 里那份，页面照常可用。
    try {
      applyPorts(await (api.frpsProtectPorts() as any))
    } catch {
      applyPorts({
        bind_port: snippet.value?.bind_port ?? info.value?.bind_port,
        proxy_ports: info.value?.proxy_ports,
        ports: info.value?.protect_ports,
      })
    }
  } finally {
    loading.value = false
  }
}

function applyPorts(d: any) {
  bindPort.value = d?.bind_port ?? null
  proxyPortsText.value = String(d?.proxy_ports || '')
  savedProxyPorts.value = proxyPortsText.value
  effectivePorts.value = String(d?.ports || '') || '未配置'
}

function resetPorts() {
  proxyPortsText.value = savedProxyPorts.value
}

async function saveProtectPorts() {
  // 空值先在本地拦一道：后端会把空值当成"没配过"、重启后回落成默认端口，
  // 也就是"保存完看着生效了、重启又变回去"。后端也会拒，这里只是少跑一趟、
  // 并把话说得更直接。
  if (!proxyPortsText.value.trim()) {
    ElMessage.warning('代理端口不能为空：留空会被当作未配置，重启后会回落成默认值')
    return
  }
  savingPorts.value = true
  try {
    // 只提交代理端口那一半：bindPort 由 frps 自己的配置决定，改这里不会让 frps
    // 换端口，只会让防火墙规则和实际监听的端口错位。
    applyPorts(await (api.updateFrpsProtectPorts({ proxy_ports: proxyPortsText.value.trim() }) as any))
    ElMessage.success('受保护端口已更新并生效')
  } finally {
    savingPorts.value = false
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

/* 格式切换与复制按钮凑一组，和左侧标题分列两端 */
.head-actions {
  display: flex;
  align-items: center;
  gap: 8px;
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

/* 受保护端口的编辑行：bindPort 只读、代理端口可改，两者并排摆着才看得出
   "受保护端口 = 这两部分的并集"这层关系 */
.protect-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.protect-bind {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 8px;
  height: 24px;
  border: 1px solid #dfe5ef;
  border-radius: 4px;
  background: #f4f6fa;
  color: #6b7480;
  font-size: 12px;
  white-space: nowrap;
}

.protect-input {
  width: 260px;
}

:deep(.el-descriptions__label) {
  width: 130px;
}
</style>
