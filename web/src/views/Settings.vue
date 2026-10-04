<template>
  <div v-loading="loading">
    <el-alert
      v-if="restartRequired"
      type="warning"
      :closable="false"
      title="有配置改动尚未生效，重启服务后应用"
      class="mb"
    />

    <div class="page-card panel">
      <div class="section-title">面板</div>
      <el-form label-width="150px" style="max-width: 720px">
        <el-form-item label="监听地址">
          <el-input v-model="form.server.listen" placeholder="0.0.0.0:7930" />
          <div class="tip">默认 0.0.0.0:7930，对所有网卡开放；只给本机访问用 127.0.0.1:7930。若装的时候用过 --listen，它优先级更高，这里改了不生效</div>
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="form.server.auth.username" />
        </el-form-item>
        <el-form-item label="登录有效期">
          <el-input-number v-model="form.server.auth.token_ttl_hours" :min="1" :max="720" />
          <span class="unit">小时</span>
        </el-form-item>
        <el-form-item label="启用 HTTPS">
          <el-switch v-model="form.server.tls.enabled" />
        </el-form-item>
        <template v-if="form.server.tls.enabled">
          <el-form-item label="证书路径">
            <el-input v-model="form.server.tls.cert_file" placeholder="/etc/ssl/panel.crt" />
          </el-form-item>
          <el-form-item label="私钥路径">
            <el-input v-model="form.server.tls.key_file" placeholder="/etc/ssl/panel.key" />
          </el-form-item>
        </template>
      </el-form>
    </div>

    <div class="page-card panel">
      <div class="section-title">frps 对接</div>
      <el-form label-width="150px" style="max-width: 720px">
        <el-form-item label="插件监听地址">
          <el-input v-model="form.frps.plugin_listen" />
          <div class="tip">必须绑回环地址，插件接口不接受外部调用</div>
        </el-form-item>
        <el-form-item label="插件路径">
          <el-input v-model="form.frps.plugin_path" />
        </el-form-item>
        <el-form-item label="bindPort">
          <el-input-number v-model="form.frps.bind_port" :min="1" :max="65535" />
          <span class="unit">frps 的 bindPort，用于下发连接速率限制</span>
        </el-form-item>
        <el-form-item label="代理端口">
          <el-input v-model="proxyPortsText" placeholder="80,443,20000-30000" />
          <div class="tip">
            逗号分隔，支持区间 <span class="mono">20000-30000</span>。
            速率限制作用于此，「仅 frp 端口」的黑名单也按它封禁
          </div>
        </el-form-item>
        <el-form-item label="可信回源网段">
          <el-input
            v-model="trustedText"
            type="textarea"
            :rows="3"
            placeholder="103.21.244.0/22"
          />
          <div class="tip">
            每行或逗号分隔的 CIDR。来自这些网段的访问按 X-Forwarded-For 判定，
            避免把 CDN 节点封掉。留空则使用内置的 Cloudflare 回源段
          </div>
        </el-form-item>
      </el-form>
    </div>

    <div class="page-card panel">
      <div class="section-title">防护与日志</div>
      <el-form label-width="150px" style="max-width: 720px">
        <el-form-item label="总开关">
          <el-switch v-model="form.guard.enabled" />
          <span class="unit">关闭后只做判定与展示，不往防火墙写规则</span>
        </el-form-item>
        <el-form-item label="观察模式">
          <el-switch v-model="form.guard.dry_run" />
          <span class="unit">只记录不封禁，用于上线前验证误伤</span>
        </el-form-item>
        <el-form-item label="日志级别">
          <el-select v-model="form.log.level" style="width: 140px">
            <el-option label="debug" value="debug" />
            <el-option label="info" value="info" />
            <el-option label="warn" value="warn" />
            <el-option label="error" value="error" />
          </el-select>
        </el-form-item>
        <el-form-item label="日志文件">
          <el-input v-model="form.log.file" placeholder="留空输出到标准输出" />
        </el-form-item>
        <el-form-item label="事件保留天数">
          <el-input-number v-model="form.event.retention_days" :min="0" :max="3650" />
          <span class="unit">天，0 表示永久保留</span>
          <div class="tip">
            超过这个天数的事件由后台定时清理。保存后立即生效，
            <span class="warn">调小会立刻删除超期的历史记录，不可恢复</span>
          </div>
        </el-form-item>
        <el-form-item label="数据目录">
          <el-input :model-value="dataDir" disabled />
          <div class="tip">由启动参数 -data 决定，包含数据库与属地库文件</div>
        </el-form-item>
      </el-form>
    </div>

    <div class="page-card panel">
      <div class="section-title">版本更新</div>
      <el-form label-width="150px" style="max-width: 720px">
        <el-form-item label="在线检查更新">
          <el-switch v-model="form.update.enabled" />
          <span class="unit">关闭后面板不访问 GitHub，仍会显示当前版本与发布页链接</span>
        </el-form-item>
        <el-form-item label="检查来源">
          <el-input v-model="form.update.repo" placeholder="owner/name" />
          <div class="tip">
            用于查询 Release 的 GitHub 仓库。服务器访问不了 github.com 时会提示检查失败，
            此时可关闭上面的开关
          </div>
        </el-form-item>
      </el-form>
    </div>

    <div class="actions">
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      <el-button @click="load">重新载入</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const saving = ref(false)
const restartRequired = ref(false)
const dataDir = ref('')

const form = reactive<any>({
  server: {
    listen: '',
    tls: { enabled: false, cert_file: '', key_file: '' },
    auth: { username: 'admin', token_ttl_hours: 12 },
  },
  frps: {
    plugin_listen: '',
    plugin_path: '',
    bind_port: 7000,
    proxy_ports: '',
    trusted_proxies: [],
  },
  guard: { enabled: true, dry_run: false },
  log: { level: 'info', file: '' },
  update: { enabled: true, repo: '' },
  event: { retention_days: 30 },
})

const proxyPortsText = ref('')
const trustedText = ref('')

function splitList(s: string) {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

// checkPorts 与后端 portrange.Parse 保持同一套规则：单个端口或 lo-hi 区间，
// 逗号/分号/空白分隔，取值 1-65535。返回 null 表示合法，否则返回给人看的说明。
function checkPorts(s: string): string | null {
  const bad = s
    .split(/[,，;；\s]+/)
    .filter(Boolean)
    .find((tok) => {
      const m = /^(\d+)(?:[-:](\d+))?$/.exec(tok)
      if (!m) return true
      const lo = Number(m[1])
      const hi = m[2] ? Number(m[2]) : lo
      return lo < 1 || lo > 65535 || hi < 1 || hi > 65535
    })
  if (bad === undefined) return null
  return `端口「${bad}」无法识别：写单个端口（80）或区间（20000-30000），取值 1-65535`
}

async function load() {
  loading.value = true
  try {
    const r: any = await api.getConfig()
    const c = r.config || {}
    form.server = c.server || form.server
    form.frps = c.frps || form.frps
    form.guard = c.guard || form.guard
    form.log = c.log || form.log
    form.update = c.update || form.update
    form.event = c.event || form.event
    dataDir.value = r.data_dir || ''
    restartRequired.value = !!r.restart_required

    proxyPortsText.value = c.frps?.proxy_ports || ''
    trustedText.value = (c.frps?.trusted_proxies || []).join('\n')
  } finally {
    loading.value = false
  }
}

async function save() {
  // 先在本地拦一道非法端口。后端也会拒，但那边只能回一句
  // "请求格式不正确"，用户对着它猜不出自己哪里写错了。
  const portErr = checkPorts(proxyPortsText.value)
  if (portErr) {
    ElMessage.error(portErr)
    return
  }

  saving.value = true
  try {
    const body = {
      server: form.server,
      frps: {
        ...form.frps,
        // 文本原样提交：后端认的就是用户在框里敲的这种写法，
        // 中间不做结构转换，也就不会出现"转换时丢掉一半"。
        proxy_ports: proxyPortsText.value.trim(),
        trusted_proxies: splitList(trustedText.value),
      },
      guard: form.guard,
      log: form.log,
      update: form.update,
      event: form.event,
    }
    const r: any = await api.updateConfig(body)
    if (r?.restart_required) {
      restartRequired.value = true
      ElMessage.success('已保存，重启服务后生效')
    } else {
      restartRequired.value = false
      ElMessage.success('已保存')
    }
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.panel {
  padding: 16px 18px;
  margin-bottom: 12px;
}

.mb {
  margin-bottom: 12px;
}

.tip {
  font-size: 12px;
  color: #8a919f;
  line-height: 1.6;
  margin-top: 2px;
}

.unit {
  margin-left: 8px;
  font-size: 12.5px;
  color: #8a919f;
}

/* 不可逆操作的提示：这一句混在普通 tip 里会被当成套话划过去 */
.warn {
  color: #e6a23c;
}

.actions {
  display: flex;
  gap: 8px;
  padding: 4px 0 12px;
}
</style>
