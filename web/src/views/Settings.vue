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
          <div class="tip">只监听本机用 127.0.0.1:7930，对外网开放用 0.0.0.0:7930</div>
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
          <el-input v-model="proxyPortsText" placeholder="80,443" />
          <div class="tip">逗号分隔。NewUserConn 回调只在这些端口上参与判定</div>
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
        <el-form-item label="数据目录">
          <el-input :model-value="dataDir" disabled />
          <div class="tip">由启动参数 -data 决定，包含数据库与属地库文件</div>
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
    proxy_ports: [],
    trusted_proxies: [],
  },
  guard: { enabled: true, dry_run: false },
  log: { level: 'info', file: '' },
})

const proxyPortsText = ref('')
const trustedText = ref('')

function splitList(s: string) {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
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
    dataDir.value = r.data_dir || ''
    restartRequired.value = !!r.restart_required

    proxyPortsText.value = (c.frps?.proxy_ports || []).join(',')
    trustedText.value = (c.frps?.trusted_proxies || []).join('\n')
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const body = {
      server: form.server,
      frps: {
        ...form.frps,
        proxy_ports: splitList(proxyPortsText.value).map(Number).filter((n) => n > 0),
        trusted_proxies: splitList(trustedText.value),
      },
      guard: form.guard,
      log: form.log,
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

.actions {
  display: flex;
  gap: 8px;
  padding: 4px 0 12px;
}
</style>
