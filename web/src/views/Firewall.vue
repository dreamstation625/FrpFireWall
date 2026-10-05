<template>
  <div>
    <el-row :gutter="12">
      <el-col :span="12">
        <div class="page-card panel">
          <div class="section-title">防火墙后端</div>

          <el-radio-group v-model="backend" :disabled="switching">
            <el-radio-button value="auto">自动选择</el-radio-button>
            <el-radio-button value="nftables">nftables</el-radio-button>
            <el-radio-button value="iptables">iptables</el-radio-button>
          </el-radio-group>

          <div class="kv" style="margin-top: 14px">
            <div class="kv-row">
              <span class="kv-key">当前生效</span>
              <span class="kv-val">
                <el-tag v-if="cap.backend" size="small" type="success">{{ cap.backend }}</el-tag>
                <el-tag v-else size="small" type="info">未就绪</el-tag>
                <span v-if="cap.version" class="hint" style="margin-left: 8px">v{{ cap.version }}</span>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-key">per-IP 连接限速</span>
              <span class="kv-val">
                <el-tag :type="cap.rate_limit ? 'success' : 'info'" size="small">
                  {{ cap.rate_limit ? '支持' : '不支持' }}
                </el-tag>
              </span>
            </div>
          </div>

          <div v-if="cap.reason" class="alert-note" style="margin-top: 12px">{{ cap.reason }}</div>

          <div class="hint" style="margin-top: 12px">
            切换时先在新后端建链并灌入规则，再切判定，中间没有保护真空。
            旧后端的残留规则不会自动清理，需要时用
            <span class="mono">scripts/frpfirewall-panic.sh</span>。
          </div>

          <div style="margin-top: 14px">
            <el-button type="primary" :loading="switching" @click="onSwitch">应用后端设置</el-button>
            <el-button :loading="detecting" @click="onDetect">重新探测环境</el-button>
          </div>
        </div>
      </el-col>

      <el-col :span="12">
        <div class="page-card panel">
          <div class="section-title">环境探测结果</div>

          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="操作系统">
              {{ rep.os_pretty || rep.os || '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="内核">{{ rep.kernel || '—' }}</el-descriptions-item>
            <el-descriptions-item label="iptables">
              <span v-if="rep.has_iptables">
                v{{ rep.iptables_version }}
                <el-tag size="small" type="info" style="margin-left: 6px">{{ rep.iptables_provider }}</el-tag>
              </span>
              <span v-else class="hint">未安装</span>
            </el-descriptions-item>
            <el-descriptions-item label="nftables">
              <span v-if="rep.has_nftables">v{{ rep.nftables_version }}</span>
              <span v-else class="hint">未安装</span>
            </el-descriptions-item>
            <el-descriptions-item label="建议后端">
              <el-tag v-if="rep.recommended" size="small" type="success">{{ rep.recommended }}</el-tag>
              <span v-else class="hint">无可用后端</span>
            </el-descriptions-item>
            <el-descriptions-item label="冲突组件">
              <el-tag v-if="rep.firewalld_active" size="small" type="warning" style="margin-right: 4px">firewalld</el-tag>
              <el-tag v-if="rep.ufw_active" size="small" type="warning" style="margin-right: 4px">ufw</el-tag>
              <el-tag v-if="rep.baota_present" size="small" type="warning">宝塔面板</el-tag>
              <span v-if="!rep.firewalld_active && !rep.ufw_active && !rep.baota_present" class="hint">未发现</span>
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="(rep.warnings || []).length" class="alert-note" style="margin-top: 12px">
            <div v-for="(w, i) in rep.warnings" :key="i" style="margin-bottom: 4px">· {{ w }}</div>
          </div>
        </div>
      </el-col>
    </el-row>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">本程序受管规则</span>
        <div>
          <el-button size="small" @click="loadManaged">刷新</el-button>
          <el-button size="small" @click="onPreview">预览将下发的规则</el-button>
        </div>
      </div>

      <div v-if="managedError" class="alert-note">{{ managedError }}</div>
      <template v-else>
        <div v-if="(managed?.summary || []).length" class="summary-list">
          <div v-for="(l, i) in managed.summary" :key="i" class="summary-line mono">{{ l }}</div>
        </div>
        <el-collapse v-if="managed?.raw">
          <el-collapse-item title="查看原始规则文本">
            <pre class="code-block">{{ managed.raw }}</pre>
          </el-collapse-item>
        </el-collapse>
      </template>
    </div>

    <!-- 与概览页共用同一块面板（components/CounterPanel.vue），
         口径与展示只有一份实现，不会出现两处数字不一致。 -->
    <CounterPanel class="mt" />

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">系统防火墙规则（只读）</span>
        <el-button size="small" @click="loadSystem">加载 / 刷新</el-button>
      </div>
      <div class="hint" style="margin-bottom: 10px">
        主机当前全部规则，仅供查看。本程序不修改其中任何非受管规则。
      </div>
      <pre v-if="systemRaw" class="code-block" style="max-height: 460px">{{ systemRaw }}</pre>
      <div v-else class="hint">尚未加载。</div>
    </div>

    <el-drawer v-model="previewVisible" title="规则预览" size="640px">
      <div class="hint" style="margin-bottom: 10px">
        当前期望状态下将下发的规则，尚未写入内核。
      </div>
      <pre class="code-block">{{ previewText }}</pre>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'
import CounterPanel from '@/components/CounterPanel.vue'
import { useSystemStore } from '@/stores/system'

const sys = useSystemStore()

const backend = ref('auto')
const switching = ref(false)
const detecting = ref(false)
const managed = ref<any>(null)
const managedError = ref('')
const systemRaw = ref('')
const previewVisible = ref(false)
const previewText = ref('')

const rep = computed<any>(() => sys.info?.detect || {})
const cap = computed<any>(() => sys.info?.capability || {})

async function loadManaged() {
  managedError.value = ''
  try {
    managed.value = await api.managedRules()
  } catch (e: any) {
    managed.value = null
    managedError.value =
      '读取受管规则失败（通常是因为当前没有可用的防火墙后端）：' + (e?.response?.data?.error || e?.message || '')
  }
}

async function loadSystem() {
  try {
    const r: any = await api.systemRules()
    systemRaw.value = r.raw || ''
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '读取系统规则失败')
  }
}

async function onSwitch() {
  const label = { auto: '自动选择', nftables: 'nftables', iptables: 'iptables' }[backend.value] || backend.value
  try {
    await ElMessageBox.confirm(
      `确定把防火墙后端切换为「${label}」吗？切换会重建受管链并重新灌入封禁规则。`,
      '确认切换',
      { type: 'warning', confirmButtonText: '确定切换' }
    )
  } catch {
    return
  }

  switching.value = true
  try {
    const r: any = await api.switchBackend(backend.value)
    ElMessage.success(`已切换到 ${r.backend}`)
    await sys.load()
    await loadManaged()
  } finally {
    switching.value = false
  }
}

async function onDetect() {
  detecting.value = true
  try {
    await sys.detect()
    ElMessage.success('探测完成')
  } finally {
    detecting.value = false
  }
}

async function onPreview() {
  try {
    const r: any = await api.preview()
    previewText.value = r.preview || ''
    previewVisible.value = true
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '生成预览失败')
  }
}

onMounted(async () => {
  await sys.load()
  const p: any = await api.getPolicy().catch(() => null)
  if (p) {
    // 回显当前后端偏好
    const info: any = sys.info
    backend.value = info?.guard?.backend || 'auto'
  }
  loadManaged()
})
</script>

<style scoped>
.mt {
  margin-top: 12px;
}

.panel {
  padding: 16px 18px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.panel-head .section-title {
  margin: 0;
}

.kv-row {
  display: flex;
  align-items: center;
  padding: 6px 0;
  font-size: 13px;
}

.kv-key {
  width: 130px;
  color: #8a919f;
}

.kv-val {
  flex: 1;
}

.summary-list {
  background: #f7f8fa;
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  padding: 10px 14px;
  max-height: 320px;
  overflow: auto;
}

.summary-line {
  font-size: 12.5px;
  line-height: 1.9;
  color: #1f2329;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
