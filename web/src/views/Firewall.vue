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

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">防火墙拦截统计</span>
        <div>
          <el-radio-group v-model="counterHours" size="small" @change="loadCounters">
            <el-radio-button :value="24">24 小时</el-radio-button>
            <el-radio-button :value="168">7 天</el-radio-button>
          </el-radio-group>
          <el-button size="small" style="margin-left: 8px" @click="loadCounters">刷新</el-button>
        </div>
      </div>

      <div class="hint" style="margin-bottom: 10px">
        数的是<strong>内核拦截（丢弃）的包</strong>，由内核计数、不是本程序数的；每 5 分钟采一次用于画趋势。
        <span v-if="counters?.granularity === 'group'">
          当前后端是 nftables：地址装在集合里、规则只有一条，所以只能按分组统计，
          数不出单个地址被拦了多少。
        </span>
        <span v-else-if="counters?.granularity === 'addr'">
          frp 登录被拒的连接不经过内核，不在这里 —— 那些记在事件日志里。
        </span>
      </div>

      <div v-if="counters?.unsupported" class="alert-note">{{ counters.unsupported }}</div>
      <template v-else>
        <div class="counter-total">
          <div class="counter-total-num">{{ fmtNum(counters?.total_packets || 0) }}</div>
          <div class="counter-total-label">
            当前累计拦截
            <span class="hint">
              （规则重建、切换后端、重启防火墙后归零重新数）
            </span>
          </div>
        </div>

        <div v-if="(counters?.series || []).length" ref="chartRef" class="counter-chart"></div>
        <div v-else class="hint" style="margin-bottom: 10px">
          还没有采样点。首次采样在程序启动时进行，之后每 5 分钟一次。
        </div>

        <el-table :data="counterRows" size="small" border empty-text="暂无条目" max-height="380">
          <el-table-column prop="label" label="条目" min-width="180" show-overflow-tooltip />
          <el-table-column prop="kind" label="类型" width="96">
            <template #default="{ row }">
              <el-tag size="small" :type="row.kind === 'addr' ? 'info' : 'warning'">
                {{ kindLabel(row.kind) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="packets" label="拦截" width="110" align="right">
            <template #default="{ row }">{{ fmtNum(row.packets) }}</template>
          </el-table-column>
          <el-table-column label="较上批" width="110" align="right">
            <template #default="{ row }">
              <span v-if="counters?.baseline_at">+{{ fmtNum(row.delta_packets) }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="bytes" label="字节" width="120" align="right">
            <template #default="{ row }">{{ fmtBytes(row.bytes) }}</template>
          </el-table-column>
        </el-table>
      </template>
    </div>

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
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'
import echarts, { type EChartsType } from '@/utils/echarts'
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

const counters = ref<any>(null)
const counterHours = ref(24)
const chartRef = ref<HTMLElement | null>(null)
let chart: EChartsType | null = null

// 表格只显示有量的条目：几百条全是 0 的封禁条目会把真正被拦的那几条淹掉，
// 而"哪些条目在挨打"才是这张表存在的意义。
const counterRows = computed<any[]>(() =>
  (counters.value?.items || []).filter((r: any) => r.packets > 0 || r.delta_packets > 0)
)

const kindLabel = (k: string) =>
  ({ addr: '地址', port: '端口限定', group: '分组', rate: '限速' }[k] || k)

function fmtNum(n: number) {
  return (n ?? 0).toLocaleString('zh-CN')
}

function fmtBytes(n: number) {
  const v = n ?? 0
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  if (v < 1024 * 1024 * 1024) return `${(v / 1024 / 1024).toFixed(1)} MB`
  return `${(v / 1024 / 1024 / 1024).toFixed(2)} GB`
}

async function loadCounters() {
  try {
    counters.value = await api.counters(counterHours.value)
    // 图表容器挂在 v-if="series.length" 上：首次拿到数据时 DOM 还没渲染，
    // chartRef 还是 null，必须等一帧再画，否则首次进页面图表是空的、
    // 要手动点一次"刷新"才出现。
    await nextTick()
    renderCounterChart()
  } catch (e: any) {
    counters.value = null
    ElMessage.error(e?.response?.data?.error || '读取防火墙拦截统计失败')
  }
}

// 趋势画的是"这一批新增了多少"，不是累计值：累计值在规则重建时会掉回 0，
// 画成折线会出现毫无意义的断崖。
function renderCounterChart() {
  if (!chartRef.value) return
  // v-if 会在"没有采样点 / 有采样点"之间挂卸容器，旧实例可能还抱着一个
  // 已经不在文档里的 DOM —— 先对齐实例与当前容器，再谈画图。
  if (chart && chart.getDom() !== chartRef.value) {
    chart.dispose()
    chart = null
  }
  if (!chart) {
    chart = echarts.init(chartRef.value)
  }
  const pad = (n: number) => String(n).padStart(2, '0')
  const pts: any[] = counters.value?.series || []
  const x = pts.map((p) => {
    const d = new Date(p.ts)
    // 采样是每 5 分钟一批，轴标签必须带分钟，写死 ":00" 会一列全是整点。
    return counterHours.value > 48
      ? `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
      : `${pad(d.getHours())}:${pad(d.getMinutes())}`
  })
  chart.setOption({
    grid: { left: 52, right: 16, top: 16, bottom: 30 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: x,
      axisLine: { lineStyle: { color: '#e4e7ed' } },
      axisLabel: { color: '#8a919f', fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { color: '#f0f2f5' } },
      axisLabel: { color: '#8a919f', fontSize: 11 },
    },
    series: [
      {
        name: '新增拦截',
        type: 'bar',
        data: pts.map((p) => p.packets),
        itemStyle: { color: '#e24b4a' },
        barMaxWidth: 18,
      },
    ],
  })
  chart.resize()
}

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

function onResize() {
  chart?.resize()
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
  loadCounters()
  window.addEventListener('resize', onResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.mt {
  margin-top: 12px;
}

.counter-total {
  margin-bottom: 12px;
}

.counter-total-num {
  font-size: 26px;
  font-weight: 600;
  line-height: 1.2;
}

.counter-total-label {
  font-size: 12px;
  color: #8a919f;
}

.counter-chart {
  width: 100%;
  height: 200px;
  margin-bottom: 12px;
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
