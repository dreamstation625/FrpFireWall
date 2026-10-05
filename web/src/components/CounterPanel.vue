<template>
  <div class="page-card panel">
    <div class="panel-head">
      <span class="section-title">防火墙拦截统计</span>
      <div>
        <el-radio-group v-model="hours" size="small" @change="load">
          <el-radio-button :value="24">24 小时</el-radio-button>
          <el-radio-button :value="168">7 天</el-radio-button>
        </el-radio-group>
        <el-button size="small" style="margin-left: 8px" @click="load">刷新</el-button>
      </div>
    </div>

    <div v-if="error" class="alert-note">{{ error }}</div>
    <div v-else-if="!counters" class="hint">读取中…</div>
    <template v-else>
      <div v-if="counters.unsupported" class="alert-note">{{ counters.unsupported }}</div>
      <template v-else>
        <div class="hint desc" style="margin-bottom: 10px">
          数的是<strong>内核拦截（丢弃）的包</strong>，由内核计数、不是本程序数的；每 5 分钟采一次用于画趋势。
          <span v-if="counters?.granularity === 'group'">
            当前后端是 nftables：地址装在集合里、规则只有一条，所以只能按分组统计，
            数不出单个地址被拦了多少。
          </span>
          <span v-else-if="counters?.granularity === 'addr'">
            frp 登录被拒的连接不经过内核，不在这里 —— 那些记在事件日志里。
          </span>
        </div>

        <div class="counter-total">
          <div class="counter-total-num">{{ fmtNum(counters?.total_packets || 0) }}</div>
          <div class="counter-total-label">
            当前累计拦截
            <span class="hint">（规则重建、切换后端、重启防火墙后归零重新数）</span>
          </div>
        </div>

        <div v-if="(counters?.series || []).length" ref="chartRef" :class="['counter-chart', { compact }]"></div>
        <div v-else class="hint" style="margin-bottom: 10px">
          还没有采样点。首次采样在程序启动时进行，之后每 5 分钟一次。
        </div>

        <el-table :data="rows" size="small" border empty-text="暂无条目" :max-height="compact ? 260 : 380">
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
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import api from '@/api'
import echarts, { type EChartsType } from '@/utils/echarts'

// 概览页与防火墙页共用同一块面板：口径、图表、表格只有一份实现，
// 两处不会因为各写一遍而显示成两套数字。compact 只压缩高度、隐藏说明。
const props = withDefaults(defineProps<{ compact?: boolean }>(), { compact: false })

const counters = ref<any>(null)
const error = ref('')
const hours = ref(24)
const chartRef = ref<HTMLElement | null>(null)
let chart: EChartsType | null = null

// 表格只显示有量的条目：几百条全是 0 的封禁条目会把真正被拦的那几条淹掉，
// 而"哪些条目在挨打"才是这张表存在的意义。
const rows = computed<any[]>(() =>
  (counters.value?.items || []).filter((r: any) => r.packets > 0 || r.delta_packets > 0)
)

const kindLabel = (k: string) => ({ addr: '地址', port: '端口限定', group: '分组', rate: '限速' }[k] || k)

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

async function load() {
  try {
    counters.value = await api.counters(hours.value)
    error.value = ''
    // 图表容器挂在 v-if="series.length" 上：首次拿到数据时 DOM 还没渲染，
    // chartRef 还是 null，必须等一帧再画，否则首次进页面图表是空的、
    // 要手动点一次"刷新"才出现。
    await nextTick()
    renderChart()
  } catch (e: any) {
    counters.value = null
    // 面板内提示而不弹红框：概览页也挂着这块，弹窗太吵。
    error.value = e?.response?.data?.error || '读取防火墙拦截统计失败'
  }
}

// 趋势画的是"这一批新增了多少"，不是累计值：累计值在规则重建时会掉回 0，
// 画成折线会出现毫无意义的断崖。
function renderChart() {
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
    return hours.value > 48
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

function onResize() {
  chart?.resize()
}

onMounted(() => {
  load()
  window.addEventListener('resize', onResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
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

.counter-chart.compact {
  height: 160px;
}

.desc {
  display: block;
}
</style>
