<template>
  <div>
    <el-row :gutter="12">
      <el-col :span="6" v-for="c in cards" :key="c.label">
        <div class="page-card stat-card">
          <div class="stat-value" :style="{ color: c.color }">{{ c.value }}</div>
          <div class="stat-label">{{ c.label }}</div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="12" class="mt">
      <el-col :span="16">
        <div class="page-card panel">
          <div class="panel-head">
            <span class="section-title">登录拦截趋势</span>
            <el-radio-group v-model="hours" size="small" @change="load">
              <el-radio-button :value="6">6 小时</el-radio-button>
              <el-radio-button :value="24">24 小时</el-radio-button>
              <el-radio-button :value="168">7 天</el-radio-button>
            </el-radio-group>
          </div>
          <div ref="trendRef" class="chart"></div>
          <div v-if="!hasTrend" class="empty-hint">该时间段内没有拦截记录</div>
        </div>
      </el-col>

      <el-col :span="8">
        <div class="page-card panel">
          <div class="section-title">运行状态</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="防火墙后端">
              <el-tag v-if="s.guard?.backend" size="small" type="success">{{ s.guard.backend }}</el-tag>
              <el-tag v-else size="small" type="info">未就绪</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="内核规则条数">{{ s.guard?.last_sync_rules ?? 0 }}</el-descriptions-item>
            <el-descriptions-item label="白名单 / 黑名单">
              {{ s.guard?.white_count ?? 0 }} / {{ s.guard?.black_count ?? 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="可信回源网段">{{ s.guard?.trusted_count ?? 0 }} 个</el-descriptions-item>
            <el-descriptions-item label="属地库">
              <span v-if="s.geoip?.country_loaded">GeoLite2 </span>
              <span v-if="s.geoip?.region_loaded">ip2region </span>
              <span v-if="!s.geoip?.country_loaded && !s.geoip?.region_loaded">未加载</span>
              <el-tag v-if="s.geoip?.stale" size="small" type="warning" style="margin-left:6px">已过期</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="观察模式">
              <el-tag :type="s.guard?.dry_run ? 'warning' : 'info'" size="small">
                {{ s.guard?.dry_run ? '开启（只记录不封禁）' : '关闭' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="最近同步">
              {{ fmtTime(s.guard?.last_sync_at) }}
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="s.guard?.last_sync_err" class="alert-danger" style="margin-top: 12px">
            规则同步异常：{{ s.guard.last_sync_err }}
          </div>
          <div v-if="warnings.length" class="alert-note" style="margin-top: 12px">
            <div v-for="(w, i) in warnings" :key="i" style="margin-bottom: 4px">· {{ w }}</div>
          </div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="12" class="mt">
      <el-col :span="12">
        <div class="page-card panel">
          <div class="section-title">Top 来源 IP</div>
          <el-table :data="stats.top_ips || []" size="small" :show-header="true" empty-text="暂无数据">
            <el-table-column type="index" width="50" label="#" />
            <el-table-column prop="name" label="IP 地址">
              <template #default="{ row }">
                <span class="mono">{{ row.name }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="拦截次数" width="100" />
          </el-table>
        </div>
      </el-col>

      <el-col :span="12">
        <div class="page-card panel">
          <div class="section-title">Top 来源地区</div>
          <el-table :data="stats.top_countries || []" size="small" empty-text="暂无数据">
            <el-table-column type="index" width="50" label="#" />
            <el-table-column prop="name" label="国家 / 地区" />
            <el-table-column prop="count" label="拦截次数" width="100" />
          </el-table>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import echarts, { type EChartsType } from '@/utils/echarts'
import api from '@/api'
import { useSystemStore } from '@/stores/system'

const sys = useSystemStore()
const s = computed<any>(() => sys.info || {})

const stats = ref<any>({})
const hours = ref(24)
const trendRef = ref<HTMLElement>()
let chart: EChartsType | null = null

const hasTrend = computed(() => (stats.value?.trend || []).length > 0)

const cards = computed(() => [
  {
    label: '当前活跃封禁',
    value: s.value.guard?.active_bans ?? 0,
    color: (s.value.guard?.active_bans ?? 0) > 0 ? '#e24b4a' : '#1f2329',
  },
  {
    label: `近 ${hours.value} 小时被拦截`,
    value: stats.value.total_login_fail ?? 0,
    color: (stats.value.total_login_fail ?? 0) > 0 ? '#e24b4a' : '#1f2329',
  },
  {
    label: `近 ${hours.value} 小时放行尝试`,
    value: stats.value.total_login_ok ?? 0,
    color: '#1f2329',
  },
  {
    label: '内核规则条数',
    value: s.value.guard?.last_sync_rules ?? 0,
    color: '#1f2329',
  },
])

const warnings = computed(() => {
  const rep = s.value.detect
  return rep?.warnings || []
})

function fmtTime(t?: string) {
  if (!t) return '—'
  return new Date(t).toLocaleString('zh-CN', { hour12: false })
}

async function load() {
  await sys.load()
  stats.value = await api.eventStats(hours.value)
  renderChart()
}

function renderChart() {
  if (!trendRef.value) return
  if (!chart) {
    chart = echarts.init(trendRef.value)
  }

  const trend = stats.value?.trend || []
  const x = trend.map((t: any) => {
    const d = new Date(t.hour)
    return hours.value > 48
      ? `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:00`
      : `${String(d.getHours()).padStart(2, '0')}:00`
  })
  const y = trend.map((t: any) => t.fail)

  chart.setOption({
    grid: { left: 44, right: 20, top: 24, bottom: 32 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      boundaryGap: false,
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
        name: '被拦截',
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: y,
        lineStyle: { color: '#e24b4a', width: 2 },
        itemStyle: { color: '#e24b4a' },
        areaStyle: { color: 'rgba(226,75,74,0.10)' },
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
.mt {
  margin-top: 12px;
}

.stat-card {
  padding: 18px 20px;
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

.chart {
  height: 280px;
  width: 100%;
}

.empty-hint {
  font-size: 12.5px;
  color: #8a919f;
  text-align: center;
  padding: 8px 0 4px;
}
</style>
