<template>
  <div>
    <el-tabs v-model="tab" class="page-card panel" data-guide="events-panel" @tab-change="onTabChange">
      <el-tab-pane label="事件日志" name="events">
        <div class="filters">
          <el-select v-model="category" size="small" style="width: 140px" @change="reload">
            <el-option label="全部类别" value="all" />
            <el-option v-for="c in categories" :key="c.value" :label="c.label" :value="c.value" />
          </el-select>
          <el-select v-model="hours" size="small" style="width: 130px" @change="reload">
            <el-option label="最近 1 小时" :value="1" />
            <el-option label="最近 6 小时" :value="6" />
            <el-option label="最近 24 小时" :value="24" />
            <el-option label="最近 7 天" :value="168" />
            <el-option label="最近 30 天" :value="720" />
            <el-option label="不限时间" :value="0" />
          </el-select>
          <el-input
            v-model="keyword"
            size="small"
            placeholder="搜索 IP / 账号 / 代理 / 详情"
            clearable
            style="width: 220px"
            @keyup.enter="reload"
          />
          <el-button size="small" @click="reload">查询</el-button>
          <el-button size="small" @click="reset">重置</el-button>
          <!-- 刷新 = 按当前条件重新取一次并回到第 1 页。
               回第 1 页是刻意的：新事件插在最前面，停在第 5 页刷新等于
               把刚发生的事挡在视野外，而"看看现在怎么样"就是要看最新的 -->
          <el-button
            size="small"
            :loading="loading"
            style="margin-left: auto"
            @click="reload"
          >
            刷新
          </el-button>
        </div>

        <el-table
          :data="events"
          v-loading="loading"
          size="small"
          border
          empty-text="暂无事件"
          @header-dragend="cwEvents.onDragend"
        >
          <el-table-column label="时间" v-bind="cwEvents.col('时间', { width: 165 })">
            <template #default="{ row }">{{ fmt(row.ts) }}</template>
          </el-table-column>
          <el-table-column label="类别" v-bind="cwEvents.col('类别', { width: 110 })">
            <template #default="{ row }">
              <el-tag size="small" :type="catType(row.category)">{{ catName(row.category) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="ip" label="IP" v-bind="cwEvents.col('IP', { width: 150 })">
            <template #default="{ row }">
              <span v-if="row.ip" class="mono">{{ row.ip }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="属地" v-bind="cwEvents.col('属地', { width: 150 })">
            <template #default="{ row }">
              <span v-if="row.country || row.province">
                {{ [row.country, row.province].filter(Boolean).join(' · ') }}
              </span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="user" label="账号" v-bind="cwEvents.col('账号', { width: 110 })">
            <template #default="{ row }">
              <span v-if="row.user">{{ row.user }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column
            prop="proxy_name"
            label="代理"
            v-bind="cwEvents.col('代理', { width: 140 })"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span v-if="row.proxy_name" class="mono">{{ row.proxy_name }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column
            prop="detail"
            label="详情"
            v-bind="cwEvents.col('详情', { minWidth: 300 })"
            show-overflow-tooltip
          />
          <el-table-column prop="actor" label="操作者" v-bind="cwEvents.col('操作者', { width: 100 })">
            <template #default="{ row }">
              <span v-if="row.actor">{{ row.actor }}</span>
              <span v-else class="hint">系统</span>
            </template>
          </el-table-column>
        </el-table>

        <TablePager v-model:page="page" v-model:size="size" :total="total" @change="loadEvents" />
      </el-tab-pane>

      <el-tab-pane label="规则变更审计" name="changes">
        <div class="filters">
          <el-button size="small" @click="loadChanges">刷新</el-button>
        </div>

        <el-table
          :data="changes"
          v-loading="loadingChanges"
          size="small"
          border
          empty-text="暂无记录"
          @header-dragend="cwChanges.onDragend"
        >
          <el-table-column label="时间" v-bind="cwChanges.col('时间', { width: 165 })">
            <template #default="{ row }">{{ fmt(row.ts) }}</template>
          </el-table-column>
          <el-table-column prop="backend" label="后端" v-bind="cwChanges.col('后端', { width: 100 })" />
          <el-table-column prop="action" label="动作" v-bind="cwChanges.col('动作', { width: 160 })">
            <template #default="{ row }">
              <span class="mono">{{ row.action }}</span>
            </template>
          </el-table-column>
          <el-table-column label="结果" v-bind="cwChanges.col('结果', { width: 90 })">
            <template #default="{ row }">
              <el-tag size="small" :type="row.result === 'success' ? 'success' : 'danger'">
                {{ row.result === 'success' ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column
            prop="payload"
            label="参数"
            v-bind="cwChanges.col('参数', { minWidth: 240 })"
            show-overflow-tooltip
          />
          <el-table-column
            prop="error"
            label="错误"
            v-bind="cwChanges.col('错误', { minWidth: 200 })"
            show-overflow-tooltip
          />
        </el-table>

        <TablePager
          v-model:page="cPage"
          v-model:size="cSize"
          :total="cTotal"
          @change="loadChanges"
        />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import api from '@/api'
import TablePager from '@/components/TablePager.vue'
import { useColumnWidths } from '@/utils/table'

// 两张表各记各的列宽：同名列（时间）在两张表里的含义不同，宽度也没必要联动。
const cwEvents = useColumnWidths('events-log')
const cwChanges = useColumnWidths('events-changes')

const tab = ref('events')

const categories = [
  { value: 'login_attempt', label: '登录放行' },
  { value: 'login_blocked', label: '登录拦截' },
  { value: 'user_conn', label: '访问连接' },
  { value: 'ban', label: '封禁' },
  { value: 'unban', label: '解封' },
  { value: 'rule_change', label: '规则变更' },
  { value: 'config', label: '配置变更' },
  { value: 'geoip', label: '属地库' },
  { value: 'auth', label: '面板认证' },
]

const events = ref<any[]>([])
const loading = ref(false)
const category = ref('all')
const hours = ref(24)
const keyword = ref('')
const page = ref(1)
const size = ref(20)
const total = ref(0)

const changes = ref<any[]>([])
const loadingChanges = ref(false)
const cPage = ref(1)
const cSize = ref(20)
const cTotal = ref(0)

function fmt(t?: string) {
  if (!t) return '—'
  return new Date(t).toLocaleString('zh-CN', { hour12: false })
}

function catName(c: string) {
  return categories.find((x) => x.value === c)?.label || c
}

function catType(c: string) {
  switch (c) {
    case 'login_blocked':
    case 'ban':
      return 'danger'
    case 'login_attempt':
      return 'success'
    case 'config':
    case 'rule_change':
    case 'auth':
      return 'warning'
    case 'unban':
    default:
      return 'info'
  }
}

async function loadEvents() {
  loading.value = true
  try {
    const params: Record<string, unknown> = {
      category: category.value,
      keyword: keyword.value,
      page: page.value,
      size: size.value,
    }
    if (hours.value > 0) params.hours = hours.value

    const r: any = await api.listEvents(params)
    events.value = r.items || []
    total.value = r.total || 0
  } finally {
    loading.value = false
  }
}

// 筛选条件变了必须回到第 1 页：留在第 5 页再换类别，新条件下那一页很可能
// 根本不存在，结果是一张空表 —— 看起来像"没搜到"，实际是页码越界了。
function reload() {
  page.value = 1
  loadEvents()
}

function reset() {
  category.value = 'all'
  hours.value = 24
  keyword.value = ''
  reload()
}

async function loadChanges() {
  loadingChanges.value = true
  try {
    const r: any = await api.listRuleChanges({ page: cPage.value, size: cSize.value })
    changes.value = r.items || []
    cTotal.value = r.total || 0
  } finally {
    loadingChanges.value = false
  }
}

function onTabChange(name: string | number) {
  if (name === 'changes' && !changes.value.length) loadChanges()
}

onMounted(() => reload())
</script>

<style scoped>
.panel {
  padding: 16px 18px;
}

.filters {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

:deep(.el-tabs__header) {
  margin-bottom: 16px;
}
</style>
