<template>
  <div>
    <el-tabs v-model="tab" class="page-card panel" @tab-change="onTabChange">
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
            placeholder="搜索 IP / 账号 / 详情"
            clearable
            style="width: 220px"
            @keyup.enter="reload"
          />
          <el-button size="small" @click="reload">查询</el-button>
          <el-button size="small" @click="reset">重置</el-button>
        </div>

        <el-table :data="events" v-loading="loading" size="small" empty-text="暂无事件">
          <el-table-column label="时间" width="165">
            <template #default="{ row }">{{ fmt(row.ts) }}</template>
          </el-table-column>
          <el-table-column label="类别" width="110">
            <template #default="{ row }">
              <el-tag size="small" :type="catType(row.category)">{{ catName(row.category) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="ip" label="IP" width="150">
            <template #default="{ row }">
              <span v-if="row.ip" class="mono">{{ row.ip }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="属地" width="150">
            <template #default="{ row }">
              <span v-if="row.country || row.province">
                {{ [row.country, row.province].filter(Boolean).join(' · ') }}
              </span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="user" label="账号" width="110">
            <template #default="{ row }">
              <span v-if="row.user">{{ row.user }}</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="detail" label="详情" min-width="300" show-overflow-tooltip />
          <el-table-column prop="actor" label="操作者" width="100">
            <template #default="{ row }">
              <span v-if="row.actor">{{ row.actor }}</span>
              <span v-else class="hint">系统</span>
            </template>
          </el-table-column>
        </el-table>

        <div class="more">
          <el-button v-if="hasMore" size="small" :loading="loading" @click="loadMore">
            加载更多
          </el-button>
          <span v-else-if="events.length" class="hint">已到底部</span>
          <span class="hint">已加载 {{ events.length }} 条<span v-if="total">，共 {{ total }} 条</span></span>
        </div>
      </el-tab-pane>

      <el-tab-pane label="规则变更审计" name="changes">
        <div class="filters">
          <el-button size="small" @click="loadChanges">刷新</el-button>
        </div>

        <el-table :data="changes" v-loading="loadingChanges" size="small" empty-text="暂无记录">
          <el-table-column label="时间" width="165">
            <template #default="{ row }">{{ fmt(row.ts) }}</template>
          </el-table-column>
          <el-table-column prop="backend" label="后端" width="100" />
          <el-table-column prop="action" label="动作" width="160">
            <template #default="{ row }">
              <span class="mono">{{ row.action }}</span>
            </template>
          </el-table-column>
          <el-table-column label="结果" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.result === 'success' ? 'success' : 'danger'">
                {{ row.result === 'success' ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="payload" label="参数" min-width="240" show-overflow-tooltip />
          <el-table-column prop="error" label="错误" min-width="200" show-overflow-tooltip />
        </el-table>

        <el-pagination
          v-model:current-page="cPage"
          v-model:page-size="cSize"
          :total="cTotal"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          class="pager"
          @current-change="loadChanges"
          @size-change="loadChanges"
        />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import api from '@/api'

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
const limit = 50
const cursor = ref(0)
const hasMore = ref(false)
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

// append 为 true 时接着上一页往后取，否则从最新一条重新开始
async function loadEvents(append = false) {
  loading.value = true
  try {
    const params: Record<string, unknown> = {
      category: category.value,
      keyword: keyword.value,
      limit,
    }
    if (hours.value > 0) params.hours = hours.value
    if (append && cursor.value) params.cursor = cursor.value

    const r: any = await api.listEvents(params)
    const items = r.items || []
    events.value = append ? [...events.value, ...items] : items
    cursor.value = r.next_cursor || 0
    hasMore.value = !!r.has_more
    if (!append) total.value = r.total || 0
  } finally {
    loading.value = false
  }
}

function loadMore() {
  loadEvents(true)
}

function reload() {
  cursor.value = 0
  loadEvents(false)
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

.more {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 12px;
}

.pager {
  margin-top: 14px;
  justify-content: flex-end;
}

:deep(.el-tabs__header) {
  margin-bottom: 16px;
}
</style>
