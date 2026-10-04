<template>
  <div>
    <div class="page-card panel">
      <div class="panel-head">
        <span class="section-title">
          当前活跃封禁
          <el-tag size="small" type="danger" style="margin-left: 8px">{{ active.length }}</el-tag>
        </span>
        <div>
          <el-button size="small" @click="loadActive">刷新</el-button>
          <el-button type="primary" size="small" @click="openBan">手动封禁</el-button>
          <el-button
            size="small"
            type="warning"
            :disabled="!selected.length"
            @click="batchUnban"
          >
            批量解封
          </el-button>
        </div>
      </div>

      <el-table
        :data="active"
        v-loading="loadingActive"
        size="small"
        border
        empty-text="当前没有被封禁的地址"
        @selection-change="(v: any[]) => (selected = v)"
        @header-dragend="cwActive.onDragend"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="target" label="地址" v-bind="cwActive.col('地址', { minWidth: 160 })">
          <template #default="{ row }">
            <span class="mono">{{ row.target }}</span>
          </template>
        </el-table-column>
        <el-table-column label="属地" v-bind="cwActive.col('属地', { width: 150 })">
          <template #default="{ row }">
            <span v-if="row.country || row.province">
              {{ [row.country, row.province].filter(Boolean).join(' · ') }}
            </span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" v-bind="cwActive.col('来源', { width: 90 })">
          <template #default="{ row }">
            <el-tag size="small" :type="sourceType(row.source)">{{ sourceName(row.source) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="范围" v-bind="cwActive.col('范围', { width: 118 })">
          <template #default="{ row }">
            <el-tooltip :content="scopeTip(row.scope, row.ports)" placement="top">
              <el-tag size="small" :type="scopeTagType(row.scope)">
                {{ scopeLabel(row.scope) }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="封禁端口" v-bind="cwActive.col('封禁端口', { minWidth: 120 })">
          <template #default="{ row }">
            <span v-if="row.scope === 'custom' && row.ports" class="mono">{{ row.ports }}</span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column
          prop="reason"
          label="原因"
          v-bind="cwActive.col('原因', { minWidth: 220 })"
          show-overflow-tooltip
        />
        <el-table-column prop="user" label="触发账号" v-bind="cwActive.col('触发账号', { width: 100 })">
          <template #default="{ row }">
            <span v-if="row.user">{{ row.user }}</span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="剩余时间" v-bind="cwActive.col('剩余时间', { width: 130 })">
          <template #default="{ row }">
            <span v-if="row.permanent" class="permanent">永久</span>
            <span v-else class="countdown">{{ remain(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="阶梯" v-bind="cwActive.col('阶梯', { width: 70 })">
          <template #default="{ row }">第 {{ row.hit_count }} 级</template>
        </el-table-column>
        <el-table-column label="操作" v-bind="cwActive.col('操作', { width: 90 })" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="unban(row)">解封</el-button>
          </template>
        </el-table-column>
      </el-table>

      <TablePager v-model:page="aPage" v-model:size="aSize" :total="aTotal" @change="loadActive" />
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">封禁历史</span>
        <div class="filters">
          <el-select v-model="status" size="small" style="width: 120px" @change="searchHistory">
            <el-option label="全部" value="all" />
            <el-option label="生效中" value="active" />
            <el-option label="已过期" value="expired" />
            <el-option label="已解封" value="released" />
          </el-select>
          <el-input
            v-model="keyword"
            size="small"
            placeholder="搜索地址 / 原因"
            clearable
            style="width: 220px"
            @keyup.enter="searchHistory"
          />
          <el-button size="small" @click="searchHistory">查询</el-button>
        </div>
      </div>

      <el-table
        :data="history"
        v-loading="loadingHistory"
        size="small"
        border
        empty-text="暂无记录"
        @header-dragend="cwHistory.onDragend"
      >
        <el-table-column prop="target" label="地址" v-bind="cwHistory.col('地址', { minWidth: 150 })">
          <template #default="{ row }">
            <span class="mono">{{ row.target }}</span>
          </template>
        </el-table-column>
        <el-table-column label="属地" v-bind="cwHistory.col('属地', { width: 140 })">
          <template #default="{ row }">
            <span v-if="row.country || row.province">
              {{ [row.country, row.province].filter(Boolean).join(' · ') }}
            </span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" v-bind="cwHistory.col('来源', { width: 90 })">
          <template #default="{ row }">
            <el-tag size="small" :type="sourceType(row.source)">{{ sourceName(row.source) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="范围" v-bind="cwHistory.col('范围', { width: 118 })">
          <template #default="{ row }">
            <el-tooltip :content="scopeTip(row.scope, row.ports)" placement="top">
              <el-tag size="small" :type="scopeTagType(row.scope)">
                {{ scopeLabel(row.scope) }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="封禁端口" v-bind="cwHistory.col('封禁端口', { minWidth: 120 })">
          <template #default="{ row }">
            <span v-if="row.scope === 'custom' && row.ports" class="mono">{{ row.ports }}</span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column
          prop="reason"
          label="原因"
          v-bind="cwHistory.col('原因', { minWidth: 220 })"
          show-overflow-tooltip
        />
        <el-table-column label="状态" v-bind="cwHistory.col('状态', { width: 90 })">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row.status)">{{ statusName(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="封禁时间" v-bind="cwHistory.col('封禁时间', { width: 165 })">
          <template #default="{ row }">{{ fmt(row.banned_at) }}</template>
        </el-table-column>
        <el-table-column label="解除时间" v-bind="cwHistory.col('解除时间', { width: 165 })">
          <template #default="{ row }">
            <span v-if="row.released_at">{{ fmt(row.released_at) }}</span>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
      </el-table>

      <TablePager v-model:page="page" v-model:size="size" :total="total" @change="loadHistory" />
    </div>

    <el-dialog v-model="banVisible" title="手动封禁" width="480px">
      <el-form label-width="90px">
        <el-form-item label="地址">
          <el-input v-model="banForm.target" placeholder="1.2.3.4 或 1.2.3.0/24" />
        </el-form-item>
        <el-form-item label="原因">
          <el-input v-model="banForm.reason" placeholder="例如：恶意扫描" />
        </el-form-item>
        <el-form-item label="封禁范围">
          <el-radio-group v-model="banForm.scope">
            <el-radio-button
              v-for="o in SCOPE_OPTIONS"
              :key="o.value"
              :value="o.value"
            >
              {{ o.label }}
            </el-radio-button>
          </el-radio-group>
          <div class="hint" style="margin-top: 6px">{{ scopeFormHint(banForm.scope) }}</div>
        </el-form-item>
        <el-form-item v-if="banForm.scope === 'custom'" label="封禁端口">
          <el-input v-model="banForm.ports" placeholder="8080,9000-9100" />
          <div class="hint" style="margin-top: 6px">
            只影响内核层封哪些端口；frp 接入侧的拒绝仍按该地址整体生效。
          </div>
        </el-form-item>
        <el-form-item label="时长">
          <el-select v-model="banForm.duration" style="width: 100%">
            <el-option label="永久" :value="0" />
            <el-option label="10 分钟" :value="600" />
            <el-option label="1 小时" :value="3600" />
            <el-option label="1 天" :value="86400" />
            <el-option label="7 天" :value="604800" />
          </el-select>
        </el-form-item>
      </el-form>
      <div class="hint" style="margin-top: 4px">
        回环与内网地址受系统保护，无法封禁；白名单内的地址需先移出白名单。
      </div>
      <template #footer>
        <el-button @click="banVisible = false">取消</el-button>
        <el-button type="primary" :loading="banning" @click="submitBan">确定封禁</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'
import TablePager from '@/components/TablePager.vue'
import { SCOPE_OPTIONS, scopeFormHint, scopeLabel, scopeTagType, scopeTip } from '@/utils/scope'
import { useColumnWidths } from '@/utils/table'

// 活跃表与历史表各记各的列宽：两张表有「地址 / 属地 / 来源 / 范围」等同名列，
// 但内容用途不同，宽度没必要联动。
const cwActive = useColumnWidths('bans-active')
const cwHistory = useColumnWidths('bans-history')

const active = ref<any[]>([])
const history = ref<any[]>([])
const loadingActive = ref(false)
const loadingHistory = ref(false)
const selected = ref<any[]>([])
const status = ref('all')
const keyword = ref('')
// 活跃封禁分页
const aPage = ref(1)
const aSize = ref(20)
const aTotal = ref(0)
// 封禁历史分页
const page = ref(1)
const size = ref(20)
const total = ref(0)
const now = ref(Date.now())

const banVisible = ref(false)
const banning = ref(false)
const banForm = reactive({ target: '', reason: '', duration: 0, scope: 'all', ports: '' })

let timer: number | undefined

function fmt(t?: string) {
  if (!t) return '—'
  return new Date(t).toLocaleString('zh-CN', { hour12: false })
}

function remain(row: any) {
  const end = new Date(row.expires_at).getTime()
  let s = Math.max(0, Math.floor((end - now.value) / 1000))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h > 0) return `${h} 小时 ${m} 分`
  if (m > 0) return `${m} 分 ${sec} 秒`
  return `${sec} 秒`
}

function sourceName(s: string) {
  return { auto: '频次超限', manual: '人工', geoip: '地域', system: '系统' }[s] || s
}

function sourceType(s: string) {
  return { auto: 'danger', manual: 'warning', geoip: 'info', system: 'info' }[s] || 'info'
}

function statusName(s: string) {
  return { active: '生效中', expired: '已过期', released: '已解封' }[s] || s
}

function statusType(s: string) {
  return { active: 'danger', expired: 'info', released: 'success' }[s] || 'info'
}

async function loadActive() {
  loadingActive.value = true
  try {
    const r: any = await api.activeBans({ page: aPage.value, size: aSize.value })
    active.value = r.items || []
    aTotal.value = r.total || 0
  } finally {
    loadingActive.value = false
  }
}

async function loadHistory() {
  loadingHistory.value = true
  try {
    const r: any = await api.listBans({
      status: status.value,
      keyword: keyword.value,
      page: page.value,
      size: size.value,
    })
    history.value = r.items || []
    total.value = r.total || 0
  } finally {
    loadingHistory.value = false
  }
}

// 筛选条件变了回到第 1 页：停在第 5 页改状态筛选，新结果很可能不足 5 页，
// 用户看到的是一张空表，会以为"没有这类记录"。
function searchHistory() {
  page.value = 1
  loadHistory()
}

async function unban(row: any) {
  try {
    await ElMessageBox.confirm(`确定解封 ${row.target} 吗？`, '确认解封', { type: 'warning' })
  } catch {
    return
  }
  await api.deleteBan(row.record_id)
  ElMessage.success('已解封')
  await loadActive()
  await loadHistory()
}

async function batchUnban() {
  if (!selected.value.length) return
  try {
    await ElMessageBox.confirm(`确定解封选中的 ${selected.value.length} 个地址吗？`, '批量解封', {
      type: 'warning',
    })
  } catch {
    return
  }
  const ids = selected.value.map((r) => r.record_id)
  const r: any = await api.batchDeleteBan(ids)
  ElMessage.success(`成功 ${r.success} 个，失败 ${r.failed} 个`)
  await loadActive()
  await loadHistory()
}

function openBan() {
  Object.assign(banForm, { target: '', reason: '', duration: 0, scope: 'all', ports: '' })
  banVisible.value = true
}

async function submitBan() {
  if (!banForm.target) {
    ElMessage.warning('请填写地址')
    return
  }
  // 自定义范围没有端口就等于"封了等于没封"：内核规则一条都生成不出来，
  // 而列表里它会正常显示成一条生效中的封禁。后端也会拒绝，这里先拦一道省一次往返。
  if (banForm.scope === 'custom' && !banForm.ports.trim()) {
    ElMessage.warning('自定义范围需要至少一个端口')
    return
  }
  banning.value = true
  try {
    await api.createBan({
      target: banForm.target,
      reason: banForm.reason,
      duration_sec: banForm.duration,
      scope: banForm.scope,
      // 非自定义范围传空串而不是省略字段：库里残留一份不参与生效的端口，
      // 是"配置里写着、实际不生效"那类最难排查的问题。
      ports: banForm.scope === 'custom' ? banForm.ports.trim() : '',
    })
    ElMessage.success('已封禁')
    banVisible.value = false
    await loadActive()
    await loadHistory()
  } finally {
    banning.value = false
  }
}

onMounted(() => {
  loadActive()
  loadHistory()
  timer = window.setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
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
  margin-bottom: 14px;
  gap: 12px;
  flex-wrap: wrap;
}

.panel-head .section-title {
  margin: 0;
}

.filters {
  display: flex;
  gap: 8px;
}

.countdown {
  color: #d0730f;
  font-variant-numeric: tabular-nums;
}

.permanent {
  color: #e24b4a;
  font-weight: 500;
}
</style>
