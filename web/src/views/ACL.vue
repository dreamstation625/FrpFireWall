<template>
  <div class="page-card panel">
    <el-tabs v-model="kind" @tab-change="onTabChange">
      <el-tab-pane label="白名单" name="white" />
      <el-tab-pane label="黑名单" name="black" />
    </el-tabs>

    <el-alert
      v-if="kind === 'white'"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 12px"
      title="白名单地址不受本程序封禁（含自动封禁与地域封禁），但也不会额外放行端口。"
    />
    <el-alert
      v-else
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 12px"
      title="黑名单中的地址会被立即拒绝登录，并同步写入内核防火墙。"
    />

    <div class="toolbar">
      <el-input
        v-model="keyword"
        placeholder="搜索地址 / 备注 / 属地"
        clearable
        style="width: 260px"
        @keyup.enter="reload"
      >
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-button @click="reload">查询</el-button>
      <div class="spacer" />
      <el-button type="primary" @click="openCreate">新增</el-button>
      <el-button @click="openImport">批量导入</el-button>
      <el-button @click="exportList">导出</el-button>
    </div>

    <el-table :data="rows" v-loading="loading" size="small" empty-text="暂无数据">
      <el-table-column prop="target" label="地址" min-width="170">
        <template #default="{ row }">
          <span class="mono">{{ row.target }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="target_type" label="类型" width="80">
        <template #default="{ row }">
          <el-tag size="small" type="info">{{ row.target_type }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="属地" min-width="150">
        <template #default="{ row }">
          <span v-if="row.country || row.province">
            {{ [row.country, row.province].filter(Boolean).join(' · ') }}
          </span>
          <span v-else class="hint">—</span>
        </template>
      </el-table-column>
      <el-table-column prop="remark" label="备注" min-width="140">
        <template #default="{ row }">
          <span v-if="row.remark">{{ row.remark }}</span>
          <span v-else class="hint">—</span>
        </template>
      </el-table-column>
      <el-table-column prop="source" label="来源" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="row.source === 'manual' ? 'info' : 'warning'">
            {{ row.source === 'manual' ? '手动' : row.source }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="到期" width="160">
        <template #default="{ row }">
          <span v-if="row.expires_at">{{ fmt(row.expires_at) }}</span>
          <span v-else class="hint">永久</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="130" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-pagination
      v-model:current-page="page"
      v-model:page-size="size"
      :total="total"
      :page-sizes="[20, 50, 100]"
      layout="total, sizes, prev, pager, next"
      style="margin-top: 14px; justify-content: flex-end"
      @current-change="reload"
      @size-change="reload"
    />

    <el-dialog v-model="editVisible" :title="editing ? '编辑条目' : '新增条目'" width="480px">
      <el-form label-width="90px">
        <el-form-item label="地址">
          <el-input
            v-model="form.target"
            :disabled="editing"
            placeholder="1.2.3.4 或 1.2.3.0/24"
          />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.remark" placeholder="可选" />
        </el-form-item>
        <el-form-item label="有效期">
          <el-select v-model="form.expires" style="width: 100%">
            <el-option label="永久" :value="0" />
            <el-option label="1 小时" :value="3600" />
            <el-option label="1 天" :value="86400" />
            <el-option label="7 天" :value="604800" />
            <el-option label="30 天" :value="2592000" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="importVisible" title="批量导入" width="620px">
      <div class="hint" style="margin-bottom: 10px">
        每行一个地址，支持 <span class="mono">1.2.3.4</span>、
        <span class="mono">1.2.3.0/24</span>，可以追加备注：<span class="mono">1.2.3.4,机房备用</span>。
        以 # 开头的行会被忽略。
      </div>
      <el-input
        v-model="importText"
        type="textarea"
        :rows="10"
        placeholder="1.2.3.4&#10;1.2.3.0/24,办公网&#10;# 注释行"
      />
      <div v-if="importResult" class="alert-note" style="margin-top: 12px">
        可导入 {{ importResult.added }} 条，跳过 {{ importResult.skipped }} 条
        <div v-if="(importResult.invalid || []).length" style="margin-top: 6px">
          无法识别的行：{{ importResult.invalid.join('、') }}
        </div>
      </div>
      <template #footer>
        <el-button @click="importVisible = false">取消</el-button>
        <el-button @click="doImport(true)" :loading="importing">校验</el-button>
        <el-button type="primary" @click="doImport(false)" :loading="importing">确认导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import api from '@/api'

const kind = ref('white')
const rows = ref<any[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const size = ref(20)
const total = ref(0)

const editVisible = ref(false)
const editing = ref(false)
const saving = ref(false)
const form = reactive({ id: 0, target: '', remark: '', expires: 0 })

const importVisible = ref(false)
const importing = ref(false)
const importText = ref('')
const importResult = ref<any>(null)

function fmt(t: string) {
  return new Date(t).toLocaleString('zh-CN', { hour12: false })
}

async function reload() {
  loading.value = true
  try {
    const r: any = await api.listACL(kind.value, {
      keyword: keyword.value,
      page: page.value,
      size: size.value,
    })
    rows.value = r.items || []
    total.value = r.total || 0
  } finally {
    loading.value = false
  }
}

function onTabChange() {
  page.value = 1
  keyword.value = ''
  reload()
}

function openCreate() {
  editing.value = false
  Object.assign(form, { id: 0, target: '', remark: '', expires: 0 })
  editVisible.value = true
}

function openEdit(row: any) {
  editing.value = true
  Object.assign(form, {
    id: row.id,
    target: row.target,
    remark: row.remark || '',
    expires: 0,
  })
  editVisible.value = true
}

async function save() {
  if (!form.target && !editing.value) {
    ElMessage.warning('请填写地址')
    return
  }
  saving.value = true
  try {
    if (editing.value) {
      await api.updateACL(kind.value, form.id, {
        remark: form.remark,
        expires_in_sec: form.expires,
      })
    } else {
      await api.createACL(kind.value, {
        target: form.target,
        remark: form.remark,
        expires_in_sec: form.expires,
      })
    }
    ElMessage.success('已保存')
    editVisible.value = false
    reload()
  } finally {
    saving.value = false
  }
}

async function remove(row: any) {
  try {
    await ElMessageBox.confirm(`确定从${kind.value === 'white' ? '白' : '黑'}名单删除 ${row.target} 吗？`, '确认删除', {
      type: 'warning',
    })
  } catch {
    return
  }
  await api.deleteACL(kind.value, row.id)
  ElMessage.success('已删除')
  reload()
}

function openImport() {
  importText.value = ''
  importResult.value = null
  importVisible.value = true
}

async function doImport(dry: boolean) {
  if (!importText.value.trim()) {
    ElMessage.warning('请粘贴内容')
    return
  }
  importing.value = true
  try {
    const r: any = await api.importACL(kind.value, {
      content: importText.value,
      dry_run: dry,
    })
    importResult.value = r
    if (!dry) {
      ElMessage.success(`已导入 ${r.added} 条`)
      importVisible.value = false
      reload()
    }
  } finally {
    importing.value = false
  }
}

function exportList() {
  window.open(api.exportACLURL(kind.value), '_blank')
}

onMounted(reload)
</script>

<style scoped>
.panel {
  padding: 16px 18px;
}

.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
}

.spacer {
  flex: 1;
}
</style>
