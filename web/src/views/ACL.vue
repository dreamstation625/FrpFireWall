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
    >
      <template #title>黑名单地址会被立即拒绝登录，并同步写入内核防火墙。</template>
      <template #default>
        封禁范围按条目单独设置：<b>全端口</b>会把该地址访问本机的所有端口一起拒绝（含 SSH、
        面板），挡得彻底，但误伤时代价也大；<b>仅 frp 端口</b>只拒绝 frp 服务端口上的连接，
        影响面小，代价是对方仍能扫到本机其它端口；<b>自定义端口</b>只封指定的那几个端口。
        范围只决定内核层丢哪些端口上的包，不影响判定本身 —— 插件回调拿不到端口，
        自定义端口只用来精确控制内核封哪里。
      </template>
    </el-alert>

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
      <!-- 范围只对黑名单有意义，白名单不显示这一列 -->
      <el-table-column v-if="kind === 'black'" label="范围" width="118">
        <template #default="{ row }">
          <!-- 带上 ports 一起看：范围是 custom 却没有端口时后端会退化成全端口下发，
               提示语必须说同一件事，否则界面讲"只封这几个端口"、实际封了全部 -->
          <el-tooltip :content="scopeTip(row.scope, row.ports)" placement="top">
            <el-tag size="small" :type="scopeTagType(row.scope)">
              {{ scopeLabel(row.scope) }}
            </el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column v-if="kind === 'black'" label="封禁端口" min-width="130">
        <template #default="{ row }">
          <span v-if="row.scope === 'custom' && row.ports" class="mono">{{ row.ports }}</span>
          <span v-else class="hint">—</span>
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
        <el-form-item v-if="kind === 'black'" label="封禁范围">
          <el-radio-group v-model="form.scope">
            <el-radio-button
              v-for="o in SCOPE_OPTIONS"
              :key="o.value"
              :value="o.value"
            >
              {{ o.label }}
            </el-radio-button>
          </el-radio-group>
          <div class="hint" style="margin-top: 6px">{{ scopeFormHint(form.scope) }}</div>
        </el-form-item>
        <el-form-item v-if="kind === 'black' && form.scope === 'custom'" label="封禁端口">
          <el-input v-model="form.ports" placeholder="8080,9000-9100" />
          <div class="hint" style="margin-top: 6px">
            写单个端口（8080）或区间（9000-9100），多个用逗号分隔。
          </div>
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
      <div v-if="kind === 'black'" class="hint" style="margin-bottom: 10px">
        黑名单还可以在第二列写范围 <span class="mono">all</span> /
        <span class="mono">frp</span> / <span class="mono">custom:端口</span>：
        <span class="mono">1.2.3.4,frp,备注</span>、
        <span class="mono">1.2.3.4,custom:8080;9000-9100</span>。
        第二列只有恰好是这几种写法时才当作范围，否则整体按备注处理，所以旧文件可以直接导入。
        <br />
        注意端口列表在<strong>文件里要用分号</strong>分隔 —— 逗号是列分隔符，
        写逗号会把备注列切走；上面那个输入框是单独一个字段，用逗号即可。
      </div>
      <el-form v-if="kind === 'black'" label-width="90px" style="margin-bottom: 10px">
        <el-form-item label="默认范围">
          <el-radio-group v-model="importScope">
            <el-radio-button
              v-for="o in SCOPE_OPTIONS"
              :key="o.value"
              :value="o.value"
            >
              {{ o.label }}
            </el-radio-button>
          </el-radio-group>
          <div class="hint" style="margin-top: 6px">未写范围的行按此处理。</div>
        </el-form-item>
        <el-form-item v-if="importScope === 'custom'" label="默认端口">
          <el-input v-model="importPorts" placeholder="8080,9000-9100" />
          <div class="hint" style="margin-top: 6px">
            未写范围的行用这一份端口。某一行自己写了范围，端口就跟着那一行走。
          </div>
        </el-form-item>
      </el-form>
      <!-- 占位符里的换行必须用 \n 转义：写 &#10; 会被解析成真实换行，
           再当作 JS 字符串编译就报 "Unterminated string constant" -->
      <el-input
        v-model="importText"
        type="textarea"
        :rows="10"
        :placeholder="importPlaceholder"
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
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import api from '@/api'
import { SCOPE_OPTIONS, scopeFormHint, scopeLabel, scopeTagType, scopeTip } from '@/utils/scope'

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
const form = reactive({ id: 0, target: '', remark: '', expires: 0, scope: 'all', ports: '' })

const importVisible = ref(false)
const importing = ref(false)
const importText = ref('')
const importScope = ref('all')
const importPorts = ref('')
const importResult = ref<any>(null)

// 黑名单多给一行带范围的示例，白名单保持原样
const importPlaceholder = computed(() =>
  kind.value === 'black'
    ? '1.2.3.4,frp,扫描源\n1.2.3.0/24,办公网\n1.2.3.4,custom:8080;9000-9100,只封两个端口\n# 注释行'
    : '1.2.3.4\n1.2.3.0/24,办公网\n# 注释行'
)

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
  Object.assign(form, { id: 0, target: '', remark: '', expires: 0, scope: 'all', ports: '' })
  editVisible.value = true
}

function openEdit(row: any) {
  editing.value = true
  Object.assign(form, {
    id: row.id,
    target: row.target,
    remark: row.remark || '',
    expires: 0,
    // 老条目可能是空串，回显成全端口而不是留空，避免用户以为没设置过
    scope: row.scope === 'frp' || row.scope === 'custom' ? row.scope : 'all',
    ports: row.ports || '',
  })
  editVisible.value = true
}

async function save() {
  if (!form.target && !editing.value) {
    ElMessage.warning('请填写地址')
    return
  }
  // 自定义范围必须有端口：没有端口内核一条规则都生成不出来，而列表里它会显示成
  // 一条正常生效中的条目。后端也会拦，这里先拦一道是为了不白跑一趟。
  if (kind.value === 'black' && form.scope === 'custom' && !form.ports.trim()) {
    ElMessage.warning('自定义范围需要至少一个端口')
    return
  }
  // 非自定义范围一律把端口清成空串，而不是"不传"：库里残留一份不参与生效的端口，
  // 是"配置里写着、实际不生效"那类最难排查的问题。
  const ports = form.scope === 'custom' ? form.ports.trim() : ''
  saving.value = true
  try {
    // 编辑时总是带上 scope：form.scope 已用行内原值回填，等价于"不改动"。
    // 白名单的 scope 由后端忽略，这里不用特判。
    if (editing.value) {
      await api.updateACL(kind.value, form.id, {
        remark: form.remark,
        expires_in_sec: form.expires,
        scope: form.scope,
        ports,
      })
    } else {
      await api.createACL(kind.value, {
        target: form.target,
        remark: form.remark,
        expires_in_sec: form.expires,
        scope: form.scope,
        ports,
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
  importScope.value = 'all'
  importPorts.value = ''
  importResult.value = null
  importVisible.value = true
}

// 默认范围与行内写法共用一套语法，所以自定义范围要拼成 "custom:端口" 再传。
// 这里用逗号分隔端口：它是独立的请求字段，不受"逗号是列分隔符"那条约束，
// 后端两种分隔符都收。
function defaultScopeField() {
  if (importScope.value !== 'custom') return importScope.value
  return `custom:${importPorts.value.trim()}`
}

async function doImport(dry: boolean) {
  if (!importText.value.trim()) {
    ElMessage.warning('请粘贴内容')
    return
  }
  if (importScope.value === 'custom' && !importPorts.value.trim()) {
    ElMessage.warning('自定义范围需要至少一个端口')
    return
  }
  importing.value = true
  try {
    const r: any = await api.importACL(kind.value, {
      content: importText.value,
      dry_run: dry,
      scope: defaultScopeField(),
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
