<template>
  <div class="page-card panel" data-guide="acl-table">
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
      title="白名单地址不被封禁，但不会额外放行端口。"
    />
    <el-alert
      v-else
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 12px"
    >
      <template #title>黑名单地址会被立即拒绝登录，并写入内核防火墙。</template>
      <template #default>
        封禁范围：<b>全端口</b> / <b>仅 frp 端口</b> / <b>自定义端口</b>。
        范围只决定内核封哪些端口，不影响判定 —— 插件回调拿不到端口。
        <div style="margin-top: 6px">
          <b>地区条目</b>按属地匹配，命中即把该来源 IP 封进内核。
          地区条件不产生内核规则，没来访过的地址在内核里没有痕迹。
        </div>
      </template>
    </el-alert>

    <div class="toolbar">
      <el-input
        v-model="keyword"
        placeholder="搜索地址 / 备注 / 属地"
        clearable
        style="width: 260px"
        @keyup.enter="search"
      >
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-button @click="search">查询</el-button>
      <div class="spacer" />
      <el-button type="primary" @click="openCreate">新增</el-button>
      <el-button @click="openImport">批量导入</el-button>
      <el-button @click="exportList">导出</el-button>
    </div>

    <el-table
      :data="rows"
      v-loading="loading"
      size="small"
      border
      empty-text="暂无数据"
      :row-class-name="rowClass"
      @header-dragend="cw.onDragend"
    >
      <el-table-column prop="target" label="地址" v-bind="cw.col('地址', { minWidth: 170 })">
        <template #default="{ row }">
          <!-- 地区条目在响应里带 target_label（国家码已翻成中文名）。库里存的仍是
               国家码，所以 hover 时把原始匹配值露出来，排查时好对照。 -->
          <el-tooltip v-if="row.target_label" :content="`匹配值：${row.target}`" placement="top">
            <span>{{ row.target_label }}</span>
          </el-tooltip>
          <span v-else class="mono">{{ row.target }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="target_type" label="类型" v-bind="cw.col('类型', { width: 92 })">
        <template #default="{ row }">
          <el-tag size="small" :type="isGeoTarget(row.target_type) ? 'warning' : 'info'">
            {{ typeLabel(row.target_type) }}
          </el-tag>
        </template>
      </el-table-column>
      <!-- 启用/禁用直接在列表上切。停用的条目不参与判定，由它封掉的地址会被
           一并解禁（与删除同待遇），后端在响应里带回 released_bans。 -->
      <el-table-column label="启用/禁用" v-bind="cw.col('启用/禁用', { width: 90 })" align="center">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" size="small" @change="toggleEnabled(row)" />
        </template>
      </el-table-column>
      <!-- 范围只对黑名单有意义，白名单不显示这一列 -->
      <el-table-column v-if="kind === 'black'" label="范围" v-bind="cw.col('范围', { width: 118 })">
        <template #default="{ row }">
          <!-- 地区条目没有"范围"这个字段的含义：它不产生内核规则，命中之后
               封的是那个具体 IP（全端口）。列里显示"全端口"会让人以为有一条
               按全端口生效中的内核规则，而实际上它挡不住任何没来访过的地址。 -->
          <el-tooltip v-if="isGeoTarget(row.target_type)" content="命中后把该来源全端口封进内核；地区条件本身不产生内核规则" placement="top">
            <el-tag size="small" type="warning">命中即封</el-tag>
          </el-tooltip>
          <!-- 带上 ports 一起看：范围是 custom 却没有端口时后端会退化成全端口下发，
               提示语必须说同一件事，否则界面讲"只封这几个端口"、实际封了全部 -->
          <el-tooltip v-else :content="scopeTip(row.scope, row.ports)" placement="top">
            <el-tag size="small" :type="scopeTagType(row.scope)">
              {{ scopeLabel(row.scope) }}
            </el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column
        v-if="kind === 'black'"
        label="封禁端口"
        v-bind="cw.col('封禁端口', { minWidth: 130 })"
      >
        <template #default="{ row }">
          <span v-if="row.scope === 'custom' && row.ports" class="mono">{{ row.ports }}</span>
          <span v-else class="hint">—</span>
        </template>
      </el-table-column>
      <el-table-column label="属地" v-bind="cw.col('属地', { minWidth: 150 })">
        <template #default="{ row }">
          <span v-if="row.country || row.province">
            {{ [row.country, row.province].filter(Boolean).join(' · ') }}
          </span>
          <span v-else class="hint">—</span>
        </template>
      </el-table-column>
      <el-table-column prop="remark" label="备注" v-bind="cw.col('备注', { minWidth: 140 })">
        <template #default="{ row }">
          <span v-if="row.remark">{{ row.remark }}</span>
          <span v-else class="hint">—</span>
        </template>
      </el-table-column>
      <el-table-column prop="source" label="来源" v-bind="cw.col('来源', { width: 80 })">
        <template #default="{ row }">
          <el-tag size="small" :type="row.source === 'manual' ? 'info' : 'warning'">
            {{ row.source === 'manual' ? '手动' : row.source }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="到期" v-bind="cw.col('到期', { width: 180 })">
        <template #default="{ row }">
          <template v-if="row.expires_at">
            <span :class="{ 'text-expired': isExpired(row.expires_at) }">{{ fmt(row.expires_at) }}</span>
            <el-tag v-if="isExpired(row.expires_at)" size="small" type="danger" style="margin-left: 6px">
              已过期
            </el-tag>
          </template>
          <span v-else class="hint">永久</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" v-bind="cw.col('操作', { width: 130 })" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <TablePager v-model:page="page" v-model:size="size" :total="total" @change="reload" />

    <el-dialog v-model="editVisible" :title="editing ? '编辑条目' : '新增条目'" width="520px">
      <el-form label-width="90px">
        <el-form-item label="目标类型">
          <el-radio-group v-model="form.targetType" :disabled="editing">
            <el-radio-button v-for="o in TARGET_TYPE_OPTIONS" :key="o.value" :value="o.value">
              {{ o.label }}
            </el-radio-button>
          </el-radio-group>
          <div v-if="editing" class="hint" style="margin-top: 6px">
            保存后类型与匹配值不能改。
          </div>
        </el-form-item>

        <el-form-item :label="targetLabel">
          <!-- IP / CIDR -->
          <el-input
            v-if="!isGeo"
            v-model="form.target"
            :disabled="editing"
            placeholder="1.2.3.4 或 1.2.3.0/24"
          />

          <!-- 国家 / 地区：候选表来自服务端，和属地库返回的是同一套码。
               同时允许直接输入 —— 候选表是刻意只收常见来源地的，未收录的国家
               若不让人手输，就只能靠导入文件才能配得出来。 -->
          <el-select
            v-else-if="form.targetType === 'geo_country'"
            v-model="geoValues"
            multiple
            filterable
            allow-create
            default-first-option
            clearable
            collapse-tags
            collapse-tags-tooltip
            :max-collapse-tags="8"
            :disabled="editing"
            placeholder="选择或直接输入两位国家码（如 CN、CU）"
            style="width: 100%"
          >
            <el-option
              v-for="c in countries"
              :key="c.code"
              :label="`${c.name}（${c.code}）`"
              :value="c.code"
            >
              <span>{{ c.name }}</span>
              <span class="opt-code">{{ c.code }}</span>
              <el-tag v-if="c.common" size="small" type="info" style="margin-left: 6px">常见</el-tag>
            </el-option>
          </el-select>

          <!-- 省份：候选集封闭（34 个省级行政区），所以用下拉而不是自由输入 -->
          <el-select
            v-else-if="form.targetType === 'geo_province'"
            v-model="geoValues"
            multiple
            filterable
            clearable
            collapse-tags
            collapse-tags-tooltip
            :max-collapse-tags="8"
            :disabled="editing"
            placeholder="选择省份（可多选）"
            style="width: 100%"
          >
            <el-option v-for="p in provinces" :key="p.name" :label="p.full" :value="p.name" />
          </el-select>

          <!-- 城市：候选集开放，只能自由输入 -->
          <el-select
            v-else
            v-model="geoValues"
            multiple
            filterable
            allow-create
            default-first-option
            clearable
            collapse-tags
            collapse-tags-tooltip
            :max-collapse-tags="8"
            :disabled="editing"
            placeholder="输入城市名后回车（可多个），例如 深圳"
            style="width: 100%"
          >
            <el-option v-for="c in geoValues" :key="c" :label="c" :value="c" />
          </el-select>

          <div class="hint" style="margin-top: 6px">{{ targetHint }}</div>
        </el-form-item>

        <el-form-item label="备注">
          <el-input v-model="form.remark" placeholder="可选" />
        </el-form-item>
        <!-- 地区条目恒为全端口：它命中之后的落地方式是"把这个具体 IP 全端口封掉"，
             内核里没有"地区"这个对象，也就不存在能限定到某几个端口的规则。
             所以这里整块隐藏，而不是显示一个改不动的禁用框。 -->
        <el-form-item v-if="kind === 'black' && !isGeo" label="封禁范围">
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
        <el-form-item v-if="kind === 'black' && !isGeo && form.scope === 'custom'" label="封禁端口">
          <el-input v-model="form.ports" placeholder="8080,9000-9100" />
          <div class="hint" style="margin-top: 6px">
            写单个端口（8080）或区间（9000-9100），多个用逗号分隔。
          </div>
        </el-form-item>
        <el-form-item label="有效期">
          <el-select
            v-model="form.expires"
            style="width: 100%"
            clearable
            :placeholder="editing ? '保持原有效期' : ''"
          >
            <el-option v-for="o in EXPIRE_OPTIONS" :key="o.value" :label="o.label" :value="o.value" />
          </el-select>
          <div class="hint" style="margin-top: 6px">
            <template v-if="editing">不选则保持原有效期；选档位后从现在重新计时。</template>
            <template v-if="isGeo">
              地区条目命中后按有效期封禁：还有多久到期就封多久，永久条目封永久。
            </template>
          </div>
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
        <br />
        地区条目在目标前加类型前缀：<span class="mono">country:CN</span>、
        <span class="mono">province:广东</span>、
        <span class="mono">city:深圳</span>，多个值用<strong>分号</strong>分隔
        （<span class="mono">province:广东;福建</span>）。不加前缀的一律按地址解析。
      </div>
      <div v-if="kind === 'black'" class="hint" style="margin-bottom: 10px">
        第二列可写范围 <span class="mono">all</span> /
        <span class="mono">frp</span> / <span class="mono">custom:端口</span>：
        <span class="mono">1.2.3.4,frp</span>、
        <span class="mono">1.2.3.4,custom:8080;9000-9100</span>。
        不是这些写法时整段按备注，旧文件可直接导入。
        端口在<strong>文件里用分号</strong>分隔（逗号是列分隔符）；上面输入框是独立字段，用逗号。
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
          <div class="hint" style="margin-top: 6px">
            未写范围的行按此处理；地区条目（<span class="mono">country:</span> 等前缀开头）恒为全端口。
          </div>
        </el-form-item>
        <el-form-item v-if="importScope === 'custom'" label="默认端口">
          <el-input v-model="importPorts" placeholder="8080,9000-9100" />
          <div class="hint" style="margin-top: 6px">未写范围的行用这一份端口。</div>
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
import TablePager from '@/components/TablePager.vue'
import { SCOPE_OPTIONS, scopeFormHint, scopeLabel, scopeTagType, scopeTip } from '@/utils/scope'
import { useColumnWidths } from '@/utils/table'

const cw = useColumnWidths('acl')

// 目标类型。前四个是地址（后端按内容推断），后三个是地区。
// 值直接就是后端的 target_type 常量，不做二次映射 —— 多一层映射就多一处
// 可能对不上的地方，而"界面写着城市、存进去是国家"这种错很难看出来。
const TARGET_TYPE_OPTIONS = [
  { label: 'IP / 网段', value: 'ip' },
  { label: '国家 / 地区', value: 'geo_country' },
  { label: '省份', value: 'geo_province' },
  { label: '城市', value: 'geo_city' },
]

// 列表里的类型标签。地区类型要用中文，否则表格里是 geo_country 这种内部常量，
// 用户既读不出它和「国家/地区」是一回事，也没法核对。
const TYPE_LABEL: Record<string, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  cidr4: 'IPv4 网段',
  cidr6: 'IPv6 网段',
  geo_country: '国家/地区',
  geo_province: '省份',
  geo_city: '城市',
}

const isGeoTarget = (t?: string) => !!t && t.startsWith('geo_')
const typeLabel = (t?: string) => (t ? TYPE_LABEL[t] || t : '')

// 列表里一行"地址"该显示什么。地区条目用后端给的中文名（target_label），
// 地址条目就用原值。
//
// 换算放在后端而不是这里：国家码到中文名的表在 geoip 包里，同一份表还兼着
// 搜索时的中文名反查（见 aclSearchTerms）。前端抄一份的话，两边迟早对不上 ——
// 表现成"列表写着中国香港，搜中国香港却搜不到"。
function displayTarget(row: any) {
  return row.target_label || row.target
}

const kind = ref('white')
const rows = ref<any[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const size = ref(20)
const total = ref(0)

// 有效期的预设档。值就是"从现在起多少秒"，后端按 expires_in_sec 收。
//
// 地区条目上这个字段还有第二层含义：它同时是**命中之后封多久**（见后端
// banStepsForEntry）。地址条目是常驻内核规则，条目在就封着；地区条目没有
// 内核对象可依赖，所以"封到条目到期为止"要显式落成封禁时长。
const EXPIRE_OPTIONS = [
  { label: '永久', value: 0 },
  { label: '1 小时', value: 3600 },
  { label: '1 天', value: 86400 },
  { label: '7 天', value: 604800 },
  { label: '30 天', value: 2592000 },
]

// 条目是否已过期（到期时刻已经过去）。
const isExpired = (iso?: string | null) => !!iso && new Date(iso).getTime() <= Date.now()

const editVisible = ref(false)
const editing = ref(false)
const saving = ref(false)
const form = reactive({
  id: 0,
  target: '',
  targetType: 'ip',
  remark: '',
  // null = 不改有效期（编辑时下拉留空、提交时不发这个字段）。
  // 数字 = 从现在起多少秒，0 是永久。
  expires: null as number | null,
  scope: 'all',
  ports: '',
})
// 地区条目的多值单独存一份数组：多选组件的 v-model 必须是数组，
// 而入库形态是逗号分隔的一串。打开弹窗时拆开、保存时拼回去，只在这两处转换。
const geoValues = ref<string[]>([])

const countries = ref<any[]>([])
const provinces = ref<any[]>([])

const isGeo = computed(() => isGeoTarget(form.targetType))

const targetLabel = computed(() => {
  if (form.targetType === 'geo_country') return '国家 / 地区'
  if (form.targetType === 'geo_province') return '省份'
  if (form.targetType === 'geo_city') return '城市'
  return '地址'
})

const targetHint = computed(() => {
  switch (form.targetType) {
    case 'geo_country':
      return '命中任一所选地区即拦截。下拉只收常见来源地，其他直接输入两位国家码（如 CU）。'
    case 'geo_province':
      return '与属地库一致（不带「省 / 自治区」后缀）。'
    case 'geo_city':
      return '写错不报错、只是不命中。「深圳」「深圳市」均可。'
    default:
      return '单个 IP（1.2.3.4）或网段（1.2.3.0/24）。'
  }
})

const importVisible = ref(false)
const importing = ref(false)
const importText = ref('')
const importScope = ref('all')
const importPorts = ref('')
const importResult = ref<any>(null)

// 黑名单多给一行带范围的示例，白名单保持原样
const importPlaceholder = computed(() =>
  kind.value === 'black'
    ? '1.2.3.4,frp,扫描源\n1.2.3.0/24,办公网\ncountry:CN,扫描源\nprovince:广东;福建\n1.2.3.4,custom:8080;9000-9100,只封两个端口\n# 注释行'
    : '1.2.3.4\n1.2.3.0/24,办公网\ncountry:CN\n# 注释行'
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

// 查询条件变了要回到第 1 页：停在第 5 页改关键字，新结果很可能不足 5 页，
// 用户看到的是一张空表，会以为"没搜到"。
function search() {
  page.value = 1
  reload()
}

// 逗号 / 分号 / 中文标点 / 空白都当分隔符：入库形态是逗号，但手工改过的库、
// 从别处粘来的文本都可能带别的写法。地名里不会出现这些字符，多认几个不会误伤。
const splitList = (s?: string) =>
  String(s ?? '')
    .split(/[,，;；\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)

function openCreate() {
  editing.value = false
  Object.assign(form, {
    id: 0,
    target: '',
    targetType: 'ip',
    remark: '',
    expires: 0,
    scope: 'all',
    ports: '',
  })
  geoValues.value = []
  editVisible.value = true
}

function openEdit(row: any) {
  editing.value = true
  Object.assign(form, {
    id: row.id,
    target: row.target,
    // 老行存的是 ipv4 / cidr4 这类具体类型，回显到选项里都归到「IP / 网段」
    // 那一档 —— 选项里没有 ipv4 这一项，直接塞进去会让整个单选组一个都不选中。
    targetType: isGeoTarget(row.target_type) ? row.target_type : 'ip',
    remark: row.remark || '',
    // 编辑态默认留空 = 不改有效期（提交时不发这个字段）。展示剩余秒数的老做法
    // 已去掉：那会多出一条与预设档撞名的选项，用户分不清选哪个。
    expires: row.expires_at ? null : 0,
    // 老条目可能是空串，回显成全端口而不是留空，避免用户以为没设置过
    scope: row.scope === 'frp' || row.scope === 'custom' ? row.scope : 'all',
    ports: row.ports || '',
  })
  geoValues.value = isGeoTarget(row.target_type) ? splitList(row.target) : []
  editVisible.value = true
}

async function save() {
  if (isGeo.value) {
    // 地区条目的"值"在多选组件里，不是 form.target。这里必须单独判，
    // 否则空选也能提交，后端报一句"国家/地区不能为空"，用户还得找是哪个框。
    if (!geoValues.value.length) {
      ElMessage.warning(`请至少填一个${targetLabel.value}`)
      return
    }
  } else if (!form.target && !editing.value) {
    ElMessage.warning('请填写地址')
    return
  }
  // 自定义范围必须有端口：没有端口内核一条规则都生成不出来，而列表里它会显示成
  // 一条正常生效中的条目。后端也会拦，这里先拦一道是为了不白跑一趟。
  if (kind.value === 'black' && !isGeo.value && form.scope === 'custom' && !form.ports.trim()) {
    ElMessage.warning('自定义范围需要至少一个端口')
    return
  }
  // 非自定义范围一律把端口清成空串，而不是"不传"：库里残留一份不参与生效的端口，
  // 是"配置里写着、实际不生效"那类最难排查的问题。
  // 地区条目本身恒为全端口，端口也一并清空（后端同样会摆正）。
  const ports = !isGeo.value && form.scope === 'custom' ? form.ports.trim() : ''
  // 地区值拼成入库形态（逗号分隔）；地址条目的值就是 form.target。
  const target = isGeo.value ? geoValues.value.join(',') : form.target
  const targetType = isGeo.value ? form.targetType : ''
  saving.value = true
  try {
    // 编辑时总是带上 scope：form.scope 已用行内原值回填，等价于"不改动"。
    // 白名单的 scope 由后端忽略，这里不用特判。
    // 类型与匹配值不可改，所以更新请求里不带 target / target_type。
    if (editing.value) {
      const body: Record<string, unknown> = {
        remark: form.remark,
        scope: form.scope,
        ports,
      }
      // KEEP_EXPIRES 已删除：编辑态 expires 为 null 表示不改，整个字段不发出去
      //（后端把"没传"理解成"不改动"）。发 0 会被后端理解成"改成永久"。
      if (form.expires !== null) body.expires_in_sec = form.expires
      await api.updateACL(kind.value, form.id, body)
    } else {
      await api.createACL(kind.value, {
        target,
        target_type: targetType,
        remark: form.remark,
        expires_in_sec: form.expires ?? 0,
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

// 停用的行整行压暗：不参与判定的事实要在列表上一眼可见，
// 否则"名单里有它却没生效"只能靠猜。
function rowClass({ row }: { row: any }) {
  return row.enabled ? '' : 'row-disabled'
}

// 列表上的启用开关。失败时把开关翻回去，别让界面停在没保存成功的状态。
async function toggleEnabled(row: any) {
  const want = row.enabled
  try {
    const r: any = await api.updateACL(kind.value, row.id, { enabled: want })
    const n = r?.released_bans ?? 0
    if (!want && n > 0) {
      ElMessage.success(`已停用，并解禁了 ${n} 条由它产生的封禁`)
    }
  } catch {
    row.enabled = !want
    reload()
  }
}

async function remove(row: any) {
  try {
    await ElMessageBox.confirm(`确定从${kind.value === 'white' ? '白' : '黑'}名单删除 ${displayTarget(row)} 吗？`, '确认删除', {
      type: 'warning',
    })
  } catch {
    return
  }
  const r: any = await api.deleteACL(kind.value, row.id)
  // 删条目会连带解禁"由这条条目封掉"的地址（否则删了名单，被它封的地址还是
  // 进不来，而界面上已经看不到那条名单了）。这里必须把件数报出来 ——
  // 静默解禁几个 IP 是那种"事后完全查不出发生过什么"的操作。
  const n = r?.released_bans ?? 0
  ElMessage.success(n > 0 ? `已删除，并解禁了 ${n} 条由它产生的封禁` : '已删除')
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

async function exportList() {
  try { await api.exportACL(kind.value) } catch { /* 请求层已提示下载错误 */ }
}

// 国家与省份候选表来自服务端：这两个值必须和属地库返回的是同一套写法，
// 前端自己抄一份就等于把这份约定抄成了两份，早晚有一份会过时。
async function loadGeoOptions() {
  try {
    const [c, p]: any[] = await Promise.all([api.geoCountries(), api.geoProvinces()])
    countries.value = c?.countries || []
    provinces.value = p?.provinces || []
  } catch {
    // 候选表拉不到不该让整个页面打不开：地址条目完全用不到它，
    // 地区条目的下拉会空着，但用户仍能通过批量导入把条目写进去。
  }
}

onMounted(() => {
  reload()
  loadGeoOptions()
})
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

.opt-code {
  float: right;
  color: #8a919f;
  font-size: 12px;
}

/* 已经到期的时刻压暗一档：与右侧的「已过期」标签一起表示这条当前不生效。 */
.text-expired {
  color: var(--el-text-color-placeholder);
}

/* 停用条目整行压暗。 */
:deep(.row-disabled) {
  opacity: 0.55;
}
</style>
