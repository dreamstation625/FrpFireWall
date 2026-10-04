<template>
  <div v-loading="loading">
    <div class="page-card panel" style="margin-bottom: 16px">
      <div class="panel-head">
        <span class="section-title">细分规则</span>
        <div>
          <el-button size="small" type="primary" plain @click="addRule">新增规则</el-button>
        </div>
      </div>

      <div class="hint" style="margin-bottom: 12px">
        从上到下按顺序匹配，<strong>第一条命中的规则取代全局规则</strong> —— 窗口、阈值、阶梯、限速全部换成这条规则的。
        一条都没命中才走下面的全局规则。地域封禁名单不受影响，它始终先生效。
      </div>

      <div v-if="guardProblems.length" class="alert-danger" style="margin-bottom: 12px">
        <div>以下规则没能生效，请检查：</div>
        <div v-for="(p, i) in guardProblems" :key="i">· {{ p }}</div>
      </div>

      <el-table :data="pagedRules" size="small" border @header-dragend="cw.onDragend">
        <el-table-column label="顺序" v-bind="cw.col('顺序', { width: 60 })" align="center">
          <template #default="{ $index }">
            <span class="mono">{{ ruleIndex($index) + 1 }}</span>
          </template>
        </el-table-column>

        <el-table-column label="启用" v-bind="cw.col('启用', { width: 66 })" align="center">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" size="small" />
          </template>
        </el-table-column>

        <el-table-column
          label="规则名"
          v-bind="cw.col('规则名', { minWidth: 150 })"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            <span :class="{ 'rule-off': !row.enabled }">{{ row.name }}</span>
            <div v-if="row.remark" class="hint">{{ row.remark }}</div>
          </template>
        </el-table-column>

        <el-table-column label="落点" v-bind="cw.col('落点', { width: 88 })" align="center">
          <template #default="{ row }">
            <el-tooltip :content="LAYER_TIP[rowLayer(row)]" placement="top">
              <el-tag size="small" :type="LAYER_TAG_TYPE[rowLayer(row)]">
                {{ LAYER_LABEL[rowLayer(row)] }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>

        <el-table-column label="匹配条件" v-bind="cw.col('匹配条件', { minWidth: 210 })">
          <template #default="{ row }">
            <div v-for="(p, i) in conditionParts(row, countryLabel)" :key="i">{{ p }}</div>
          </template>
        </el-table-column>

        <el-table-column label="动作" v-bind="cw.col('动作', { minWidth: 190 })">
          <template #default="{ row }">
            <div v-for="(p, i) in actionParts(row)" :key="i">{{ p }}</div>
          </template>
        </el-table-column>

        <el-table-column label="操作" v-bind="cw.col('操作', { width: 200 })" align="center">
          <template #default="{ $index }">
            <el-button
              size="small"
              link
              type="primary"
              :disabled="ruleIndex($index) === 0"
              @click="moveRule(ruleIndex($index), -1)"
            >
              上移
            </el-button>
            <el-button
              size="small"
              link
              type="primary"
              :disabled="ruleIndex($index) === rules.length - 1"
              @click="moveRule(ruleIndex($index), 1)"
            >
              下移
            </el-button>
            <el-button size="small" link type="primary" @click="editRule(ruleIndex($index))">
              编辑
            </el-button>
            <el-button size="small" link type="danger" @click="removeRule(ruleIndex($index))">
              删除
            </el-button>
          </template>
        </el-table-column>

        <template #empty>
          <span class="hint">还没有细分规则，所有流量都按下面的全局规则处理。</span>
        </template>
      </el-table>

      <TablePager v-model:page="rPage" v-model:size="rSize" :total="rules.length" />

      <div class="hint" style="margin-top: 10px">
        规则的先后顺序就是匹配顺序。改动后需要点右上角「保存并生效」—— 策略和规则在同一次请求里一起保存。
      </div>
    </div>

    <div class="page-card panel">
      <div class="panel-head">
        <span class="section-title">全局规则（细分规则没命中时生效）</span>
        <div>
          <el-button size="small" @click="load">重新加载</el-button>
          <el-button size="small" @click="resetToSaved">放弃修改</el-button>
          <el-button type="primary" size="small" :loading="saving" @click="save">保存并生效</el-button>
        </div>
      </div>

      <div v-if="dirty" class="alert-note" style="margin-bottom: 14px">
        有未保存的修改，保存后立即生效。
      </div>

      <el-form label-width="150px" label-position="right">
        <el-divider content-position="left">滑动窗口</el-divider>

        <el-form-item label="统计窗口">
          <el-input-number v-model="form.window_seconds" :min="1" :max="86400" :step="10" />
          <span class="unit">秒</span>
          <div class="hint">
            窗口内登录尝试达到阈值即封禁，按来源 IP 独立计数。
          </div>
        </el-form-item>

        <el-form-item label="触发阈值">
          <el-input-number v-model="form.threshold" :min="1" :max="100000" :step="1" />
          <span class="unit">次</span>
          <div class="hint">
            建议 10 ~ 30 次。frps 在鉴权<strong>之前</strong>回调插件，这里统计的是登录尝试次数，
            正常的 frpc 重连也会计入，阈值别设太低。
          </div>
        </el-form-item>

        <el-divider content-position="left">阶梯封禁时长</el-divider>

        <el-form-item label="封禁阶梯">
          <BanStepsEditor v-model="steps" />
        </el-form-item>

        <el-form-item label="升级统计窗口">
          <el-input-number v-model="form.escalate_window_hours" :min="1" :max="8760" />
          <span class="unit">小时</span>
          <div class="hint">距上次封禁在这个时间内再次触发，才会升级到下一级阶梯。</div>
        </el-form-item>

        <el-divider content-position="left">封禁行为</el-divider>

        <el-form-item label="封禁粒度">
          <el-radio-group v-model="form.ban_granularity">
            <el-radio value="ip">精确 IP</el-radio>
            <el-radio value="cidr24">整段 /24</el-radio>
          </el-radio-group>
          <div class="hint">
            /24 能整段封掉扫描源，但会误伤同网段正常用户（例如整栋楼的 NAT 出口）。默认精确 IP。
            频次统计始终按单个来源 IP 计，不受此项影响。
          </div>
        </el-form-item>

        <el-form-item label="插件异常策略">
          <el-radio-group v-model="form.fail_mode">
            <el-radio value="open">放行（fail-open）</el-radio>
            <el-radio value="close">拒绝（fail-close）</el-radio>
          </el-radio-group>
          <div class="hint">
            插件超时或 panic 时的处理方式。默认放行：宁可漏拦，也不能因为插件故障让整条隧道全断。
            只有在内网、且明确接受「插件故障 = 全部 frpc 连不上」时才选拒绝。
          </div>
        </el-form-item>

        <el-form-item label="自动封禁">
          <el-switch v-model="form.auto_ban_enabled" active-text="开启" inactive-text="关闭" inline-prompt />
          <div class="hint">关闭后仍然记录事件和统计，只是不再自动产生封禁记录。</div>
        </el-form-item>

        <el-form-item label="观察模式">
          <el-switch v-model="form.observe_only" active-text="开启" inactive-text="关闭" inline-prompt />
          <div v-if="form.observe_only" class="alert-note" style="margin-top: 6px; width: 100%">
            不会真正封禁，只在事件日志里记录「本该被封」。建议上线头几天开着校准阈值，
            确认误封率可接受后再关。
          </div>
          <div v-else class="hint">开启后只记录不封禁，用于校准阈值。</div>
        </el-form-item>

        <el-divider content-position="left">地域封禁（GeoIP）</el-divider>

        <el-form-item label="启用地域封禁">
          <el-switch
            v-model="form.geoip_block_enabled"
            active-text="开启"
            inactive-text="关闭"
            inline-prompt
          />
          <el-tag v-if="!countryAvailable" size="small" type="warning" style="margin-left: 10px">
            属地库未加载，此项不会生效
          </el-tag>
        </el-form-item>

        <template v-if="form.geoip_block_enabled">
          <el-form-item label="地域模式">
            <el-radio-group v-model="form.geoip_mode">
              <el-radio value="blacklist">黑名单：拒绝列表内国家</el-radio>
              <el-radio value="whitelist">白名单：只允许列表内国家</el-radio>
            </el-radio-group>
            <div v-if="form.geoip_mode === 'whitelist'" class="alert-danger" style="margin-top: 6px; width: 100%">
              风险高：不在列表内、以及未能匹配到属地的 IP 都会连不上。
              务必先把运维出口、监控节点、CDN 回源段加进白名单，再切这个模式。
            </div>
          </el-form-item>

          <el-form-item label="国家 / 地区">
            <el-select
              v-model="selectedCountries"
              multiple
              filterable
              clearable
              collapse-tags
              collapse-tags-tooltip
              :max-collapse-tags="8"
              placeholder="选择国家或地区"
              style="width: 100%"
            >
              <el-option
                v-for="c in countriesGrouped"
                :key="c.code"
                :label="`${c.name}（${c.code}）`"
                :value="c.code"
              >
                <span>{{ c.name }}</span>
                <span class="opt-code">{{ c.code }}</span>
                <el-tag v-if="c.common" size="small" type="info" style="margin-left: 6px">常见</el-tag>
              </el-option>
            </el-select>
            <div class="hint">已选 {{ selectedCountries.length }} 项。</div>
          </el-form-item>
        </template>

        <el-divider content-position="left">连接速率限制</el-divider>

        <el-form-item label="启用速率限制">
          <el-switch v-model="form.rate_limit_enabled" active-text="开启" inactive-text="关闭" inline-prompt />
          <el-tag v-if="!rateSupported" size="small" type="warning" style="margin-left: 10px">
            当前防火墙后端不支持，规则不会下发
          </el-tag>
        </el-form-item>

        <template v-if="form.rate_limit_enabled">
          <el-form-item label="单 IP 速率">
            <el-input-number v-model="form.rate_limit_per_sec" :min="1" :max="100000" />
            <span class="unit">包 / 秒</span>
          </el-form-item>
          <el-form-item label="突发容量">
            <el-input-number v-model="form.rate_limit_burst" :min="1" :max="100000" />
            <span class="unit">包</span>
            <div class="hint">
              允许短暂突发不被丢弃，一般设为速率的 2 倍。由系统防火墙在网络层执行，
              只作用于受保护的 frp 端口。它是<strong>兜底</strong>：上面细分规则里的限速会先匹配、先生效。
            </div>
          </el-form-item>
        </template>
      </el-form>
    </div>

    <RateRuleDialog
      v-model="ruleDialogVisible"
      :rule="editingRule"
      :countries="countries"
      :provinces="provinces"
      @saved="onRuleSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'
import BanStepsEditor from '@/components/BanStepsEditor.vue'
import RateRuleDialog from '@/components/RateRuleDialog.vue'
import TablePager from '@/components/TablePager.vue'
import { type Step, parseStepsOrDefault, stepsToCSV, validateSteps } from '@/utils/duration'
import {
  LAYER_LABEL,
  LAYER_TAG_TYPE,
  LAYER_TIP,
  type Layer,
  type RateRule,
  actionParts,
  conditionParts,
  layerOf,
} from '@/utils/raterule'
import { useColumnWidths } from '@/utils/table'

const cw = useColumnWidths('policy-rules')

const loading = ref(false)
const saving = ref(false)
const dirty = ref(false)
const saved = ref<any>(null)

const steps = ref<Step[]>(parseStepsOrDefault(''))

const form = reactive({
  window_seconds: 60,
  threshold: 10,
  escalate_window_hours: 24,
  ban_granularity: 'ip',
  fail_mode: 'open',
  auto_ban_enabled: true,
  observe_only: false,
  geoip_block_enabled: false,
  geoip_mode: 'blacklist',
  rate_limit_enabled: false,
  rate_limit_per_sec: 20,
  rate_limit_burst: 40,
})

const selectedCountries = ref<string[]>([])
const countries = ref<any[]>([])
const provinces = ref<any[]>([])
const countryAvailable = ref(false)
const capability = ref<any>({})

// ---- 细分规则 ----

const rules = ref<RateRule[]>([])

// 规则表分页。规则本身仍以全量 rules 为准 —— 保存、脏标记比对、上移下移全都
// 作用于它，分页只决定「显示哪一段」。所以模板里所有按位置操作的按钮都必须
// 先把页内序号换成全表序号（ruleIndex）；直接拿 $index 去改会改到别的规则上，
// 而且改错时界面看起来完全正常。
const rPage = ref(1)
const rSize = ref(20)
const pagedRules = computed(() =>
  rules.value.slice((rPage.value - 1) * rSize.value, rPage.value * rSize.value)
)

/** 页内序号 → 全表序号。 */
function ruleIndex(i: number) {
  return (rPage.value - 1) * rSize.value + i
}

/**
 * 翻到某条规则所在的页。
 *
 * 上移下移跨页时必须调用：规则被移到上一页后，当前页的切片里就没有它了，
 * 用户看到的是「点了上移，这条规则凭空消失」，会以为被删掉了。
 */
function gotoRule(i: number) {
  rPage.value = Math.floor(i / rSize.value) + 1
}

/** 删完之后当前页可能空了，回退到最后一页，别停在一张空表上。 */
function clampRulePage() {
  const last = Math.max(1, Math.ceil(rules.value.length / rSize.value))
  if (rPage.value > last) rPage.value = last
}
const guardProblems = ref<string[]>([])
const ruleDialogVisible = ref(false)
const editingIndex = ref(-1)
const editingRule = ref<RateRule | null>(null)

const rateSupported = computed(() => capability.value?.rate_limit !== false)

const countriesGrouped = computed(() => countries.value)

const countryLabel = (code: string) => {
  const c = countries.value.find((x) => x.code === code)
  return c?.name || code
}

// 落点优先用后端算的那份（保存过的规则都带），没保存过的新行本地推一遍。
// 两边推的是同一条规则（有端口落内核），所以不会出现两种答案。
const rowLayer = (row: RateRule): Layer => row.layer || layerOf(row)

/**
 * 提交给后端的字段白名单。
 *
 * 显式列出而不是整个对象丢过去：id / layer 是服务端算的，
 * 顺便传回去会让人以为它们是可以由客户端决定的（而且后端确实会忽略 id）。
 */
function rulePayload(r: RateRule) {
  return {
    name: r.name,
    enabled: r.enabled,
    countries: r.countries,
    provinces: r.provinces,
    cidrs: r.cidrs,
    ports: r.ports,
    per_sec: r.per_sec,
    burst: r.burst,
    window_seconds: r.window_seconds,
    threshold: r.threshold,
    ban_durations: r.ban_durations,
    remark: r.remark,
  }
}

function addRule() {
  editingIndex.value = -1
  editingRule.value = null
  ruleDialogVisible.value = true
}

function editRule(i: number) {
  editingIndex.value = i
  editingRule.value = { ...rules.value[i] }
  ruleDialogVisible.value = true
}

function onRuleSaved(r: RateRule) {
  if (editingIndex.value >= 0) {
    rules.value.splice(editingIndex.value, 1, r)
  } else {
    rules.value.push(r)
    // 新增的规则追加在末尾，跟过去 —— 否则在当前页看不到它，像是没加上
    gotoRule(rules.value.length - 1)
  }
}

async function removeRule(i: number) {
  const r = rules.value[i]
  try {
    await ElMessageBox.confirm(`确定删除规则「${r.name}」吗？`, '确认删除', { type: 'warning' })
  } catch {
    return
  }
  rules.value.splice(i, 1)
  clampRulePage()
}

function moveRule(i: number, dir: number) {
  const j = i + dir
  if (j < 0 || j >= rules.value.length) return
  const arr = rules.value
  ;[arr[i], arr[j]] = [arr[j], arr[i]]
  gotoRule(j)
}

// ---- 脏标记 ----

let baseline = ''

// 任何字段变动都重新比对基线，而不是简单地置 true，
// 这样「改了又改回去」也能正确显示为未修改。
watch(
  [() => ({ ...form }), steps, selectedCountries, rules],
  () => {
    if (!baseline) return
    dirty.value = snapshot() !== baseline
  },
  { deep: true }
)

function snapshot() {
  return JSON.stringify({
    ...form,
    steps: steps.value.map((s) => ({ value: s.value, unit: s.unit })),
    countries: [...selectedCountries.value].sort(),
    // 顺序本身是配置的一部分，所以不能排序
    rules: rules.value.map(rulePayload),
  })
}

function markClean() {
  baseline = snapshot()
  dirty.value = false
}

// 规则表 + 编译状态。保存之后要重新拉一次：服务端会规范化条件
// （端口合并、省份收敛、裸 IP 补掩码），不重拉的话基线立刻对不上，
// 刚点完保存就显示"有未保存的修改"。
async function loadRuleMeta() {
  const [r, info]: any[] = await Promise.all([api.listRateRules(), api.systemInfo()])
  rules.value = (r?.rules || []) as RateRule[]
  guardProblems.value = info?.guard?.rule_problems || []
  capability.value = info?.capability || {}
}

async function load() {
  loading.value = true
  try {
    const [p, g, prov] = await Promise.all([
      api.getPolicy() as any,
      api.geoCountries() as any,
      api.geoProvinces() as any,
    ])

    const policy = p || {}
    saved.value = policy

    form.window_seconds = policy.window_seconds ?? 60
    form.threshold = policy.threshold ?? 10
    form.escalate_window_hours = policy.escalate_window_hours ?? 24
    form.ban_granularity = policy.ban_granularity || 'ip'
    form.fail_mode = policy.fail_mode || 'open'
    form.auto_ban_enabled = policy.auto_ban_enabled ?? true
    form.observe_only = policy.observe_only ?? false
    form.geoip_block_enabled = policy.geoip_block_enabled ?? false
    form.geoip_mode = policy.geoip_mode || 'blacklist'
    form.rate_limit_enabled = policy.rate_limit_enabled ?? false
    form.rate_limit_per_sec = policy.rate_limit_per_sec ?? 20
    form.rate_limit_burst = policy.rate_limit_burst ?? 40

    steps.value = parseStepsOrDefault(policy.ban_durations)
    selectedCountries.value = String(policy.geoip_block_countries || '')
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean)

    countries.value = g?.countries || []
    countryAvailable.value = !!g?.available
    provinces.value = prov?.provinces || []

    await loadRuleMeta()

    markClean()
  } finally {
    loading.value = false
  }
}

function resetToSaved() {
  if (!saved.value) return
  load()
}

async function save() {
  const stepErr = validateSteps(steps.value)
  if (stepErr) {
    ElMessage.error(stepErr)
    return
  }
  if (form.geoip_block_enabled && selectedCountries.value.length === 0) {
    ElMessage.error('已启用地域封禁但没选任何国家，请先选择或关闭该开关')
    return
  }

  saving.value = true
  try {
    const body = {
      window_seconds: form.window_seconds,
      threshold: form.threshold,
      ban_durations: stepsToCSV(steps.value),
      escalate_window_hours: form.escalate_window_hours,
      ban_granularity: form.ban_granularity,
      fail_mode: form.fail_mode,
      auto_ban_enabled: form.auto_ban_enabled,
      observe_only: form.observe_only,
      geoip_block_enabled: form.geoip_block_enabled,
      geoip_block_countries: selectedCountries.value.join(','),
      geoip_mode: form.geoip_mode,
      rate_limit_enabled: form.rate_limit_enabled,
      rate_limit_per_sec: form.rate_limit_per_sec,
      rate_limit_burst: form.rate_limit_burst,
      // 传空数组也是这个字段：后端据此区分"清空所有规则"和"不动规则"
      rules: rules.value.map(rulePayload),
    }

    const r: any = await api.updatePolicy(body)
    saved.value = r
    // 后端会规范化国家码并回填，这里以服务端返回为准
    if (r) {
      steps.value = parseStepsOrDefault(r.ban_durations)
      selectedCountries.value = String(r.geoip_block_countries || '')
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean)
    }
    await loadRuleMeta()
    markClean()
    ElMessage.success('策略已保存并生效')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
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

.unit {
  margin-left: 8px;
  color: #8a919f;
  font-size: 12.5px;
}

.rule-off {
  color: #a8b0bd;
  text-decoration: line-through;
}

.opt-code {
  float: right;
  color: #8a919f;
  font-size: 12px;
}

:deep(.el-divider__text) {
  font-size: 13px;
  color: #5a6472;
  background: #fff;
}

:deep(.el-form-item__content) {
  display: block;
}

:deep(.el-form-item) {
  margin-bottom: 16px;
}
</style>
