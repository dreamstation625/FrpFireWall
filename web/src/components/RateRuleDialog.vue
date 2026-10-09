<template>
  <el-dialog
    v-model="visible"
    :title="isEdit ? '编辑细分规则' : '新增细分规则'"
    width="780px"
    :close-on-click-modal="false"
    append-to-body
  >
    <div v-if="problems.length" class="alert-danger" style="margin-bottom: 14px">
      <div v-for="(p, i) in problems" :key="i">{{ p }}</div>
    </div>

    <el-form label-width="110px" label-position="right">
      <el-form-item label="规则名">
        <el-input v-model="form.name" maxlength="64" show-word-limit placeholder="例如：香港访客限速" />
      </el-form-item>

      <el-form-item label="状态">
        <el-switch v-model="form.enabled" active-text="启用" inactive-text="停用" inline-prompt />
        <span class="unit" style="margin-left: 10px">停用的规则留在列表里，但不参与匹配</span>
      </el-form-item>

      <el-divider content-position="left">匹配条件</el-divider>

      <el-form-item label="国家 / 地区">
        <el-select
          v-model="countries"
          multiple
          filterable
          allow-create
          default-first-option
          clearable
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="6"
          placeholder="选择或直接输入两位国家码（如 CN、CU）"
          style="width: 100%"
        >
          <el-option
            v-for="c in countryOptions"
            :key="c.code"
            :label="`${c.name}（${c.code}）`"
            :value="c.code"
          >
            <span>{{ c.name }}</span>
            <span class="opt-code">{{ c.code }}</span>
          </el-option>
        </el-select>
        <div class="hint">
          同一维度内多选是「或」，不同维度之间是「且」。下拉里只收了常见来源地，
          没收录的国家直接敲两位代码即可回车添加（国家码只校验格式，写错不报错、只会不命中）。
        </div>
      </el-form-item>

      <el-form-item label="省份">
        <el-select
          v-model="provinces"
          multiple
          filterable
          clearable
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="6"
          placeholder="中国省份（可多选）"
          style="width: 100%"
        >
          <el-option
            v-for="p in provinceOptions"
            :key="p.name"
            :label="p.full"
            :value="p.name"
          />
        </el-select>
        <div class="hint">
          省份取值与属地库返回的一致（已经去掉「省 / 市 / 自治区」这类后缀，
          所以库里返回「广东省」也能命中这里的「广东」）。属地查不到时按不命中处理。
        </div>
      </el-form-item>

      <el-form-item label="城市">
        <el-select
          v-model="cities"
          multiple
          filterable
          allow-create
          default-first-option
          clearable
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="6"
          placeholder="直接输入城市名后回车（可多个），例如 深圳"
          style="width: 100%"
        >
          <el-option v-for="c in cityOptions" :key="c" :label="c" :value="c" />
        </el-select>
        <div class="hint">
          城市没有候选列表（全国几百个地级市，还有国外的），所以<strong>写错不会报错、只会永远不命中</strong>。
          写「深圳」或「深圳市」都行（后缀会被去掉），不确定时先用「属地查询」核对一下。
        </div>
      </el-form-item>

      <el-form-item label="来源地址">
        <el-input
          v-model="form.cidrs"
          type="textarea"
          :rows="2"
          placeholder="单个 IP 或网段，用逗号 / 空格 / 换行分隔，例如 1.2.3.4, 203.0.113.0/24"
        />
      </el-form-item>

      <el-form-item label="目的端口">
        <el-input
          v-model="form.ports"
          type="textarea"
          :rows="2"
          placeholder="端口或区间，例如 443, 20000-30000"
        />
        <div class="hint">
          本版本目的端口条件仅匹配登录阶段的 bindPort。<br />对代理新连接做频控，请将此项留空；代理名可选，留空表示不限代理，仍按地区和来源条件匹配，无需 Dashboard。统计的是新建连接，不是 HTTP 请求数；自动封禁仍为全端口。
        </div>
      </el-form-item>

      <el-form-item label="代理（可选）">
        <el-select
          v-model="form.proxy_name"
          filterable
          allow-create
          default-first-option
          clearable
          placeholder="留空 = 不限代理；可手填代理名后回车"
          style="width: 100%"
        >
          <el-option
            v-for="p in proxyOptions"
            :key="p"
            :label="p"
            :value="p"
          />
        </el-select>
        <div class="hint">
          <strong>可留空</strong>：不限制代理名，按其他条件匹配；填写后只对<strong>这个代理</strong>的新连接生效。代理新连接规则的目的端口请留空，无需启用 Dashboard。不同代理要不同力度，就建多条规则、把专用的排前面。
          <br />
          下拉里是<strong>最近出现过</strong>的代理名（来自事件日志，受保留期影响），
          新建的隧道还没人来过时不在里面 —— 直接敲名字回车即可。
          登录阶段还没有隧道，只有填写了代理名的规则才会跳过登录阶段；留空时也可匹配登录尝试。所有匹配条件都留空时，请使用全局规则。
        </div>
      </el-form-item>

      <el-form-item label="落点">
        <el-tag :type="LAYER_TAG_TYPE[layer]" size="small">{{ LAYER_LABEL[layer] }}</el-tag>
        <div class="hint">{{ LAYER_TIP[layer] }}</div>
      </el-form-item>

      <el-divider content-position="left">动作</el-divider>

      <el-form-item label="直接拦截">
        <el-switch
          v-model="form.block"
          active-text="开启"
          inactive-text="关闭"
          inline-prompt
        />
        <div v-if="form.block" class="alert-note" style="margin-top: 6px; width: 100%">
          命中即<strong>拒绝这次连接</strong>，同时把来源封进内核防火墙，后续它连别的端口也进不来。
          按全局策略的封禁粒度与阶梯时长执行。与限速、封禁阈值互斥（命中就被拒了，后面那些参数轮不到生效）。
        </div>
        <div v-else class="hint">只判定，不直接拒绝。</div>
      </el-form-item>

      <el-form-item label="限速">
        <el-switch v-model="rateOn" :disabled="form.block" active-text="开启" inactive-text="关闭" inline-prompt />
        <div v-if="rateOn" style="margin-top: 8px; width: 100%">
          <el-input-number v-model="form.per_sec" :min="1" :max="100000" size="small" />
          <span class="unit">次 / 秒（每个来源 IP 单独计数）</span>
          <div style="margin-top: 6px">
            <el-input-number v-model="form.burst" :min="0" :max="100000" size="small" />
            <span class="unit">突发额度，留 0 按速率的 2 倍自动补</span>
          </div>
        </div>
        <div v-else-if="form.block" class="hint">已开启直接拦截，不再需要限速。</div>
        <div v-else class="hint">这条规则不限速。</div>
      </el-form-item>

      <el-form-item label="封禁">
        <el-switch
          v-model="banOn"
          :disabled="form.block"
          active-text="开启"
          inactive-text="关闭"
          inline-prompt
        />
        <div v-if="form.block" class="hint">已开启直接拦截，不再需要封禁阈值。</div>
        <div v-else-if="banOn" style="margin-top: 8px; width: 100%">
          <div>
            <span class="field-label">统计窗口</span>
            <el-input-number v-model="form.window_seconds" :min="1" :max="86400" size="small" />
            <span class="unit">秒</span>
          </div>
          <div style="margin-top: 6px">
            <span class="field-label">触发阈值</span>
            <el-input-number v-model="form.threshold" :min="1" :max="100000" size="small" />
            <span class="unit">次</span>
          </div>
          <div style="margin-top: 10px">
            <span class="field-label">封禁阶梯</span>
            <BanStepsEditor v-model="steps" :show-preview="true" />
          </div>
          <div class="hint" style="margin-top: 8px">
            这条规则用自己的阶梯表；「阶梯级数」仍按该地址最近一次封禁是第几级推导，
            与本条规则无关 —— 那样做的话，攻击者在两条规则之间来回触发就能把等级永远压在第一级。
          </div>
        </div>
        <div v-else class="hint">这条规则只限速，不封禁。</div>
      </el-form-item>

      <el-form-item label="备注">
        <el-input v-model="form.remark" maxlength="255" placeholder="选填" />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :disabled="problems.length > 0" @click="confirm">
        {{ isEdit ? '确定' : '添加' }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import BanStepsEditor from '@/components/BanStepsEditor.vue'
import { type Step, parseSteps, stepsToCSV } from '@/utils/duration'
import {
  LAYER_LABEL,
  LAYER_TAG_TYPE,
  LAYER_TIP,
  type RateRule,
  emptyRule,
  layerOf,
  ruleProblems,
} from '@/utils/raterule'

const props = defineProps<{
  modelValue: boolean
  /** null 表示新增 */
  rule: RateRule | null
  countries: any[]
  provinces: any[]
  /** 最近出现过的代理名，只是候选：手填的值同样有效 */
  proxyNames?: string[]
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'saved', r: RateRule): void
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v),
})

const isEdit = computed(() => props.rule !== null)

const form = reactive<RateRule>(emptyRule())
const countries = ref<string[]>([])
const provinces = ref<string[]>([])
const cities = ref<string[]>([])
const steps = ref<Step[]>([])

// 限速/封禁用开关控制对应字段是否"算数"。
//
// 不用"字段为 0 就当关闭"直接绑界面：那样用户把速率清成 0 时，
// 界面上看不出这条规则已经不达标了，只有保存时才被后端拒绝。
const rateOn = ref(false)
const banOn = ref(false)


const countryOptions = computed(() => props.countries || [])
const provinceOptions = computed(() => props.provinces || [])

// 当前填的值要并进选项里：它可能是手填的、也可能是保留期已经被清掉的旧隧道，
// 两种情况都不在候选列表里。不加进来的话 Select 会把值显示成空（看着像没配），
// 而规则其实存着代理名 —— 属于"界面骗人"那类问题。
const proxyOptions = computed(() => {
  const cur = String(form.proxy_name ?? '').trim()
  const list = (props.proxyNames || []).filter((v) => v && v !== cur)
  return cur ? [cur, ...list] : list
})

// 城市没有候选表（候选集开放，见后端 model.CanonicalCity 的说明），
// 但把用户已经填过的城市回显成可选项，至少同一台机器上是同一套写法。
const cityOptions = computed(() => cities.value)

const splitList = (s?: string) =>
  String(s ?? '')
    .split(/[,，;；\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)

const layer = computed(() => layerOf(form))

/** 把界面状态组装成一条完整的规则，交给 problems 判定 */
function build(): RateRule {
  return {
    ...form,
    countries: countries.value.join(','),
    provinces: provinces.value.join(','),
    cities: cities.value.join(','),
    // 开了拦截就不该带着限速/封禁值出门：界面上已经把它们禁掉了，
    // 但库里回填的值还在（比如从"限速规则"改成"拦截规则"），
    // 不清掉会被后端判成"两者只能保留一个"，而用户在界面上根本看不到那几个数。
    per_sec: rateOn.value && !form.block ? Number(form.per_sec) || 0 : 0,
    burst: rateOn.value && !form.block ? Number(form.burst) || 0 : 0,
    window_seconds: banOn.value && !form.block ? Number(form.window_seconds) || 0 : 0,
    threshold: banOn.value && !form.block ? Number(form.threshold) || 0 : 0,
    ban_durations: banOn.value && !form.block ? stepsToCSV(steps.value) : '',
  }
}

const problems = computed(() => ruleProblems(build()))

// 打开时把传入的规则灌进表单。
// 用 watch 而不是 onMounted：同一个弹窗实例会被反复打开。
watch(
  () => [props.modelValue, props.rule] as const,
  ([open]) => {
    if (!open) return
    const src = props.rule ? { ...props.rule } : emptyRule()
    Object.assign(form, emptyRule(), src)
    form.block = !!src.block
    countries.value = splitList(src.countries).map((c) => c.toUpperCase())
    provinces.value = splitList(src.provinces)
    cities.value = splitList(src.cities)
    steps.value = parseSteps(src.ban_durations)
    rateOn.value = (src.per_sec ?? 0) > 0
    banOn.value = (src.window_seconds ?? 0) > 0 || (src.threshold ?? 0) > 0
  },
  { immediate: true }
)

// 打开拦截时把限速/封禁关掉：它们在界面上已经变灰，留着勾选状态会让人以为
// 还在生效（后端实际上会直接拒绝这样一条规则）。
watch(
  () => form.block,
  (on) => {
    if (!on) return
    rateOn.value = false
    banOn.value = false
    form.per_sec = 0
    form.burst = 0
    form.window_seconds = 0
    form.threshold = 0
    steps.value = []
  }
)

// 打开封禁时给一套默认值，免得用户面对三个空格子不知道填什么。
// 只在确实全空的时候补，改过的值不动。
watch(banOn, (on) => {
  if (!on) return
  if (!form.window_seconds) form.window_seconds = 60
  if (!form.threshold) form.threshold = 10
  if (!steps.value.length) {
    steps.value = [
      { value: 10, unit: 'm' },
      { value: 1, unit: 'h' },
      { value: 1, unit: 'd' },
      { value: 0, unit: 'forever' },
    ]
  }
})

watch(rateOn, (on) => {
  if (on && !form.per_sec) form.per_sec = 20
})


function confirm() {
  if (problems.value.length) return
  emit('saved', build())
  visible.value = false
}
</script>

<style scoped>
.unit {
  margin-left: 8px;
  color: #8a919f;
  font-size: 12.5px;
}

.field-label {
  display: inline-block;
  width: 78px;
  color: #5a6472;
  font-size: 13px;
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
</style>
