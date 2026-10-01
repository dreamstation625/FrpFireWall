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
          clearable
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="6"
          :disabled="portsFilled"
          placeholder="选择国家或地区（可多选）"
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
        <div class="hint">同一维度内多选是「或」，不同维度之间是「且」。</div>
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
          :disabled="portsFilled"
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
          留空表示不限端口。填了端口这条规则就落在<strong>内核层</strong>，由系统防火墙按目的端口丢包。
        </div>
      </el-form-item>

      <el-form-item label="落点">
        <el-tag :type="LAYER_TAG_TYPE[layer]" size="small">{{ LAYER_LABEL[layer] }}</el-tag>
        <div class="hint">{{ LAYER_TIP[layer] }}</div>
      </el-form-item>

      <el-divider content-position="left">动作</el-divider>

      <el-form-item label="限速">
        <el-switch v-model="rateOn" active-text="开启" inactive-text="关闭" inline-prompt />
        <div v-if="rateOn" style="margin-top: 8px; width: 100%">
          <el-input-number v-model="form.per_sec" :min="1" :max="100000" size="small" />
          <span class="unit">次 / 秒（每个来源 IP 单独计数）</span>
          <div style="margin-top: 6px">
            <el-input-number v-model="form.burst" :min="0" :max="100000" size="small" />
            <span class="unit">突发额度，留 0 按速率的 2 倍自动补</span>
          </div>
        </div>
        <div v-else class="hint">这条规则不限速。</div>
      </el-form-item>

      <el-form-item label="封禁">
        <el-switch v-model="banOn" :disabled="portsFilled" active-text="开启" inactive-text="关闭" inline-prompt />
        <div v-if="portsFilled" class="hint">
          带端口条件的规则落在内核层。内核只能丢包，超限的包到不了 frps，
          应用层无从知道它超限，所以内核规则不能封禁 —— 需要封禁请去掉端口条件。
        </div>
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
const steps = ref<Step[]>([])

// 限速/封禁用开关控制对应字段是否"算数"。
//
// 不用"字段为 0 就当关闭"直接绑界面：那样用户把速率清成 0 时，
// 界面上看不出这条规则已经不达标了，只有保存时才被后端拒绝。
const rateOn = ref(false)
const banOn = ref(false)

const portsFilled = computed(() => String(form.ports ?? '').trim() !== '')

const countryOptions = computed(() => props.countries || [])
const provinceOptions = computed(() => props.provinces || [])

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
    per_sec: rateOn.value ? Number(form.per_sec) || 0 : 0,
    burst: rateOn.value ? Number(form.burst) || 0 : 0,
    window_seconds: banOn.value ? Number(form.window_seconds) || 0 : 0,
    threshold: banOn.value ? Number(form.threshold) || 0 : 0,
    ban_durations: banOn.value ? stepsToCSV(steps.value) : '',
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
    countries.value = splitList(src.countries).map((c) => c.toUpperCase())
    provinces.value = splitList(src.provinces)
    steps.value = parseSteps(src.ban_durations)
    rateOn.value = (src.per_sec ?? 0) > 0
    banOn.value = (src.window_seconds ?? 0) > 0 || (src.threshold ?? 0) > 0
  },
  { immediate: true }
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

// 填了端口就不能再有封禁：直接把封禁开关关掉并清空，
// 比留着值让后端报错更清楚 —— 界面上已经用红框说明了原因。
watch(portsFilled, (filled) => {
  if (!filled) return
  banOn.value = false
  form.window_seconds = 0
  form.threshold = 0
  steps.value = []
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
