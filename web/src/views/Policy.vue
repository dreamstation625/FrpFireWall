<template>
  <div v-loading="loading">
    <div class="page-card panel">
      <div class="panel-head">
        <span class="section-title">频控策略</span>
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
          <div style="width: 100%">
            <div v-for="(step, i) in steps" :key="i" class="step-row">
              <span class="step-idx">第 {{ i + 1 }} 次</span>
              <template v-if="step.unit === 'forever'">
                <el-tag type="danger" size="small" style="width: 130px">永久封禁</el-tag>
              </template>
              <template v-else>
                <el-input-number v-model="step.value" :min="1" :max="9999" size="small" controls-position="right" style="width: 130px" />
                <el-select v-model="step.unit" size="small" style="width: 100px; margin-left: 8px">
                  <el-option label="秒" value="s" />
                  <el-option label="分钟" value="m" />
                  <el-option label="小时" value="h" />
                  <el-option label="天" value="d" />
                </el-select>
                <el-button size="small" style="margin-left: 8px" @click="step.unit = 'forever'">
                  设为永久
                </el-button>
              </template>
              <div class="step-ops">
                <el-button size="small" link type="primary" :disabled="i === 0" @click="move(i, -1)">上移</el-button>
                <el-button size="small" link type="danger" :disabled="steps.length <= 1" @click="removeStep(i)">删除</el-button>
              </div>
            </div>
            <el-button size="small" style="margin-top: 8px" @click="addStep">新增一级</el-button>
            <div class="hint" style="margin-top: 8px">
              升级窗口内反复触发就逐级下移，用满最后一级后维持该级时长。
              「永久」只能放最后一级，放在别处后面几级永远不会生效。
            </div>
            <div class="hint">
              等价配置：<span class="mono">{{ durationsPreview }}</span>
            </div>
          </div>
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
              只作用于受保护的 frp 端口。
            </div>
          </el-form-item>
        </template>
      </el-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

type Unit = 's' | 'm' | 'h' | 'd' | 'forever'
interface Step {
  value: number
  unit: Unit
}

const loading = ref(false)
const saving = ref(false)
const dirty = ref(false)
const saved = ref<any>(null)

const steps = ref<Step[]>([
  { value: 10, unit: 'm' },
  { value: 1, unit: 'h' },
  { value: 1, unit: 'd' },
  { value: 0, unit: 'forever' },
])

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
const countryAvailable = ref(false)
const capability = ref<any>({})

const rateSupported = computed(() => capability.value?.rate_limit !== false)

const countriesGrouped = computed(() => countries.value)

// ---- 阶梯时长 <-> 秒序列 ----

const UNIT_SEC: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }

function parseSteps(csv: string): Step[] {
  const out: Step[] = []
  for (const raw of String(csv || '').split(',')) {
    const s = raw.trim()
    if (!s) continue
    const v = Number(s)
    if (!Number.isFinite(v) || v < 0) continue
    if (v === 0) {
      out.push({ value: 0, unit: 'forever' })
      continue
    }
    if (v % 86400 === 0) out.push({ value: v / 86400, unit: 'd' })
    else if (v % 3600 === 0) out.push({ value: v / 3600, unit: 'h' })
    else if (v % 60 === 0) out.push({ value: v / 60, unit: 'm' })
    else out.push({ value: v, unit: 's' })
  }
  return out.length ? out : [{ value: 10, unit: 'm' }]
}

function stepToSec(s: Step): number {
  if (s.unit === 'forever') return 0
  return Math.max(1, Math.floor(s.value)) * UNIT_SEC[s.unit]
}

const durationsPreview = computed(() => {
  const parts = steps.value.map((s) => (s.unit === 'forever' ? '永久(0)' : String(stepToSec(s))))
  return parts.join(',')
})

function addStep() {
  const last = steps.value[steps.value.length - 1]
  // 新增的一级默认比上一级更长；上一级是永久就把新级插到永久之前
  if (last && last.unit === 'forever') {
    steps.value.splice(steps.value.length - 1, 0, { value: 7, unit: 'd' })
  } else {
    steps.value.push({ value: 7, unit: 'd' })
  }
  touch()
}

function removeStep(i: number) {
  if (steps.value.length <= 1) return
  steps.value.splice(i, 1)
  touch()
}

function move(i: number, dir: number) {
  const j = i + dir
  if (j < 0 || j >= steps.value.length) return
  const arr = steps.value
  ;[arr[i], arr[j]] = [arr[j], arr[i]]
  touch()
}

// ---- 脏标记 ----

let baseline = ''

// 任何字段变动都重新比对基线，而不是简单地置 true，
// 这样「改了又改回去」也能正确显示为未修改。
watch(
  [() => ({ ...form }), steps, selectedCountries],
  () => {
    if (!baseline) return
    dirty.value = snapshot() !== baseline
  },
  { deep: true }
)

function touch() {
  dirty.value = true
}

function snapshot() {
  return JSON.stringify({
    ...form,
    steps: steps.value.map((s) => ({ value: s.value, unit: s.unit })),
    countries: [...selectedCountries.value].sort(),
  })
}

function markClean() {
  baseline = snapshot()
  dirty.value = false
}

async function load() {
  loading.value = true
  try {
    const [p, g] = await Promise.all([
      api.getPolicy() as any,
      api.geoCountries() as any,
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

    steps.value = parseSteps(policy.ban_durations)
    selectedCountries.value = String(policy.geoip_block_countries || '')
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean)

    countries.value = g?.countries || []
    countryAvailable.value = !!g?.available

    const info: any = await api.systemInfo()
    capability.value = info?.capability || {}

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
  // 校验：永久只能出现在最后一级
  for (let i = 0; i < steps.value.length; i++) {
    if (steps.value[i].unit === 'forever' && i !== steps.value.length - 1) {
      ElMessage.error('「永久封禁」只能放在最后一级')
      return
    }
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
      ban_durations: steps.value.map((s) => String(stepToSec(s))).join(','),
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
    }

    const r: any = await api.updatePolicy(body)
    saved.value = r
    // 后端会规范化国家码并回填，这里以服务端返回为准
    if (r) {
      steps.value = parseSteps(r.ban_durations)
      selectedCountries.value = String(r.geoip_block_countries || '')
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean)
    }
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

.step-row {
  display: flex;
  align-items: center;
  gap: 0;
  padding: 6px 0;
  border-bottom: 1px dashed #eef0f4;
}

.step-row:last-of-type {
  border-bottom: none;
}

.step-idx {
  width: 78px;
  color: #5a6472;
  font-size: 13px;
}

.step-ops {
  margin-left: auto;
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
