<template>
  <div style="width: 100%">
    <div v-for="(step, i) in list" :key="i" class="step-row">
      <span class="step-idx">第 {{ i + 1 }} 次</span>
      <template v-if="step.unit === 'forever'">
        <el-tag type="danger" size="small" style="width: 130px">永久封禁</el-tag>
      </template>
      <template v-else>
        <el-input-number
          v-model="step.value"
          :min="1"
          :max="9999"
          size="small"
          :disabled="disabled"
          controls-position="right"
          style="width: 130px"
          @change="sync"
        />
        <el-select
          v-model="step.unit"
          size="small"
          :disabled="disabled"
          style="width: 100px; margin-left: 8px"
          @change="sync"
        >
          <el-option label="秒" value="s" />
          <el-option label="分钟" value="m" />
          <el-option label="小时" value="h" />
          <el-option label="天" value="d" />
        </el-select>
        <el-button
          size="small"
          style="margin-left: 8px"
          :disabled="disabled"
          @click="setForever(i)"
        >
          设为永久
        </el-button>
      </template>
      <div class="step-ops">
        <el-button size="small" link type="primary" :disabled="disabled || i === 0" @click="move(i, -1)">
          上移
        </el-button>
        <el-button
          size="small"
          link
          type="danger"
          :disabled="disabled || list.length <= 1"
          @click="removeAt(i)"
        >
          删除
        </el-button>
      </div>
    </div>

    <el-button size="small" style="margin-top: 8px" :disabled="disabled" @click="add">
      新增一级
    </el-button>

    <div class="hint" style="margin-top: 8px">
      升级窗口内反复触发就逐级下移，用满最后一级后维持该级时长。
      「永久」只能放最后一级，放在别处后面几级永远不会生效。
    </div>
    <div v-if="showPreview" class="hint">
      等价配置：<span class="mono">{{ preview }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { type Step, stepsPreview } from '@/utils/duration'

const props = withDefaults(
  defineProps<{
    modelValue: Step[]
    disabled?: boolean
    /** 是否展示"等价配置"那行。全局策略里默认显示 */
    showPreview?: boolean
  }>(),
  { disabled: false, showPreview: true }
)

const emit = defineEmits<{ (e: 'update:modelValue', v: Step[]): void }>()

// 就地改 props 里的对象虽然"看得见效果"，但父组件的 deep watcher 未必能
// 稳定地比对出变化（尤其是"改了又改回去"）。所以每次改动都发一份新数组，
// 让父组件走明确的赋值路径。
const list = computed(() => props.modelValue)

const preview = computed(() => stepsPreview(props.modelValue))

function snapshot(): Step[] {
  return props.modelValue.map((s) => ({ ...s }))
}

function emitValue(next: Step[]) {
  emit('update:modelValue', next)
}

/** 值或单位被 el-input-number / el-select 直接改过之后，把最新状态同步出去 */
function sync() {
  emitValue(snapshot())
}

function setForever(i: number) {
  const next = snapshot()
  next[i] = { value: 0, unit: 'forever' }
  emitValue(next)
}

function add() {
  const next = snapshot()
  const last = next[next.length - 1]
  if (last && last.unit === 'forever') {
    // 上一级是永久就把新级插到它前面，否则新增的这级永远轮不到
    next.splice(next.length - 1, 0, { value: 7, unit: 'd' })
  } else {
    next.push({ value: 7, unit: 'd' })
  }
  emitValue(next)
}

function removeAt(i: number) {
  if (props.modelValue.length <= 1) return
  const next = snapshot()
  next.splice(i, 1)
  emitValue(next)
}

function move(i: number, dir: number) {
  const j = i + dir
  if (j < 0 || j >= props.modelValue.length) return
  const next = snapshot()
  ;[next[i], next[j]] = [next[j], next[i]]
  emitValue(next)
}
</script>

<style scoped>
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
</style>
