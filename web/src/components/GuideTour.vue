<template>
  <div v-if="modelValue" class="guide-root">
    <!-- 遮罩分两层：整屏一层只负责吃掉点击（引导期间不该误操作），
         变暗由高亮框那层巨大的 box-shadow 完成 —— 阴影铺满全屏、
         框内是透明的，目标就是这么"挖"出来的。
         没有指向的步骤（整句是正文）没有高亮框，此时才由整屏那层变暗。 -->
    <div class="guide-blocker" :style="{ background: rect ? 'transparent' : 'rgba(15, 18, 24, 0.45)' }"></div>
    <div v-if="rect" class="guide-hole" :style="holeStyle"></div>

    <div class="guide-pop" :style="popStyle">
      <div class="guide-head">
        <span class="guide-seq">{{ index + 1 }} / {{ steps.length }}</span>
        <span class="guide-title">{{ step.title }}</span>
      </div>
      <div class="guide-text">{{ step.text }}</div>
      <div class="guide-foot">
        <el-button size="small" text @click="skip">跳过</el-button>
        <div class="spacer" />
        <el-button size="small" :disabled="index === 0" @click="prev">上一步</el-button>
        <el-button size="small" type="primary" @click="next">
          {{ index === steps.length - 1 ? '完成' : '下一步' }}
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { GuideStep } from '@/utils/guide'

const props = defineProps<{ modelValue: boolean; steps: GuideStep[] }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; finish: [] }>()

const router = useRouter()
const route = useRoute()

const index = ref(0)
const rect = ref<{ top: number; left: number; bottom: number; right: number } | null>(null)
let targetEl: HTMLElement | null = null

// 越界保护：steps 被改短时不至于渲染出一个空气泡
const step = computed<GuideStep>(
  () => props.steps[Math.min(index.value, props.steps.length - 1)] || props.steps[0] || { title: '', text: '' }
)

const PAD = 4
const holeStyle = computed(() => {
  const r = rect.value
  if (!r) return {}
  return {
    top: `${r.top - PAD}px`,
    left: `${r.left - PAD}px`,
    width: `${r.right - r.left + PAD * 2}px`,
    height: `${r.bottom - r.top + PAD * 2}px`,
  }
})

const POP_W = 340
const popStyle = computed(() => {
  const r = rect.value
  if (!r) {
    // 没有指向时居中：整句话就是内容本身，不该偏到某个角落去
    return { left: '50%', top: '50%', width: `${POP_W}px`, transform: 'translate(-50%, -50%)' }
  }
  const left = Math.max(16, Math.min(r.left, window.innerWidth - POP_W - 16))
  const below = r.bottom + 12
  // 下面放得下就放下面，放不下翻到上面。气泡高度随文案长短变化，
  // 这里按最长那句估（约 260），宁可翻到上面也不要溢出视口。
  if (below + 260 <= window.innerHeight) {
    return { left: `${left}px`, top: `${below}px`, width: `${POP_W}px` }
  }
  return { left: `${left}px`, bottom: `${window.innerHeight - r.top + 12}px`, width: `${POP_W}px` }
})

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

// waitEl 等目标出现：跨页面那几步要等路由组件挂载，
// 直接 querySelector 会拿到 null，表现是"这句没有高亮"。
async function waitEl(sel: string, timeout = 2000): Promise<HTMLElement | null> {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    const el = document.querySelector(sel) as HTMLElement | null
    if (el) return el
    await sleep(50)
  }
  return null
}

function measure() {
  if (!targetEl) {
    rect.value = null
    return
  }
  const r = targetEl.getBoundingClientRect()
  rect.value = { top: r.top, left: r.left, bottom: r.bottom, right: r.right }
}

async function locate(s: GuideStep) {
  rect.value = null
  targetEl = null
  if (!s.target) return
  const el = await waitEl(s.target)
  if (!el) return
  targetEl = el
  // 目标可能在滚动区里（主内容区自带滚动），先滚到中间再量，
  // 否则高亮框会飘在视口外。
  el.scrollIntoView({ block: 'center', behavior: 'smooth' })
  await sleep(320)
  if (targetEl === el) measure()
}

async function go(i: number) {
  index.value = Math.max(0, Math.min(i, props.steps.length - 1))
  const s = step.value
  if (s.route && route.path !== s.route) {
    await router.push(s.route)
  }
  await locate(s)
}

function next() {
  if (index.value >= props.steps.length - 1) {
    finish()
    return
  }
  go(index.value + 1)
}

function prev() {
  go(index.value - 1)
}

function skip() {
  finish()
}

function finish() {
  emit('finish')
  emit('update:modelValue', false)
}

function onReposition() {
  if (props.modelValue) measure()
}

function onKey(e: KeyboardEvent) {
  if (props.modelValue && e.key === 'Escape') skip()
}

watch(
  () => props.modelValue,
  (v) => {
    if (v) go(0)
  }
)

onMounted(() => {
  window.addEventListener('resize', onReposition)
  // 捕获阶段：滚动发生在内部容器（.main）上，冒泡阶段收不到
  window.addEventListener('scroll', onReposition, true)
  window.addEventListener('keydown', onKey)
})

onUnmounted(() => {
  window.removeEventListener('resize', onReposition)
  window.removeEventListener('scroll', onReposition, true)
  window.removeEventListener('keydown', onKey)
})
</script>

<style scoped>
.guide-blocker {
  position: fixed;
  inset: 0;
  z-index: 3000;
}

.guide-hole {
  position: fixed;
  z-index: 3001;
  border-radius: 6px;
  pointer-events: none;
  box-shadow: 0 0 0 9999px rgba(15, 18, 24, 0.45);
}

.guide-pop {
  position: fixed;
  z-index: 3002;
  background: #fff;
  border-radius: 10px;
  padding: 16px 18px 12px;
  box-shadow: 0 8px 28px rgba(15, 18, 24, 0.22);
}

.guide-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 8px;
}

.guide-seq {
  font-size: 12px;
  color: #8a919f;
}

.guide-title {
  font-size: 15px;
  font-weight: 600;
  color: #1f2329;
}

.guide-text {
  font-size: 13px;
  line-height: 1.8;
  color: #4e5969;
}

.guide-foot {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 14px;
}

.spacer {
  flex: 1;
}
</style>
