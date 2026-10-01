// 阶梯封禁时长 <-> 秒序列的换算。
//
// 全局策略和每条细分规则各有一套阶梯，编辑器是同一个组件，换算也必须只有一份：
// 分两处实现的话，"界面显示 1 小时"和"实际存下去 3600 秒"迟早会对不上，
// 而且是在某一次改动之后悄悄对不上。

export type StepUnit = 's' | 'm' | 'h' | 'd' | 'forever'

export interface Step {
  value: number
  unit: StepUnit
}

export const UNIT_SEC: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }

/** 新建阶梯时的默认值（与后端的出厂默认一致） */
export const DEFAULT_STEPS: Step[] = [
  { value: 10, unit: 'm' },
  { value: 1, unit: 'h' },
  { value: 1, unit: 'd' },
  { value: 0, unit: 'forever' },
]

/**
 * 把后端存的秒序列解析成编辑器用的结构。
 *
 * 空串返回**空数组**（表示"没配阶梯"），由调用方决定兜不兜默认值 ——
 * 全局策略不允许空阶梯，而细分规则里"空"是合法状态（这条规则只限速不封禁）。
 * 在这里一律兜默认值的话，细分规则会被误判成"配了封禁"。
 */
export function parseSteps(csv?: string): Step[] {
  const out: Step[] = []
  for (const raw of String(csv ?? '').split(',')) {
    const s = raw.trim()
    if (!s) continue
    const v = Number(s)
    // 负数、NaN 直接丢掉：宁可少一级，也不要造出一个"看不见的 0 秒封禁"
    if (!Number.isFinite(v) || v < 0) continue
    if (v === 0) {
      out.push({ value: 0, unit: 'forever' })
      continue
    }
    // 尽量用最大的单位展示：3600 秒显示成"1 小时"比"3600 秒"好读
    if (v % 86400 === 0) out.push({ value: v / 86400, unit: 'd' })
    else if (v % 3600 === 0) out.push({ value: v / 3600, unit: 'h' })
    else if (v % 60 === 0) out.push({ value: v / 60, unit: 'm' })
    else out.push({ value: v, unit: 's' })
  }
  return out
}

/** 解析，空则给默认阶梯（全局策略用这个） */
export function parseStepsOrDefault(csv?: string): Step[] {
  const list = parseSteps(csv)
  return list.length ? list : DEFAULT_STEPS.map((s) => ({ ...s }))
}

export function stepToSec(s: Step): number {
  if (s.unit === 'forever') return 0
  return Math.max(1, Math.floor(s.value)) * UNIT_SEC[s.unit]
}

/** 编辑器结构 -> 后端要的秒序列 */
export function stepsToCSV(steps: Step[]): string {
  return steps.map((s) => String(stepToSec(s))).join(',')
}

/** 悬浮/行内预览，让人一眼看到存下去的是什么 */
export function stepsPreview(steps: Step[]): string {
  if (!steps.length) return '（未配置）'
  return steps.map((s) => (s.unit === 'forever' ? '永久(0)' : String(stepToSec(s)))).join(',')
}

/**
 * 阶梯本身是否合法。不合法返回原因，合法返回 null。
 *
 * 「永久」只能放最后一级：放在前面的话，后面几级永远轮不到，
 * 而且界面上看不出任何问题。
 */
export function validateSteps(steps: Step[]): string | null {
  for (let i = 0; i < steps.length; i++) {
    if (steps[i].unit === 'forever' && i !== steps.length - 1) {
      return '「永久封禁」只能放在最后一级'
    }
  }
  return null
}
