// 细分频控规则的展示口径。
//
// 表格里的"条件"列和编辑弹窗里的落点提示都从这里取，落点判断尤其不能各写一份：
// 一处按"有没有端口"算、另一处按"有没有地区"算的话，界面会显示落在内核层、
// 而实际规则落在应用层 —— 用户按界面上的提示去理解行为，就会得出错误结论。

/** 后端返回的一条细分规则 */
export interface RateRule {
  id?: number
  name: string
  enabled: boolean
  priority?: number
  countries: string
  provinces: string
  cities: string
  cidrs: string
  ports: string
  /** 命中即拒绝这次连接，不再计数也不限速 */
  block: boolean
  per_sec: number
  burst: number
  window_seconds: number
  threshold: number
  ban_durations: string
  remark: string
  /** 后端算好一起返回的落点 */
  layer?: Layer
}

export type Layer = 'kernel' | 'app'

export function emptyRule(): RateRule {
  return {
    name: '',
    enabled: true,
    countries: '',
    provinces: '',
    cities: '',
    cidrs: '',
    ports: '',
    block: false,
    per_sec: 0,
    burst: 0,
    window_seconds: 0,
    threshold: 0,
    ban_durations: '',
    remark: '',
  }
}

const splitList = (s?: string) =>
  String(s ?? '')
    .split(/[,，;；\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)

export const hasPorts = (r: RateRule) => splitList(r.ports).length > 0
export const hasGeo = (r: RateRule) =>
  splitList(r.countries).length > 0 ||
  splitList(r.provinces).length > 0 ||
  splitList(r.cities).length > 0
export const hasBan = (r: RateRule) =>
  r.window_seconds > 0 || r.threshold > 0 || splitList(r.ban_durations).length > 0

/**
 * 落点：有端口条件就落内核，否则落应用层。
 *
 * 这不是"用户选的"，是两条硬约束推出来的：需要按被访问的端口分流只能在内核做
 * （frps 插件回调拿不到端口），需要按来源属地分流只能在应用层做
 * （属地库没法反查出某个国家的 CIDR 列表）。落点不同，能配的动作也不同。
 */
export function layerOf(r: RateRule): Layer {
  return hasPorts(r) ? 'kernel' : 'app'
}

export const LAYER_LABEL: Record<Layer, string> = {
  kernel: '内核',
  app: '应用层',
}

export const LAYER_TAG_TYPE: Record<Layer, 'success' | 'warning'> = {
  kernel: 'warning',
  app: 'success',
}

export const LAYER_TIP: Record<Layer, string> = {
  kernel:
    '带端口条件的规则下发到系统防火墙，按目的端口丢包。内核只能丢包，不能封禁 —— 超限的包根本到不了 frps，应用层无从知道它超限。',
  app: '不带端口条件的规则由 frps 插件在每次登录时判定，可以限速、可以封禁，也可以直接拒绝。限速按来源 IP 独立计数。',
}

/** 条件的可读摘要 */
export function conditionParts(r: RateRule, countryLabel?: (code: string) => string): string[] {
  const out: string[] = []
  const countries = splitList(r.countries).map((c) => countryLabel?.(c) || c)
  if (countries.length) out.push(`地区：${countries.join('、')}`)
  const provinces = splitList(r.provinces)
  if (provinces.length) out.push(`省份：${provinces.join('、')}`)
  const cities = splitList(r.cities)
  if (cities.length) out.push(`城市：${cities.join('、')}`)
  const cidrs = splitList(r.cidrs)
  if (cidrs.length) out.push(`来源：${cidrs.join('、')}`)
  const ports = splitList(r.ports)
  if (ports.length) out.push(`端口：${ports.join('、')}`)
  return out
}

/** 动作的可读摘要 */
export function actionParts(r: RateRule): string[] {
  const out: string[] = []
  // 「直接拦截」与限速/封禁互斥（后端也拦），所以命中它时不用再往下看
  if (r.block) out.push('直接拦截（命中即拒绝）')
  if (r.per_sec > 0) {
    out.push(`限速 ${r.per_sec}/秒${r.burst > 0 ? `（突发 ${r.burst}）` : ''}`)
  }
  if (r.threshold > 0) {
    out.push(`${r.window_seconds} 秒内 ${r.threshold} 次即封禁`)
  }
  return out
}

/**
 * 这条规则有什么问题（会导致保存被后端拒绝），没问题返回空数组。
 *
 * 三条冲突必须在这里拦下来并讲清楚，而不是让用户去读后端的报错：
 * 地区 + 端口凑在一条里必然有一条不生效，这个约束从界面上完全看不出来。
 *
 * 这里的判据必须与 model.RateRule.Validate 一一对应：前端放行、后端拒绝，
 * 用户看到的是一句弹窗报错；前端拦住、后端本来会放行，则是一个能用却配不出来的
 * 功能。两边都从"有没有端口"这个唯一的落点开关推，就不会走岔。
 */
export function ruleProblems(r: RateRule): string[] {
  const out: string[] = []
  if (!String(r.name ?? '').trim()) out.push('规则名不能为空')
  const hasCond = hasPorts(r) || hasGeo(r) || splitList(r.cidrs).length > 0
  if (!hasCond) {
    out.push('还没有任何匹配条件，这条规则会命中所有流量；全量兜底请用下方的全局规则')
  }
  if (hasPorts(r) && hasGeo(r)) {
    out.push(
      '「地区」和「端口」不能出现在同一条规则里：地区只有 frps 插件能判（它拿不到被访问的端口），' +
        '端口只有系统防火墙能判。请清掉其中一边，或者拆成两条规则'
    )
  }
  if (hasPorts(r) && r.block) {
    out.push('带端口条件的规则落在内核层，内核只能丢包、丢不到「拒绝」这一步，请清掉端口或关掉「直接拦截」')
  }
  if (hasPorts(r) && hasBan(r)) {
    out.push('带端口条件的规则落在内核层，内核只能丢包、不能封禁，请清掉封禁配置或改走应用层')
  }
  if (!hasPorts(r) && r.block && (r.per_sec > 0 || hasBan(r))) {
    out.push('「直接拦截」命中就直接拒绝了，后面的限速与封禁阈值永远不会被用到，请只保留一个')
  }
  // 拦截也算一种动作，所以开了拦截就不再要求限速/封禁
  if (!hasPorts(r) && !r.block && r.per_sec <= 0 && !hasBan(r)) {
    out.push('既没有限速也没有封禁阈值，命中后什么都不会发生')
  }
  const banParts = [r.window_seconds > 0, r.threshold > 0, splitList(r.ban_durations).length > 0].filter(Boolean).length
  if (!hasPorts(r) && banParts !== 0 && banParts !== 3) {
    out.push('封禁配置不完整：「统计窗口」「触发阈值」「封禁阶梯」要么都填，要么都不填')
  }
  return out
}
