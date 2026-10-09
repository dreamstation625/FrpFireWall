// 细分频控规则统一在应用层匹配。

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
  /**
   * frp 的代理（隧道）名，精确匹配，单个值。空 = 不限代理。
   *
   * 只能落在应用层：代理名来自 frps 的 NewUserConn 回调，登录阶段（Login）
   * 还没有隧道，所以带这个条件的规则在登录时不命中。
   */
  proxy_name?: string
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
    proxy_name: '',
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
/** 指定了代理（隧道）名。空 = 不限代理 */
export const hasProxy = (r: RateRule) => String(r.proxy_name ?? '').trim() !== ''
export const hasGeo = (r: RateRule) =>
  splitList(r.countries).length > 0 ||
  splitList(r.provinces).length > 0 ||
  splitList(r.cities).length > 0
export const hasBan = (r: RateRule) =>
  r.window_seconds > 0 || r.threshold > 0 || splitList(r.ban_durations).length > 0

/** 所有细分规则在应用层匹配；触发封禁后才写内核。 */
export function layerOf(_r: RateRule): Layer { return "app" }

export const LAYER_LABEL: Record<Layer, string> = {kernel: "内核", app: "应用层"}

export const LAYER_TAG_TYPE: Record<Layer, 'success' | 'warning'> = {
  kernel: 'warning',
  app: 'success',
}

export const LAYER_TIP: Record<Layer, string> = {
 kernel: "旧版内核限速已迁移到应用层。",
 app: "按来源、属地与代理名匹配新连接；目的端口仅用于登录阶段。先计数再限速，触发封禁后才写内核，自动封禁仍为全端口。"
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
  if (hasProxy(r)) out.push(`代理：${String(r.proxy_name).trim()}`)
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

/** 校验规则动作，口径与后端一致。端口条件仅用于登录阶段，代理名规则须留空。 */
export function ruleProblems(r: RateRule): string[] {
  const out: string[] = []
  if (hasProxy(r) && hasPorts(r)) out.push('本版本未接入代理端口映射：按代理名对新连接做频控时，请将目的端口留空')
  if (!String(r.name ?? '').trim()) out.push('规则名不能为空')
  // 代理名也算匹配条件：只有它、没有地区和网段，是"给这个隧道单独定一套参数"。
  const hasCond = hasPorts(r) || hasGeo(r) || hasProxy(r) || splitList(r.cidrs).length > 0
  if (!hasCond) {
    out.push('还没有任何匹配条件，这条规则会命中所有流量；全量兜底请用下方的全局规则')
  }
  if (r.block && (r.per_sec > 0 || hasBan(r))) {
    out.push('「直接拦截」命中就直接拒绝了，后面的限速与封禁阈值永远不会被用到，请只保留一个')
  }
  // 拦截也算一种动作，所以开了拦截就不再要求限速/封禁
  if (!r.block && r.per_sec <= 0 && !hasBan(r)) {
    out.push('既没有限速也没有封禁阈值，命中后什么都不会发生')
  }
  const banParts = [r.window_seconds > 0, r.threshold > 0, splitList(r.ban_durations).length > 0].filter(Boolean).length
  if (banParts !== 0 && banParts !== 3) {
    out.push('封禁配置不完整：「统计窗口」「触发阈值」「封禁阶梯」要么都填，要么都不填')
  }
  return out
}
