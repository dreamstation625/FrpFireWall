// 教学引导的步骤定义。
//
// 步骤里的 target 是 CSS 选择器，一律用 data-guide 属性而不是 class：
// class 会被样式调整顺手改掉，引导就会静悄悄地指到一个不存在的元素上
// （表现是"引导卡在中间不动"，很难看出是选择器失效）。
export interface GuideStep {
  // route 非空时先切到该页面再定位，这样一份引导能跨页面讲完整个链路。
  route?: string
  // target 为空表示这一句没有具体指向，气泡居中显示。
  target?: string
  title: string
  text: string
}

export const guideSteps: GuideStep[] = [
  {
    title: '它站在 frps 前面',
    text: 'frps 把登录与新建连接的事件交给它，它按你定的规则决定放行还是拒绝，并把要封的地址写进系统防火墙。下面按「接通 → 定规则 → 查结果」走一遍。',
  },
  {
    route: '/frps',
    target: '[data-guide="frps-config"]',
    title: '第一步：让 frps 把事件送过来',
    text: '把这段配置加进 frps 的配置文件并重启 frps，然后回这一页看「插件链路状态」是否变绿。没接上这一步，后面配的规则一条都不会生效。',
  },
  {
    route: '/policy',
    target: '[data-guide="policy-rules"]',
    title: '第二步：细分规则',
    text: '按条件定阈值：国家 / 省份 / 城市、IP 段、端口、代理（隧道）名都能当条件；没命中就走页面下方的全局规则。细分规则统一在应用层匹配，代理名可与地区、来源组合，目的端口请留空，无需 Dashboard；先计数再限速，触发封禁后才写内核。端口条件仅用于登录阶段。',
  },
  {
    route: '/acl',
    target: '[data-guide="acl-table"]',
    title: '第三步：黑白名单',
    text: '白名单里的地址一律放行；黑名单里的地址直接拦，可指定封禁范围（全端口 / frp 端口 / 自定义端口）和有效期。条目可以停用而不必删除 —— 停用会同时解掉由它封的 IP。按地区拦需要先在 GeoIP 页下载属地库。',
  },
  {
    route: '/bans',
    target: '[data-guide="bans-active"]',
    title: '第四步：封禁记录',
    text: '正在封的地址在这里，可以手动解封；到期自动解，配了阶梯就逐步加长时长。每条封禁都记着来源（哪个名单条目或哪条规则），解错地方会反复复发的那种问题靠这一列定位。',
  },
  {
    route: '/events',
    target: '[data-guide="events-panel"]',
    title: '第五步：事件日志',
    text: '每一次判定都留痕：放行、拒绝、封禁都记在这里，可以按 IP、账号、代理名、详情搜索。「为什么它被拦了」看这一页。',
  },
  {
    route: '/dashboard',
    target: '[data-guide="dash-trend"]',
    title: '第六步：概览上是两套数字',
    text: '这张趋势图数的是 frps 登录阶段被拒绝的连接；页面下方「防火墙拦截统计」数的是内核丢弃的包。两边不重叠，别相加。规则重建、切换后端、重启防火墙后内核计数会归零重新数。',
  },
  {
    target: '[data-guide="guide-entry"]',
    title: '就这些',
    text: '想再看一遍就点这里的「引导」。侧边菜单是按「看数 → 定规则 → 查结果 → 调防火墙」排的：属地库在 GeoIP 页，后端选择与内核规则在防火墙页。',
  },
]

const PENDING_KEY = 'frpfirewall_guide_pending'
const DONE_KEY = 'frpfirewall_guide_done'

// 初始化完成时打一个"待引导"标记，而不是直接在 setup 页里开引导 ——
// 引导要指着侧边菜单、顶栏这些主框架元素讲，那时它们还没渲染出来。
export function markGuidePending() {
  try {
    localStorage.setItem(PENDING_KEY, '1')
  } catch {
    // 隐私模式下写不进去就算了，最多是不自动弹，菜单里仍然能手动打开
  }
}

// consumeGuidePending 取出并清掉标记：自动引导只应该发生一次。
export function consumeGuidePending(): boolean {
  try {
    const v = localStorage.getItem(PENDING_KEY) === '1'
    if (v) localStorage.removeItem(PENDING_KEY)
    return v
  } catch {
    return false
  }
}

export function markGuideDone() {
  try {
    localStorage.setItem(DONE_KEY, '1')
  } catch {
    // 同上
  }
}
