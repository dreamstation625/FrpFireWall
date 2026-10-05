import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

// 服务器公网出口 IP 相关的两件事：探测一次、以及把地址放进白名单。
// 概览页（进页面自动探一次并提示）和设置页（手动点按钮）都要用，
// 放一处免得两边文案与备注写法慢慢长歪。

// 「暂不加入」记的是这个值本身：换了出口 IP 就该重新问一次，
// 而不是因为用户点过一次"暂不"就永远不提了。
const DISMISS_KEY = 'frpfirewall_myip_dismissed'

export type PublicIP = {
  ip: string
  source: string
  checked_at: string
  whitelisted: boolean
  error?: string
}

export function isIPv4(s: string) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(s || '').trim())
}

export async function detectPublicIP(refresh = false): Promise<PublicIP | null> {
  try {
    return (await api.publicIp(refresh)) as PublicIP
  } catch {
    // 接口失败时 axios 拦截器已经弹过提示，这里不重复打扰
    return null
  }
}

// addToWhitelist 把地址加进白名单，带一条固定备注方便日后认出它。
export async function addToWhitelist(ip: string, remark = '服务器出口 IP') {
  await api.createACL('white', { target: ip.trim(), remark })
}

// promptWhitelist 小窗确认：默认填探测到的地址，允许改成手填的。
//
// 返回值只区分"加了 / 没加"：取消时把这次的 IP 记为已忽略，
// 否则每次进概览都弹同一个窗，很快就会被当成噪音关掉。
export async function promptWhitelist(ip: string, source: string) {
  try {
    const { value } = await ElMessageBox.prompt(
      `检测到服务器公网出口 IP 为 ${ip}${source ? `（来源 ${source}）` : ''}。` +
        '它当前不在白名单里，建议加入 —— 回源流量、本机对外访问一旦被自己的' +
        '规则拦掉，表现是"服务莫名连不上"，很难往这上面想。' +
        '如果检测到的不是实际服务器 IP，直接在下面改。',
      '服务器出口 IP 未放行',
      {
        inputValue: ip,
        inputValidator: (v: string) => isIPv4(v) || '请填一个 IPv4 地址',
        confirmButtonText: '加入白名单',
        cancelButtonText: '暂不',
        // 输入框里要能直接改，不能是只读展示
        closeOnClickModal: false,
      }
    )
    const target = String(value || '').trim()
    if (!isIPv4(target)) {
      ElMessage.error('请填一个 IPv4 地址')
      return false
    }
    await addToWhitelist(target)
    ElMessage.success('已加入白名单')
    return true
  } catch {
    // 取消、关闭、加入失败都走这里：记下这次问过的地址，别再弹
    localStorage.setItem(DISMISS_KEY, ip)
    return false
  }
}

// autoCheckServerIP 概览页进页面时调一次：探到地址且不在白名单里才提示。
//
// 探测失败、地址已放行、用户点过"暂不"都直接返回 —— 这个提示只在
// 真有可能出事的时候出现，否则没人会看第二眼。
export async function autoCheckServerIP() {
  const r = await detectPublicIP(false)
  if (!r?.ip || r.whitelisted) return
  if (localStorage.getItem(DISMISS_KEY) === r.ip) return
  await promptWhitelist(r.ip, r.source)
}
