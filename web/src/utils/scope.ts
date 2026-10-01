// 封禁范围（all | frp）的展示口径。
//
// ACL 页与封禁页共用这几个函数：同一个概念在两个页面上要是一处写"全端口"、
// 另一处写"全部端口"，用户会以为是两回事。
//
// 注意：后端对迁移前写入的老行可能返回空串，这里一律按"全端口"渲染，
// 与后端「非法值回落 all」的兜底方向保持一致 —— 宁可显示得严一点。

/** 表格里的短标签 */
export function scopeLabel(s?: string) {
  return s === 'frp' ? '仅 frp 端口' : '全端口'
}

/** 悬浮说明：讲清楚这个范围实际挡住了什么 */
export function scopeTip(s?: string) {
  return s === 'frp'
    ? '只拒绝该地址访问 frp 服务端口（bindPort 与代理端口）'
    : '拒绝该地址访问本机的全部端口，含 SSH 与管理面板'
}

/** 单选按钮 / 下拉框的选项 */
export const SCOPE_OPTIONS = [
  { label: '全部端口', value: 'all' },
  { label: '仅 frp 端口', value: 'frp' },
]
