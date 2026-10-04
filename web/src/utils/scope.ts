// 封禁范围（all | frp | custom）的展示口径。
//
// ACL 页与封禁页共用这几个函数：同一个概念在两个页面上要是一处写"全端口"、
// 另一处写"全部端口"，用户会以为是两回事。
//
// 注意：后端对迁移前写入的老行可能返回空串，这里一律按"全端口"渲染，
// 与后端「非法值回落 all」的兜底方向保持一致 —— 宁可显示得严一点。

/** 表格里的短标签 */
export function scopeLabel(s?: string) {
  if (s === 'frp') return '仅 frp 端口'
  if (s === 'custom') return '自定义端口'
  return '全端口'
}

/** 悬浮说明：讲清楚这个范围实际挡住了什么 */
export function scopeTip(s?: string, ports?: string) {
  if (s === 'frp') return '只拒绝该地址访问 frp 服务端口（bindPort 与代理端口）'
  if (s === 'custom') {
    // 范围是自定义却没有端口时，后端会退化成全端口下发（宁可封严也不静默放掉），
    // 这里必须说同一件事，否则界面讲"只封这几个端口"、实际封了全部。
    return ports
      ? `只拒绝该地址访问这些端口：${ports}`
      : '自定义范围没有可用端口，已按「全部端口」下发'
  }
  return '拒绝该地址访问本机的全部端口，含 SSH 与管理面板'
}

/** 范围标签的配色：全端口用 warning 提醒误伤，自定义与 frp 各自一色以示区分。 */
export function scopeTagType(s?: string) {
  if (s === 'custom') return 'primary'
  return s === 'frp' ? 'info' : 'warning'
}

/** 单选按钮 / 下拉框的选项 */
export const SCOPE_OPTIONS = [
  { label: '全部端口', value: 'all' },
  { label: '仅 frp 端口', value: 'frp' },
  { label: '自定义端口', value: 'custom' },
]

/** 表单下方的提示文字，选中哪个范围就说哪个范围的代价。 */
export function scopeFormHint(s?: string) {
  if (s === 'frp') return '只拒绝该地址访问 frp 服务端口，本机其它端口不受影响。'
  if (s === 'custom') {
    return '只拒绝该地址访问下面列出的端口。写单个端口（8080）或区间（9000-9100），多个用逗号分隔。'
  }
  return '拒绝该地址访问本机的全部端口，含 SSH 与管理面板。确认不会误伤再选。'
}
