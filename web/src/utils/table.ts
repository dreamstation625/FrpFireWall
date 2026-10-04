// 表格的公共约定：分页条数与列宽记忆。
//
// 分页条数放在这里而不是写死在各页面里：同一个「每页显示多少条」在事件日志、
// 封禁历史、名单三处必须给出同样的选项，否则用户会以为某几个页面不支持调整。

import { reactive } from 'vue'

/** 每页条数选项。与后端 pageParams 的上限（500）留出余量。 */
export const PAGE_SIZES = [20, 50, 100]

/** 分页器的统一布局：总数、条数选择、上下页、页码、跳页输入框。 */
export const PAGER_LAYOUT = 'total, sizes, prev, pager, next, jumper'

// ---------------- 列宽记忆 ----------------

type Stored = Record<string, Record<string, number>>

const STORAGE_KEY = 'frpfw.table-widths'

// 读写 localStorage 一律 try/catch：隐私模式下 setItem 会直接抛异常，
// 读取时也可能撞上被手工改坏的 JSON。这类失败不该把整个页面带崩 ——
// 拖拽本身已经生效了，存不下最多是刷新后回到默认宽度。
function load(): Stored {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    return parsed as Stored
  } catch {
    return {}
  }
}

function persist(tableKey: string, cols: Record<string, number>) {
  try {
    // 每次保存前重新读一遍全量存储再改：同一个页面里有多张表（事件页有
    // 事件与变更审计两张），各自持有一份加载时的快照，直接回写会把
    // 另一张表刚记下的宽度覆盖掉。
    const all = load()
    all[tableKey] = cols
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all))
  } catch {
    /* 存不下就算了，不影响拖拽本身 */
  }
}

/** 列的默认宽度：只用其一，与 el-table-column 的 width / min-width 对应。 */
export interface ColumnDefaults {
  width?: number
  minWidth?: number
}

/**
 * 按表记忆用户拖出来的列宽。
 *
 * 用法：
 *   const cw = useColumnWidths('events')
 *   <el-table :data="rows" border @header-dragend="cw.onDragend">
 *     <el-table-column label="时间" v-bind="cw.col('时间', { width: 165 })" />
 *     <el-table-column label="详情" v-bind="cw.col('详情', { minWidth: 300 })" />
 *
 * 两点必须守住：
 *
 *   - **列标识要显式给**（col() 的第一个参数），不能拿列序号当标识。中间插一列
 *     会让后面所有列的宽度整体错位，表现成「加了列之后时间列变宽了」这种怪事。
 *   - **弹性列（minWidth）拖过之后要转成固定宽**。只记 minWidth 是记不住的：
 *     弹性列的实际宽度由剩余空间算出来，把用户拖的那个值塞回 minWidth 不生效。
 */
export function useColumnWidths(tableKey: string) {
  const saved = reactive<Record<string, number>>({ ...(load()[tableKey] || {}) })

  /** 取某列的宽度绑定；没拖过就用模板里的默认值。 */
  function col(key: string, def: ColumnDefaults) {
    const w = saved[key]
    if (w) return { columnKey: key, width: w }
    return def.minWidth != null
      ? { columnKey: key, minWidth: def.minWidth }
      : { columnKey: key, width: def.width }
  }

  /** 绑到 el-table 的 @header-dragend 上。 */
  function onDragend(newWidth: number, _oldWidth: number, column: { columnKey?: string }) {
    const key = column?.columnKey
    // 没带 columnKey 说明这列的 col() 漏了标识，记下来也只会是脏数据。
    if (!key) return
    saved[key] = Math.round(newWidth)
    persist(tableKey, { ...saved })
  }

  /** 忘掉这张表的列宽，回到模板默认值（供「重置列宽」入口调用）。 */
  function reset() {
    for (const k of Object.keys(saved)) delete saved[k]
    persist(tableKey, {})
  }

  return { col, onDragend, reset }
}
