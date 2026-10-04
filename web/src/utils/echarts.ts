// ECharts 按需注册。
//
// 直接 `import * as echarts from 'echarts'` 会把全部图表类型和组件打进包里，
// 单这一项就有 1MB 左右。这里只注册实际用到的部分，新增图表类型时记得补进来。
import * as echarts from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, CanvasRenderer])

export default echarts
export type { EChartsType } from 'echarts/core'
