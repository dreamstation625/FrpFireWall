import { createApp } from 'vue'
import { createPinia } from 'pinia'
// 样式全量引入：组件按需打包解决的是 JS 体积，
// 样式表统一在这里加载，避免函数式组件（ElMessage 等）丢样式。
import 'element-plus/dist/index.css'

import App from './App.vue'
import router from './router'
import './styles/main.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.mount('#app')
