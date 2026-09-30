import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
import { fileURLToPath, URL } from 'node:url'

// 构建产物直接输出到 internal/web/dist，
// 由 go:embed 打进二进制，最终部署只有一个可执行文件。
export default defineConfig({
  plugins: [
    vue(),
    // element-plus 按需引入：只打包模板里真正用到的组件。
    // importStyle 关掉是有意的 —— 入口已全量引入 element-plus 的 CSS，
    // 这样 ElMessage / ElMessageBox 这类函数式组件的样式不会漏掉。
    Components({
      resolvers: [ElementPlusResolver({ importStyle: false })],
      dts: 'src/components.d.ts',
    }),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7930',
        changeOrigin: true,
      },
    },
  },
})
