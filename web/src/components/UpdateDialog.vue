<template>
  <el-dialog
    v-model="visible"
    title="版本信息"
    width="620px"
    :close-on-click-modal="false"
    @open="onOpen"
  >
    <!-- 当前运行的版本 -->
    <div class="ver-row">
      <span class="ver-label">当前版本</span>
      <span class="ver-current">{{ currentText }}</span>
      <el-tag v-if="isPrerelease" type="warning" size="small" effect="light">预发布版</el-tag>
      <el-tag v-else type="success" size="small" effect="light">正式版</el-tag>
    </div>

    <div v-if="buildTime" class="ver-sub">
      构建于 {{ buildTime }}<template v-if="commit">，提交 {{ commit }}</template>
    </div>

    <el-divider />

    <!-- 结果区 -->
    <el-alert
      v-if="!enabled"
      type="info"
      :closable="false"
      show-icon
      title="已关闭在线检查"
      description="可以在「系统设置」里重新开启，或直接前往 GitHub Releases 查看新版本。"
    />

    <template v-else>
      <el-alert
        v-if="error"
        type="warning"
        :closable="false"
        show-icon
        title="检查失败"
        :description="error"
      />

      <el-alert
        v-else-if="!checked"
        type="info"
        :closable="false"
        show-icon
        title="尚未检查"
        description="点击下方「检查更新」按钮获取最新版本信息。"
      />

      <el-alert
        v-else-if="!result?.has_update"
        type="success"
        :closable="false"
        show-icon
        title="已是最新版本"
        :description="upToDateHint"
      />

      <template v-else>
        <div class="update-head">
          <span class="ver-label">最新版本</span>
          <span class="ver-latest">{{ result.latest }}</span>
          <el-tag v-if="result.latest_is_pre" type="warning" size="small" effect="light">
            预发布
          </el-tag>
          <span v-if="result.published_at" class="ver-sub inline">
            发布于 {{ formatDate(result.published_at) }}
          </span>
        </div>

        <!-- 预发布版用户迎来正式版，值得单独说一句 -->
        <el-alert
          v-if="isPrerelease && !result.latest_is_pre"
          class="tip"
          type="success"
          :closable="false"
          show-icon
          title="正式版已发布"
          description="当前运行的是预发布版，建议升级到同名正式版以获得稳定体验。"
        />

        <div v-if="assets.length" class="assets">
          <div class="assets-title">下载文件</div>
          <div v-for="a in assets" :key="a.name" class="asset">
            <a :href="a.url" target="_blank" rel="noopener">{{ a.name }}</a>
            <span class="asset-size">{{ humanSize(a.size) }}</span>
          </div>
        </div>

        <el-collapse v-if="result.notes" class="notes">
          <el-collapse-item title="更新说明" name="notes">
            <pre class="notes-body">{{ result.notes }}</pre>
          </el-collapse-item>
        </el-collapse>
      </template>
    </template>

    <template #footer>
      <div class="footer">
        <a
          v-if="releasesUrl"
          class="all-releases"
          :href="releasesUrl"
          target="_blank"
          rel="noopener"
        >
          查看全部版本
        </a>
        <div class="spacer" />
        <el-button @click="visible = false">关闭</el-button>
        <el-button
          v-if="enabled"
          type="primary"
          :loading="loading"
          @click="runCheck(true)"
        >
          检查更新
        </el-button>
        <el-button v-else-if="releasesUrl" tag="a" :href="releasesUrl" target="_blank">
          前往下载
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const props = defineProps<{
  modelValue: boolean
  // 系统信息里已有的字段，避免重复请求
  version?: string
  commit?: string
  buildTime?: string
  isPrerelease?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'checked', hasUpdate: boolean): void
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v),
})

const loading = ref(false)
const enabled = ref(true)
const checked = ref(false)
const error = ref('')
const result = ref<any>(null)
const repo = ref('')

const currentText = computed(() => props.version || '未知')
const releasesUrl = computed(() => {
  if (result.value?.releases_url) return result.value.releases_url
  if (!repo.value) return ''
  return `https://github.com/${repo.value}/releases`
})

const assets = computed<any[]>(() => {
  const list = result.value?.assets
  return Array.isArray(list) ? list : []
})

const upToDateHint = computed(() => {
  if (props.isPrerelease) {
    return '当前是预发布版，已是最新的预发布版本。正式版发布后会在这里提示。'
  }
  return '当前已是最新的正式版本。预发布版不会提示给正式版用户。'
})

const buildTime = computed(() => {
  const t = props.buildTime
  if (!t || t === 'unknown') return ''
  return formatDate(t)
})

function formatDate(s: string): string {
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return s
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function humanSize(n: number): string {
  if (!n || n < 0) return ''
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

// 每次打开对话框先读一次服务端缓存，让界面立刻有内容，
// 但不主动联网——真正联网只在用户点「检查更新」或首次自动检查时发生。
async function onOpen() {
  try {
    const r: any = await api.updateStatus()
    enabled.value = r?.enabled !== false
    repo.value = r?.repo || ''
    if (r?.checked && r?.result) {
      apply(r.result)
    }
  } catch {
    // 读缓存失败不打断用户，点检查更新时会重新报错
  }

  // 没检查过就自动查一次，省掉用户一次点击
  if (enabled.value && !checked.value) {
    runCheck(false)
  }
}

function apply(res: any) {
  result.value = res
  repo.value = res?.repo || repo.value
  error.value = res?.error || ''
  checked.value = true
  emit('checked', !!res?.has_update)
}

async function runCheck(force: boolean) {
  loading.value = true
  try {
    const r: any = await api.checkUpdate(force)
    enabled.value = r?.enabled !== false
    if (!enabled.value) {
      checked.value = false
      result.value = null
      error.value = ''
      return
    }
    apply(r?.result || {})
    if (force) {
      if (error.value) {
        ElMessage.warning('检查失败，请稍后再试')
      } else if (result.value?.has_update) {
        ElMessage.success(`发现新版本 ${result.value.latest}`)
      } else {
        ElMessage.success('已是最新版本')
      }
    }
  } catch (e: any) {
    error.value = e?.message || '检查失败'
    checked.value = true
  } finally {
    loading.value = false
  }
}

defineExpose({ runCheck })
</script>

<style scoped>
.ver-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.ver-label {
  font-size: 13px;
  color: #8a919f;
  min-width: 68px;
}

.ver-current {
  font-size: 20px;
  font-weight: 500;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.ver-latest {
  font-size: 20px;
  font-weight: 500;
  color: #d03050;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.ver-sub {
  font-size: 12px;
  color: #8a919f;
  margin-top: 6px;
}

.ver-sub.inline {
  margin-top: 0;
  margin-left: 4px;
}

.update-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.tip {
  margin-bottom: 12px;
}

.assets {
  margin-top: 14px;
}

.assets-title {
  font-size: 13px;
  color: #8a919f;
  margin-bottom: 6px;
}

.asset {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 0;
  font-size: 13px;
}

.asset a {
  color: #1f6feb;
  text-decoration: none;
}

.asset a:hover {
  text-decoration: underline;
}

.asset-size {
  color: #8a919f;
  font-size: 12px;
}

.notes {
  margin-top: 14px;
}

.notes-body {
  margin: 0;
  font-size: 12px;
  line-height: 1.7;
  color: #4a5160;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  max-height: 260px;
  overflow-y: auto;
}

.footer {
  display: flex;
  align-items: center;
}

.footer .spacer {
  flex: 1;
}

.all-releases {
  font-size: 13px;
  color: #1f6feb;
  text-decoration: none;
}

.all-releases:hover {
  text-decoration: underline;
}
</style>
