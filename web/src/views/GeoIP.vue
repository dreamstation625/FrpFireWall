<template>
  <div v-loading="loading">
    <div class="page-card panel">
      <div class="panel-head">
        <span class="section-title">属地数据库状态</span>
        <div class="head-actions">
          <el-select v-model="mirrorId" size="small" style="width: 210px">
            <el-option label="自动选择（依次尝试）" :value="autoId" />
            <el-option v-for="m in mirrors" :key="m.id" :label="m.name" :value="m.id" />
          </el-select>
          <el-button size="small" @click="load">刷新</el-button>
        </div>
      </div>

      <div v-if="stale" class="alert-note" style="margin-bottom: 14px">
        {{ status?.reason || '数据库可能需要更新。' }}
      </div>

      <div v-if="downloading" class="alert-note" style="margin-bottom: 14px">
        正在下载 <strong>{{ downloadingName }}</strong>，请勿关闭页面。
        选中的源不通时会自动切换下一个，可能要等一会儿。
      </div>

      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="数据目录">
          <span class="mono">{{ status?.data_dir || '—' }}</span>
        </el-descriptions-item>
      </el-descriptions>

      <div class="db-grid">
        <div v-for="db in dbCards" :key="db.key" class="db-item">
          <div class="db-head">
            <span class="db-name">{{ db.title }}</span>
            <el-tag size="small" :type="db.loaded ? 'success' : 'info'">
              {{ db.loaded ? '已加载' : '未加载' }}
            </el-tag>
          </div>
          <div class="db-desc hint">{{ db.desc }}</div>
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item label="文件名">
              <span class="mono">{{ db.file }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="大小">
              {{ db.size ? fmtSize(db.size) : '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="更新时间">
              {{ db.time && !isZero(db.time) ? fmt(db.time) : '—' }}
            </el-descriptions-item>
          </el-descriptions>

          <div class="db-actions">
            <el-button
              size="small"
              type="primary"
              plain
              :loading="downloading === db.key"
              :disabled="!!downloading"
              @click="doDownload(db)"
            >
              下载更新
            </el-button>
            <span class="hint" :title="db.src ? '上游：' + db.src.from : ''">
              {{ db.src?.note || '没有可用的下载源' }}
            </span>
          </div>
        </div>
      </div>

      <div class="alert-note">
        缺少任何一个都不影响拦截主流程：
        <br />
        · <strong>GeoLite2-Country</strong>：只有国家/地区，做地域封禁必须要有。
        <br />
        · <strong>GeoLite2-City</strong>：含省/市，排障时看得更细。
        <br />
        · <strong>ip2region.xdb</strong>：国内解析更细，不依赖 MaxMind 账号。
        <br />
        下载会先校验文件头，通过才替换旧库并立即生效；校验不通过旧库原样在用。
        下载失败时会依次换源重试，全部失败会把每个源的原因列出来。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">上传 / 更新数据库</span>
      </div>
      <el-form label-width="110px">
        <el-form-item label="数据库">
          <el-select v-model="uploadName" style="width: 320px">
            <el-option label="GeoLite2-Country.mmdb（国家级）" :value="FILE_COUNTRY" />
            <el-option label="GeoLite2-City.mmdb（城市级）" :value="FILE_CITY" />
            <el-option label="ip2region.xdb（国内细化）" :value="FILE_REGION" />
          </el-select>
        </el-form-item>
        <el-form-item label="文件">
          <el-upload
            :auto-upload="false"
            :limit="1"
            :on-change="onFileChange"
            :on-remove="() => (picked = null)"
            :file-list="fileList"
            drag
            style="width: 100%"
          >
            <div class="upload-inner">
              把 {{ uploadName }} 拖到这里，或<em>点击选择文件</em>
            </div>
          </el-upload>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="uploading" :disabled="!picked" @click="doUpload">
            上传并热加载
          </el-button>
          <span class="hint" style="margin-left: 10px">
            上传后先校验文件头，通过才替换旧库并立即生效。
          </span>
        </el-form-item>
      </el-form>
      <div class="hint">
        mmdb 从 MaxMind 获取，xdb 从 ip2region 仓库获取。
      </div>
    </div>

    <div class="page-card panel mt">
      <div class="panel-head">
        <span class="section-title">IP 属地查询</span>
      </div>

      <div class="filters">
        <el-input
          v-model="queryIP"
          placeholder="输入 IP，例如 8.8.8.8"
          clearable
          style="width: 300px"
          @keyup.enter="doLookup"
        />
        <el-button type="primary" :loading="looking" @click="doLookup">查询</el-button>
      </div>

      <template v-if="result">
        <div class="result-grid">
          <div class="result-block">
            <div class="block-title">属地信息</div>
            <el-descriptions :column="1" size="small" border>
              <el-descriptions-item label="IP">{{ result.geoip?.ip || queryIP }}</el-descriptions-item>
              <el-descriptions-item label="是否命中">
                <el-tag size="small" :type="result.geoip?.found ? 'success' : 'info'">
                  {{ result.geoip?.found ? '已命中' : '未命中' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="国家 / 地区">
                {{ result.geoip?.country_name || '—' }}
                <span v-if="result.geoip?.country" class="hint">
                  （{{ result.geoip.country }}）
                </span>
              </el-descriptions-item>
              <el-descriptions-item label="省 / 市">
                {{ [result.geoip?.province, result.geoip?.city].filter(Boolean).join(' · ') || '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="运营商">
                {{ result.geoip?.isp || '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="数据来源">
                <span class="mono">{{ result.geoip?.source || '—' }}</span>
              </el-descriptions-item>
            </el-descriptions>
          </div>

          <div class="result-block">
            <div class="block-title">当前拦截状态</div>
            <el-descriptions :column="1" size="small" border>
              <el-descriptions-item label="合法地址">
                <el-tag size="small" :type="state?.valid ? 'success' : 'danger'">
                  {{ state?.valid ? '是' : '否' }}
                </el-tag>
                <span v-if="state?.error" class="hint" style="margin-left: 8px">{{ state.error }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="系统保护">
                <el-tag size="small" :type="state?.system_protected ? 'warning' : 'info'">
                  {{ state?.system_protected ? '是（不可封禁）' : '否' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="白名单">
                <el-tag size="small" :type="state?.whitelisted ? 'success' : 'info'">
                  {{ state?.whitelisted ? '是' : '否' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="黑名单">
                <el-tag size="small" :type="state?.blacklisted ? 'danger' : 'info'">
                  {{ state?.blacklisted ? '是' : '否' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="可信回源">
                <el-tag size="small" :type="state?.trusted_proxy ? 'success' : 'info'">
                  {{ state?.trusted_proxy ? '是（CDN 回源段）' : '否' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="当前封禁">
                <el-tag size="small" :type="state?.banned ? 'danger' : 'success'">
                  {{ state?.banned ? '已封禁' : '未封禁' }}
                </el-tag>
                <span v-if="state?.banned" class="hint" style="margin-left: 8px">
                  {{ state.ban?.permanent ? '永久' : `剩余 ${fmtRemain(state.ban?.remaining_sec)}` }}
                </span>
              </el-descriptions-item>
              <el-descriptions-item label="窗口内尝试">
                {{ state?.window_hits ?? 0 }} 次
                <span class="hint" style="margin-left: 8px">
                  （阈值 {{ threshold }} 次即触发）
                </span>
              </el-descriptions-item>
            </el-descriptions>

            <div v-if="state?.banned" class="alert-danger" style="margin-top: 10px">
              封禁原因：{{ state.ban?.reason || '—' }}
            </div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const FILE_COUNTRY = 'GeoLite2-Country.mmdb'
const FILE_CITY = 'GeoLite2-City.mmdb'
const FILE_REGION = 'ip2region.xdb'

// 加速源选择记住上次用的。公共加速源随时可能挂，用户往往会固定用一个能通的，
// 每次进来都要重选很烦。
const MIRROR_KEY = 'frpfirewall.geoip.mirror'

const loading = ref(false)
const status = ref<any>(null)
const stale = ref(false)
const threshold = ref(10)

const sources = ref<any[]>([])
const mirrors = ref<any[]>([])
const autoId = ref('auto')
const mirrorId = ref(localStorage.getItem(MIRROR_KEY) || 'auto')
const downloading = ref<string | null>(null)

watch(mirrorId, (v) => localStorage.setItem(MIRROR_KEY, v || 'auto'))

const uploadName = ref(FILE_COUNTRY)
const picked = ref<File | null>(null)
const fileList = ref<any[]>([])
const uploading = ref(false)

const queryIP = ref('')
const looking = ref(false)
const result = ref<any>(null)

const state = computed(() => result.value?.state || null)

// 下载源按落地文件名和状态卡片对上，后端换源时前端不用跟着改。
const srcOf = (file: string) => sources.value.find((s) => s.name === file)

const dbCards = computed(() => [
  {
    key: 'country',
    title: '国家级 mmdb',
    desc: '用于地域封禁与国家级归属展示。',
    file: FILE_COUNTRY,
    src: srcOf(FILE_COUNTRY),
    loaded: !!status.value?.country_loaded,
    size: status.value?.country_size || 0,
    time: status.value?.country_time,
  },
  {
    key: 'city',
    title: '城市级 mmdb',
    desc: '补省 / 市（不含运营商）。',
    file: FILE_CITY,
    src: srcOf(FILE_CITY),
    loaded: !!status.value?.city_loaded,
    size: status.value?.city_size || 0,
    time: status.value?.city_time,
  },
  {
    key: 'region',
    title: 'ip2region xdb',
    desc: '国内属地细化的补充来源；当前为 ' +
      (status.value?.region_is_v4 ? 'IPv4' : '未知') + ' 版本。',
    file: FILE_REGION,
    src: srcOf(FILE_REGION),
    loaded: !!status.value?.region_loaded,
    size: status.value?.region_size || 0,
    time: status.value?.region_time,
  },
])

const downloadingName = computed(() => {
  const c = dbCards.value.find((d) => d.key === downloading.value)
  return c ? c.file : ''
})

function fmt(t?: string) {
  if (!t) return '—'
  return new Date(t).toLocaleString('zh-CN', { hour12: false })
}

function isZero(t?: string) {
  if (!t) return true
  return new Date(t).getTime() < 86400000
}

function fmtSize(n: number) {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

function mirrorName(id: string) {
  return mirrors.value.find((m) => m.id === id)?.name || id
}

function fmtRemain(sec?: number) {
  if (sec == null || sec < 0) return '永久'
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (h > 0) return `${h} 小时 ${m} 分`
  if (m > 0) return `${m} 分钟`
  return `${sec} 秒`
}

async function load() {
  loading.value = true
  try {
    const [s, p, src] = await Promise.all([
      api.geoStatus() as any,
      api.getPolicy() as any,
      api.geoSources() as any,
    ])
    status.value = s
    stale.value = !!s?.stale
    threshold.value = p?.threshold ?? 10
    sources.value = src?.sources || []
    mirrors.value = src?.mirrors || []
    autoId.value = src?.auto || 'auto'
  } finally {
    loading.value = false
  }
}

async function doDownload(db: any) {
  if (!db?.src) {
    ElMessage.warning('这一项没有可用的下载源，请手动上传')
    return
  }
  downloading.value = db.key
  try {
    const r: any = await api.geoDownload(db.src.name, mirrorId.value)
    status.value = r?.status || status.value
    stale.value = !!status.value?.stale
    const res = r?.result || {}
    const ver = res.version ? `，上游版本 ${res.version}` : ''
    // 回显用的是加速源的名字而不是 ID，用户在下拉里看到的就是这个名字。
    const via =
      res.mirror && res.mirror !== 'direct' ? `（经 ${mirrorName(res.mirror)}）` : ''
    ElMessage.success(
      `${res.name || db.file} 已更新并热加载${ver}${via}，${fmtSize(res.size || 0)}`,
    )
  } finally {
    downloading.value = null
  }
}

function onFileChange(f: any) {
  picked.value = f.raw as File
  fileList.value = [f]
}

async function doUpload() {
  if (!picked.value) {
    ElMessage.warning('请先选择文件')
    return
  }
  uploading.value = true
  try {
    const r: any = await api.geoUpload(uploadName.value, picked.value)
    status.value = r?.status || status.value
    stale.value = !!status.value?.stale
    ElMessage.success('数据库已更新并热加载')
    picked.value = null
    fileList.value = []
    await load()
  } finally {
    uploading.value = false
  }
}

async function doLookup() {
  const ip = queryIP.value.trim()
  if (!ip) {
    ElMessage.warning('请输入 IP')
    return
  }
  looking.value = true
  try {
    result.value = await api.geoLookup(ip)
  } finally {
    looking.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.panel {
  padding: 16px 18px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  gap: 12px;
  flex-wrap: wrap;
}

.panel-head .section-title {
  margin: 0;
}

.head-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.mt {
  margin-top: 12px;
}

.db-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 14px;
  margin: 14px 0;
}

.db-item {
  border: 1px solid #eef0f4;
  border-radius: 8px;
  padding: 12px 14px;
  background: #fcfdff;
}

.db-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}

.db-name {
  font-size: 13.5px;
  font-weight: 500;
}

.db-desc {
  margin-bottom: 10px;
}

.db-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 10px;
  flex-wrap: wrap;
}

.upload-inner {
  font-size: 13px;
  color: #5a6472;
}

.upload-inner em {
  color: #2f6fed;
  font-style: normal;
}

.filters {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
}

.result-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
}

.block-title {
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 8px;
  color: #1f2329;
}

:deep(.el-descriptions__label) {
  width: 110px;
}

:deep(.el-upload-dragger) {
  padding: 24px 16px;
}

:deep(.el-form-item) {
  margin-bottom: 16px;
}
</style>
