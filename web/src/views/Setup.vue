<template>
  <div class="setup-page">
    <div class="card">
      <div class="head">
        <div class="title">初始化 FrpFireWall</div>
        <div class="sub">设置面板密码后即可使用</div>
      </div>

      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="初始化令牌">
          <el-input
            v-model="form.token"
            size="large"
            placeholder="启动时打印的令牌"
          />
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="form.username" size="large" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="form.password"
            size="large"
            type="password"
            show-password
            placeholder="至少 8 位"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="form.confirm"
            size="large"
            type="password"
            show-password
            @keyup.enter="submit"
          />
        </el-form-item>

        <el-button
          type="primary"
          size="large"
          style="width: 100%"
          :loading="loading"
          @click="submit"
        >
          完成初始化
        </el-button>
      </el-form>

      <div class="note">
        令牌在首次启动时打印到控制台，同时保存在数据目录的
        <span class="mono">setup_token.txt</span>，设置完成后即作废。
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { markInitialized } from '@/router'
import { markGuidePending } from '@/utils/guide'

const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const form = reactive({ token: '', username: 'admin', password: '', confirm: '' })

async function submit() {
  if (!form.token.trim()) {
    ElMessage.warning('请填写初始化令牌')
    return
  }
  if (form.password.length < 8) {
    ElMessage.warning('密码至少 8 位')
    return
  }
  if (form.password !== form.confirm) {
    ElMessage.warning('两次输入的密码不一致')
    return
  }

  loading.value = true
  try {
    await auth.setup({
      token: form.token.trim(),
      username: form.username.trim() || 'admin',
      password: form.password,
    })
    markInitialized()
    // 进主框架后自动弹一次教学引导（标记由 MainLayout 消费）
    markGuidePending()
    ElMessage.success('初始化完成')
    router.push('/dashboard')
  } catch {
    // 错误提示由拦截器统一处理
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.setup-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f7fa;
  padding: 24px 0;
}

.card {
  width: 420px;
  background: #fff;
  border: 1px solid #e9ecf2;
  border-radius: 12px;
  padding: 32px 32px 24px;
}

.head {
  margin-bottom: 20px;
}

.title {
  font-size: 19px;
  font-weight: 500;
}

.sub {
  font-size: 12.5px;
  color: #8a919f;
  margin-top: 6px;
}

.note {
  margin-top: 16px;
  font-size: 12px;
  line-height: 1.7;
  color: #8a919f;
}
</style>
