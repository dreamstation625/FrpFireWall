<template>
  <div class="login-page">
    <div class="card">
      <div class="head">
        <div class="title">FrpFireWall</div>
        <div class="sub">frps 服务端防火墙</div>
      </div>

      <el-form @submit.prevent="submit">
        <el-form-item>
          <el-input
            v-model="form.username"
            size="large"
            placeholder="用户名"
            :prefix-icon="User"
          />
        </el-form-item>
        <el-form-item>
          <el-input
            v-model="form.password"
            size="large"
            type="password"
            show-password
            placeholder="密码"
            :prefix-icon="Lock"
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
          登录
        </el-button>
      </el-form>

      <div class="note">
        忘记密码：把数据库 settings 表里的
        <span class="mono">admin_password_hash</span> 置空后重启，可重新初始化。
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Lock, User } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const form = reactive({ username: 'admin', password: '' })

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    router.push('/dashboard')
  } catch {
    // 错误提示由拦截器统一处理
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f7fa;
}

.card {
  width: 380px;
  background: #fff;
  border: 1px solid #e9ecf2;
  border-radius: 12px;
  padding: 36px 32px 28px;
}

.head {
  margin-bottom: 24px;
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
  margin-top: 18px;
  font-size: 12px;
  line-height: 1.7;
  color: #8a919f;
}
</style>
