<template>
  <el-pagination
    v-model:current-page="page"
    v-model:page-size="size"
    :total="total"
    :page-sizes="PAGE_SIZES"
    :layout="PAGER_LAYOUT"
    hide-on-single-page
    class="table-pager"
    @size-change="onSizeChange"
    @current-change="fire"
  />
</template>

<script setup lang="ts">
// 全站统一的表格分页器。
//
// 抽成组件而不是在每个页面各写一遍：总数、条数选项、跳页框这几样必须处处一致，
// 各写各的就会出现「这个页面能选 100 条、那个页面只能选 50」这种问题。
//
// hide-on-single-page：只有一页时整个分页器收起来。概览页那两个 Top 榜和后端
// 的 Top 10 一样是固定条数，永远只有一页 —— 不收起来就是在卡片里白占一行，
// 摆一个「共 10 条、每页 20 条」的控件，既没用又挤。
import { nextTick } from 'vue'
import { PAGE_SIZES, PAGER_LAYOUT } from '@/utils/table'

defineProps<{ total: number }>()
const emit = defineEmits<{ change: [] }>()

const page = defineModel<number>('page', { required: true })
const size = defineModel<number>('size', { required: true })

// 同一轮里合并成一次回调：改每页条数时 Element Plus 会先更新 page-size，
// 再因为我们把 current-page 置回 1 而补抛一个 current-change —— 两次都放出去
// 就是两次重复请求。
let pending = false
function fire() {
  if (pending) return
  pending = true
  nextTick(() => {
    pending = false
  })
  emit('change')
}

// 改条数必须回到第 1 页：留在原页的话，原本停在第 5 页、条数从 20 调到 100，
// 总页数可能只剩 2 页，用户就停在一个不存在的页码上，看到一张空表却没有任何提示。
function onSizeChange() {
  page.value = 1
  fire()
}
</script>

<style scoped>
.table-pager {
  margin-top: 14px;
  justify-content: flex-end;
}
</style>
