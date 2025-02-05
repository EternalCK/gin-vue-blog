<script setup lang="ts">
import { convertImgUrl, getToken } from '@/utils'

const props = defineProps({
  preview: {
    type: String,
    default: '',
  },
  width: {
    type: Number,
    default: 120,
  },
})

const emit = defineEmits(['finish'])

const token = getToken() // 图片上传需要 Token
let previewImg = $ref(props.preview)

// 上传图片
function handleImgUpload({ event }: { event?: ProgressEvent }) {
  const respStr = (event?.target as XMLHttpRequest).response
  const res = JSON.parse(respStr)
  if (res.code !== 0) {
    window.$message?.error(res.message)
    return
  }
  previewImg = res.data
  emit('finish', previewImg)
}

// 判断是本地上传的图片或网络资源
// 开发环境可以使用本地文件上传, 生产环境建议使用云存储
const imgUrl = computed(() => convertImgUrl(previewImg))

defineExpose({ previewImg })
</script>

<template>
  <div>
    <!-- 如果文件上传需要登录, 注意 headers -->
    <n-upload
      action="/api/front/upload"
      :headers="{ Authorization: `Bearer ${token}` }"
      @finish="handleImgUpload"
    >
      <template v-if="previewImg">
        <img
          border-dashed border-2 border-color="#d9d9d9" rounded-2rem
          cursor-pointer hover:border-color-lightblue
          :style="{ width: `${props.width}px` }"
          :src="imgUrl" alt="文章封面"
        >
      </template>
      <template v-else>
        <n-upload-dragger>
          <div mb-12>
            <n-icon size="58" :depth="3">
              <i-mdi:upload />
            </n-icon>
          </div>
          <n-text text-14>
            点击或者拖动文件到该区域来上传
          </n-text>
        </n-upload-dragger>
      </template>
    </n-upload>
  </div>
</template>
