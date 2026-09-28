<script setup lang="ts">
import { watch, computed, ref } from 'vue'
import { useAppMessage } from '@/composables/useAppMessage'

import UserForm from './UserForm.vue'
import RateEditForm from './RateEditForm.vue'
import RateCreateForm from './RateCreateForm.vue'

import { useUser } from '@/composables/useUser'
import { useRate } from '@/composables/useRate'
import { SendTelegramLinks } from '@/api/users'

const show = defineModel<boolean>()

const props = defineProps<{
  userId: string
}>()

const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const { user, loading, regenerating, loadUser, saveUser, regenerate } = useUser()
const { saving, saveRate, createRate } = useRate(user)

const message = useAppMessage()
const telegramSending = ref(false)
const DEFAULT_PUBLIC_PANEL_URL = 'https://anet.vpn-rus.top'

const panelBaseUrl = (() => {
  const configured = import.meta.env.VITE_PANEL_PUBLIC_URL?.trim()
  if (!configured) return DEFAULT_PUBLIC_PANEL_URL
  try {
    const url = new URL(configured)
    const localHost = url.hostname === 'localhost'
      || url.hostname.endsWith('.localhost')
      || url.hostname === '127.0.0.1'
      || url.hostname === '[::1]'
      || url.hostname === '::1'
    return url.protocol === 'https:' && !localHost
      ? configured.replace(/\/+$/, '')
      : DEFAULT_PUBLIC_PANEL_URL
  } catch {
    return DEFAULT_PUBLIC_PANEL_URL
  }
})()

// Прямая ссылка на скачивание client.toml
const directConfigLink = computed(() => {
  if (!user.value) return ''
  return `${panelBaseUrl}/api/v1/config/${user.value.id}`
})

// Ссылка на веб-страницу со стильным QR-кодом
const qrPageLink = computed(() => {
  if (!user.value) return ''
  return `${panelBaseUrl}/api/v1/config/qr/${user.value.id}`
})

const copyToClipboard = (text: string, successMessage: string) => {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
        .then(() => message.success(successMessage))
        .catch(() => message.error('Failed to copy link.'))
  } else {
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.left = '-9999px'
    textArea.style.top = '-9999px'
    document.body.appendChild(textArea)
    textArea.focus()
    textArea.select()
    try {
      if (document.execCommand('copy')) {
        message.success(successMessage)
      } else {
        message.error('Failed to copy link.')
      }
    } catch (err) {
      message.error('Failed to copy link.')
    }
    document.body.removeChild(textArea)
  }
}

const copyDirectLink = () => {
  if (!directConfigLink.value) return
  copyToClipboard(directConfigLink.value, 'Прямая ссылка на client.toml скопирована!')
}

const copyQrPageLink = () => {
  if (!qrPageLink.value) return
  copyToClipboard(qrPageLink.value, 'Ссылка на страницу с QR-кодом скопирована!')
}

const sendTelegramLinks = async () => {
  if (!user.value?.id) return
  if (!user.value.telegram_chat_id?.trim()) {
    message.error('Укажите Telegram chat ID клиента и сохраните профиль перед отправкой')
    return
  }
  telegramSending.value = true
  try {
    await saveUser()
    await SendTelegramLinks(user.value.id)
    message.success('Конфигурация и ссылка на загрузку отправлены в Telegram')
  } catch (error: any) {
    message.error(error?.response?.data || 'Не удалось отправить сообщение в Telegram')
  } finally {
    telegramSending.value = false
  }
}

watch(
    () => props.userId,
    (id) => {
      // Пустая строка — модалка закрыта, пользователя не загружаем
      if (id) loadUser(id)
    },
    { immediate: true },
)

const close = () => {
  show.value = false
  user.value = null
  emit('close')
}

const handleSaveUser = async () => {
  await saveUser()
  emit('updated')
  close()
}
</script>

<template>
  <v-dialog
      v-model="show"
      scrollable
      @update:modelValue="close"
      max-width="900px"
  >
    <v-card class="pa-6 d-flex flex-column" style="max-height: 85vh;">
      <v-card-title class="text-h6 px-0 pb-4 flex-shrink-0">
        Редактировать пользователя
      </v-card-title>
      <!-- Кнопка прямого скачивания файла (Фокусируется и нажимается с пульта) -->
      <v-btn
          :href="directConfigLink"
          download
          color="success"
          variant="flat"
          block
          prepend-icon="mdi-download"
          class="mb-4"
      >
        Скачать client.toml на устройство
      </v-btn>
      <v-card-text class="px-0 flex-grow-1" style="overflow-y: auto;">
        <!-- Форма юзера -->
        <UserForm v-if="user" v-model="user" />

        <div v-if="user" class="mt-4">
          <RateEditForm v-if="user?.rate" v-model="user" @save="saveRate" />
          <RateCreateForm v-else @create="createRate" />
        </div>

        <!-- КОМПАКТНЫЙ БЛОК ДЛЯ ССЫЛОК И ШЕРИНГА -->
        <v-card v-if="user" variant="outlined" class="mt-6 pa-4">
          <div class="text-subtitle-2 mb-3">🔗 Получить конфигурацию</div>

          <!-- Ссылка для копирования (оставляем как резервный вариант) -->
          <v-text-field
              readonly
              :model-value="directConfigLink"
              label="Прямая ссылка на скачивание client.toml"
              variant="filled"
              density="compact"
              hide-details
              class="link-field mb-3"
          >
            <template #append>
              <v-btn color="primary" variant="tonal" @click="copyDirectLink">Copy</v-btn>
            </template>
          </v-text-field>

          <v-text-field
              v-model="user.telegram_chat_id"
              label="Telegram chat ID клиента"
              hint="Введите числовой ID клиента (его можно узнать у @userinfobot); клиент должен открыть этот бот и нажать Start"
              persistent-hint
              inputmode="numeric"
              variant="outlined"
              density="compact"
              class="mt-4"
          />
          <v-btn
              color="primary"
              variant="tonal"
              block
              prepend-icon="mdi-send"
              :disabled="!user.telegram_chat_id"
              :loading="telegramSending"
              @click="sendTelegramLinks"
          >
            Отправить конфигурацию и ссылку на обновление в Telegram
          </v-btn>

          <v-text-field
              readonly
              :model-value="qrPageLink"
              label="Ссылка на веб-страницу с QR-кодом"
              variant="filled"
              density="compact"
              hide-details
              class="link-field"
          >
            <template #append>
              <v-btn color="info" variant="tonal" @click="copyQrPageLink">Copy</v-btn>
            </template>
          </v-text-field>
        </v-card>
      </v-card-text>

      <v-divider class="my-4 flex-shrink-0" />

      <v-card-actions class="px-0 pb-0 justify-space-between flex-shrink-0">
        <v-btn color="warning" variant="text" :loading="regenerating" @click="regenerate">
          Regenerate Keys
        </v-btn>

        <div class="d-flex ga-2">
          <v-btn variant="text" @click="close">Close</v-btn>
          <v-btn color="primary" variant="flat" @click="handleSaveUser">Save User</v-btn>
        </div>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.link-field :deep(input) { font-family: 'Fira Code', monospace; font-size: 13px; }
</style>
