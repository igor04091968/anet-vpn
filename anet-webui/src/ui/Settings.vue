<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  DetectTelegramChat,
  GetTelegramSettings,
  SaveTelegramSettings,
  TestTelegramSettings,
  type TelegramSettings,
} from '@/api/telegram'
import { useAppMessage } from '@/composables/useAppMessage'

const message = useAppMessage()
const settings = ref<TelegramSettings>({ has_token: false, chat_id: null })
const botToken = ref('')
const chatId = ref('')
const loading = ref(true)
const saving = ref(false)
const detecting = ref(false)
const testing = ref(false)

const errorText = (error: unknown, fallback: string) => {
  const e = error as { response?: { data?: unknown }; message?: string }
  if (typeof e.response?.data === 'string') return e.response.data
  return error instanceof Error ? error.message : fallback
}

const loadSettings = async () => {
  loading.value = true
  try {
    settings.value = await GetTelegramSettings()
    chatId.value = settings.value.chat_id || ''
  } catch (error) {
    message.error(errorText(error, 'Не удалось загрузить настройки Telegram'))
  } finally {
    loading.value = false
  }
}

const save = async () => {
  saving.value = true
  try {
    settings.value = await SaveTelegramSettings({
      bot_token: botToken.value.trim() || undefined,
      chat_id: chatId.value.trim() || undefined,
      clear_chat_id: !chatId.value.trim(),
    })
    botToken.value = ''
    chatId.value = settings.value.chat_id || ''
    message.success('Настройки Telegram сохранены')
  } catch (error) {
    message.error(errorText(error, 'Не удалось сохранить настройки Telegram'))
  } finally {
    saving.value = false
  }
}

const detectChat = async () => {
  detecting.value = true
  try {
    const result = await DetectTelegramChat(botToken.value.trim() || undefined)
    chatId.value = result.chat_id
    message.success(`Chat ID найден: ${result.chat_id}`)
  } catch (error) {
    message.error(errorText(error, 'Не удалось определить Chat ID'))
  } finally {
    detecting.value = false
  }
}

const test = async () => {
  if (!chatId.value.trim()) {
    message.warning('Сначала укажите Chat ID или определите его через Telegram')
    return
  }
  testing.value = true
  try {
    // Backend persists edited values before calling Telegram.
    const result = await TestTelegramSettings({
      bot_token: botToken.value.trim() || undefined,
      chat_id: chatId.value.trim(),
    })
    settings.value = await GetTelegramSettings()
    botToken.value = ''
    chatId.value = settings.value.chat_id || chatId.value
    message.success(`${result.message}; настройки сохранены`)
  } catch (error) {
    // The backend deliberately saves settings before trying to send.
    botToken.value = ''
    await loadSettings()
    message.error(errorText(error, 'Telegram не принял тестовое сообщение'))
  } finally {
    testing.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <v-container max-width="900" class="settings-page">
    <div class="mb-5">
      <h1 class="text-h5 font-weight-bold">Настройки Telegram</h1>
      <p class="text-body-2 text-medium-emphasis mt-2">
        Бот используется для тестовых уведомлений и отправки клиентам ссылок на конфигурацию и обновление.
      </p>
    </div>

    <v-card variant="outlined" rounded="lg">
      <v-card-title class="text-h6">Telegram Bot</v-card-title>
      <v-card-text>
        <v-alert v-if="settings.has_token" type="success" variant="tonal" density="compact" class="mb-4">
          Токен настроен. Сохранённый токен не отображается в панели.
        </v-alert>
        <v-alert v-else type="warning" variant="tonal" density="compact" class="mb-4">
          Токен ещё не настроен.
        </v-alert>

        <v-text-field
          v-model="botToken"
          label="Токен Telegram-бота"
          :placeholder="settings.has_token ? 'Оставьте пустым, чтобы сохранить текущий токен' : '123456789:…'"
          type="password"
          autocomplete="new-password"
          variant="outlined"
          hint="Токен шифруется перед записью в базу данных и не возвращается браузеру."
          persistent-hint
          :disabled="loading"
          class="mb-5"
        />

        <v-text-field
          v-model="chatId"
          label="Chat ID"
          placeholder="Напишите /start боту, затем нажмите «Определить Chat ID»"
          variant="outlined"
          inputmode="numeric"
          hint="Для групп добавьте бота и отправьте сообщение; их Chat ID обычно начинается с -100."
          persistent-hint
          :disabled="loading"
          class="mb-3"
        />

        <div class="d-flex flex-wrap ga-3">
          <v-btn
            color="secondary"
            variant="tonal"
            prepend-icon="mdi-magnify"
            :loading="detecting"
            :disabled="loading || (!botToken.trim() && !settings.has_token)"
            @click="detectChat"
          >
            Определить Chat ID
          </v-btn>
          <v-btn
            color="primary"
            variant="flat"
            prepend-icon="mdi-content-save"
            :loading="saving"
            :disabled="loading"
            @click="save"
          >
            Сохранить
          </v-btn>
          <v-btn
            color="success"
            variant="tonal"
            prepend-icon="mdi-send-check"
            :loading="testing"
            :disabled="loading || !chatId.trim() || (!botToken.trim() && !settings.has_token)"
            @click="test"
          >
            Сохранить и отправить тест
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-container>
</template>

<style scoped>
.settings-page { padding: 24px; }
</style>
