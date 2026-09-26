<script setup lang="ts">
import { ref } from 'vue'
import { CreateServer } from '@/api/servers'
import type { CreateServerRequest } from '@/models/server'

// Используем дефолтный v-model для управления видимостью окна
const show = defineModel<boolean>()

const emit = defineEmits<{
  (e: 'created'): void
  (e: 'close'): void
}>()

const loading = ref(false)

// Функция для сброса формы к значениям по умолчанию
const defaultForm = (): CreateServerRequest => ({
  name: '',
  address: '',
  public_key: '',
  crypto_algorithm: 'chacha20-poly1305',
  ssh_user: null,
  is_active: true,
  quic_port: null,
  ssh_port: null,
  vnc_port: null,
  websocket_url: null,
  ahttp_url: null,
})

const form = ref<CreateServerRequest>(defaultForm())

const normalizePort = (value: unknown): number | null => value === '' || value == null ? null : Number(value)

const handleCreate = async () => {
  if (!form.value.name.trim() || !form.value.address.trim() || !form.value.public_key.trim()) {
    alert('Укажите название, адрес и публичный ключ сервера')
    return
  }
  const payload: CreateServerRequest = {
    ...form.value,
    quic_port: normalizePort(form.value.quic_port),
    ssh_port: normalizePort(form.value.ssh_port),
    vnc_port: normalizePort(form.value.vnc_port),
    websocket_url: form.value.websocket_url?.trim() || null,
    ahttp_url: form.value.ahttp_url?.trim() || null,
    ssh_user: form.value.ssh_user?.trim() || null,
  }
  const ports = [payload.quic_port, payload.ssh_port, payload.vnc_port]
  if (ports.some(port => port != null && (!Number.isInteger(port) || port < 1 || port > 65535))) {
    alert('Порт должен быть целым числом от 1 до 65535')
    return
  }
  if (!ports.some(port => port != null)
      && !payload.websocket_url && !payload.ahttp_url) {
    alert('Укажите хотя бы один порт или URL транспорта')
    return
  }
  loading.value = true
  try {
    await CreateServer(payload)
    form.value = defaultForm() // Сбрасываем форму после успеха
    emit('created')            // Сообщаем родителю, что надо обновить список
    show.value = false         // Закрываем модалку
  } catch (error: any) {
    console.error('Ошибка при создании сервера:', error)
    if (error.response?.data) {
      alert(`Ошибка: ${error.response.data}`)
    } else {
      alert('Произошла ошибка при создании сервера')
    }
  } finally {
    loading.value = false
  }
}

const close = () => {
  show.value = false
  emit('close')
}
</script>

<template>
  <v-dialog v-model="show" @update:model-value="close" max-width="650px">
    <!-- Обертка v-card задаст правильный фон и структуру модального окна -->
    <v-card>
      <v-card-title class="text-h6 pb-4">
        Добавить физический сервер
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field
              v-model="form.name"
              label="Название локации"
              placeholder="e.g. Germany VPS 1"
              variant="filled"
              class="mb-3"
          />

          <!-- Изменили поле DSN на "IP Адрес или Домен" -->
          <v-text-field
              v-model="form.address"
              label="IP Адрес или Домен"
              placeholder="e.g. 64.188.118.201 или vpn.ziga.com"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.public_key"
              label="Публичный ключ сервера (server_pub_key)"
              placeholder="Из утилиты anet-keygen"
              variant="filled"
              class="mb-3"
          />

          <v-select
              v-model="form.crypto_algorithm"
              label="Алгоритм шифрования"
              :items="[{ title: 'ChaCha20-Poly1305', value: 'chacha20-poly1305' }, { title: 'ГОСТ Кузнечик-MGM', value: 'kuznyechik-mgm' }]"
              variant="filled"
              class="mb-3"
          />

          <!-- Размещаем порты side-by-side с числовой валидацией -->
          <v-row class="mb-1">
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.quic_port"
                  type="number"
                  label="QUIC Port (UDP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.ssh_port"
                  type="number"
                  label="SSH Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.vnc_port"
                  type="number"
                  label="VNC Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-text-field
              v-model="form.websocket_url"
              label="WebSocket URL"
              placeholder="ws://127.0.0.1:8080/s"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.ahttp_url"
              label="AHTTP URL (CDN)"
              placeholder="https://your-cdn.some-host.net/api/v2/telemetry"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.ssh_user"
              label="Пользователь SSH (ssh_user)"
              placeholder="hanyuu"
              variant="filled"
              class="mb-3"
          />

          <v-switch
              v-model="form.is_active"
              label="Активен (ВКЛ)"
              color="success"
              class="mb-2"
          />
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Cancel</v-btn>
        <v-btn color="primary" variant="flat" :loading="loading" @click="handleCreate">
          Add Node
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
