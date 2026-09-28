import { api } from './client'

export type TelegramSettings = {
  has_token: boolean
  chat_id: string | null
}

export async function GetTelegramSettings() {
  return api<TelegramSettings>('/telegram/settings')
}

export async function SaveTelegramSettings(data: {
  bot_token?: string
  chat_id?: string
  clear_chat_id?: boolean
}) {
  return api<TelegramSettings>('/telegram/settings', { method: 'PUT', data })
}

export async function DetectTelegramChat(bot_token?: string) {
  return api<{ chat_id: string }>('/telegram/detect-chat', {
    method: 'POST',
    data: { bot_token: bot_token || undefined },
  })
}

export async function TestTelegramSettings(data: { bot_token?: string; chat_id: string }) {
  return api<{ message: string }>('/telegram/test', { method: 'POST', data })
}
