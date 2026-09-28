use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::crypto::DbEncryptor;
use crate::entities::{telegram_audit_events, telegram_settings};
use chrono::Utc;
use log::warn;
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use reqwest::Client;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use serde_json::Value;
use std::{env, time::Duration};
use uuid::Uuid;

const SETTINGS_ID: i16 = 1;

pub struct TelegramApi {
    pub db: DatabaseConnection,
}

#[derive(Object)]
pub struct TelegramSettingsDto {
    pub has_token: bool,
    pub chat_id: Option<String>,
}

#[derive(Object)]
pub struct SaveTelegramSettingsRequest {
    /// Omit or leave empty to keep the saved token. Tokens are never returned by GET.
    pub bot_token: Option<String>,
    pub chat_id: Option<String>,
    pub clear_chat_id: Option<bool>,
}

#[derive(Object)]
pub struct DetectTelegramChatRequest {
    /// Optional unsaved token; otherwise the saved token (or legacy env token) is used.
    pub bot_token: Option<String>,
}

#[derive(Object)]
pub struct DetectTelegramChatDto {
    pub chat_id: String,
}

#[derive(Object)]
pub struct TestTelegramRequest {
    pub bot_token: Option<String>,
    pub chat_id: String,
}

#[derive(Object)]
pub struct TelegramResultDto {
    pub message: String,
}

#[derive(ApiResponse)]
pub enum TelegramSettingsResponse {
    #[oai(status = 200)]
    Ok(Json<TelegramSettingsDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum TelegramSaveResponse {
    #[oai(status = 200)]
    Ok(Json<TelegramSettingsDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum TelegramDetectResponse {
    #[oai(status = 200)]
    Ok(Json<DetectTelegramChatDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NoUpdates(Json<String>),
    #[oai(status = 502)]
    TelegramError(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum TelegramTestResponse {
    #[oai(status = 200)]
    Ok(Json<TelegramResultDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 502)]
    TelegramError(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[OpenApi]
impl TelegramApi {
    #[oai(path = "/telegram/settings", method = "get")]
    async fn get_settings(&self, auth: AdminToken) -> TelegramSettingsResponse {
        if let Err(reason) = validate_admin_session(&self.db, &auth.0.token).await {
            return TelegramSettingsResponse::Unauthorized(Json(reason));
        }
        match telegram_settings::Entity::find_by_id(SETTINGS_ID)
            .one(&self.db)
            .await
        {
            Ok(row) => TelegramSettingsResponse::Ok(Json(TelegramSettingsDto {
                has_token: row.as_ref().is_some_and(|s| {
                    s.bot_token_ciphertext
                        .as_ref()
                        .is_some_and(|v| !v.is_empty())
                }) || env::var("TELEGRAM_BOT_TOKEN").is_ok_and(|v| !v.trim().is_empty()),
                chat_id: row.and_then(|s| s.chat_id),
            })),
            Err(_) => TelegramSettingsResponse::Error(Json(
                "Не удалось загрузить настройки Telegram".into(),
            )),
        }
    }

    #[oai(path = "/telegram/settings", method = "put")]
    async fn save_settings(
        &self,
        auth: AdminToken,
        req: Json<SaveTelegramSettingsRequest>,
    ) -> TelegramSaveResponse {
        let admin_id = match validate_admin_session(&self.db, &auth.0.token).await {
            Ok(id) => id,
            Err(reason) => return TelegramSaveResponse::Unauthorized(Json(reason)),
        };
        if let Some(token) = req.0.bot_token.as_deref().filter(|s| !s.trim().is_empty()) {
            if !valid_bot_token(token.trim()) {
                return TelegramSaveResponse::BadRequest(Json(
                    "Проверьте формат токена Telegram-бота".into(),
                ));
            }
        }
        if req
            .0
            .chat_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && !req.0.clear_chat_id.unwrap_or(false)
            && !valid_chat_id(req.0.chat_id.as_deref().unwrap_or_default().trim())
        {
            return TelegramSaveResponse::BadRequest(Json(
                "Chat ID должен быть числом (для группы обычно начинается с -100)".into(),
            ));
        }

        match persist_settings(&self.db, &req.0, admin_id).await {
            Ok(()) => {
                record_audit(&self.db, admin_id, "save", "ok").await;
                self.load_settings().await
            }
            Err(()) => {
                record_audit(&self.db, admin_id, "save", "failed").await;
                TelegramSaveResponse::Error(Json("Не удалось сохранить настройки Telegram".into()))
            }
        }
    }

    #[oai(path = "/telegram/detect-chat", method = "post")]
    async fn detect_chat(
        &self,
        auth: AdminToken,
        req: Json<DetectTelegramChatRequest>,
    ) -> TelegramDetectResponse {
        let admin_id = match validate_admin_session(&self.db, &auth.0.token).await {
            Ok(id) => id,
            Err(reason) => return TelegramDetectResponse::Unauthorized(Json(reason)),
        };
        let token = match resolve_bot_token(&self.db, req.0.bot_token.as_deref()).await {
            Ok(token) => token,
            Err(()) => {
                record_audit(&self.db, admin_id, "detect_chat", "no_token").await;
                return TelegramDetectResponse::BadRequest(Json(
                    "Сначала введите и сохраните токен бота".into(),
                ));
            }
        };
        match detect_chat_id(&token).await {
            Ok(Some(chat_id)) => {
                record_audit(&self.db, admin_id, "detect_chat", "found").await;
                TelegramDetectResponse::Ok(Json(DetectTelegramChatDto { chat_id }))
            }
            Ok(None) => {
                record_audit(&self.db, admin_id, "detect_chat", "no_updates").await;
                TelegramDetectResponse::NoUpdates(Json(
                    "У бота пока нет сообщений. Откройте бота, отправьте /start и повторите поиск."
                        .into(),
                ))
            }
            Err(()) => {
                record_audit(&self.db, admin_id, "detect_chat", "telegram_error").await;
                TelegramDetectResponse::TelegramError(Json("Не удалось получить обновления Telegram. Проверьте токен и отключите webhook, если он настроен.".into()))
            }
        }
    }

    #[oai(path = "/telegram/test", method = "post")]
    async fn test(&self, auth: AdminToken, req: Json<TestTelegramRequest>) -> TelegramTestResponse {
        let admin_id = match validate_admin_session(&self.db, &auth.0.token).await {
            Ok(id) => id,
            Err(reason) => return TelegramTestResponse::Unauthorized(Json(reason)),
        };
        let chat_id = req.0.chat_id.trim();
        if !valid_chat_id(chat_id) {
            return TelegramTestResponse::BadRequest(Json("Укажите корректный Chat ID".into()));
        }

        // Save first, matching s-ui-x: a failed send does not discard edited settings.
        let save_req = SaveTelegramSettingsRequest {
            bot_token: req.0.bot_token.clone(),
            chat_id: Some(chat_id.to_string()),
            clear_chat_id: Some(false),
        };
        if let Some(token) = req.0.bot_token.as_deref().filter(|s| !s.trim().is_empty()) {
            if !valid_bot_token(token.trim()) {
                return TelegramTestResponse::BadRequest(Json(
                    "Проверьте формат токена Telegram-бота".into(),
                ));
            }
        }
        if persist_settings(&self.db, &save_req, admin_id)
            .await
            .is_err()
        {
            record_audit(&self.db, admin_id, "test", "save_failed").await;
            return TelegramTestResponse::Error(Json(
                "Не удалось сохранить настройки Telegram".into(),
            ));
        }
        record_audit(&self.db, admin_id, "save_before_test", "ok").await;

        let token = match resolve_bot_token(&self.db, None).await {
            Ok(token) => token,
            Err(()) => {
                record_audit(&self.db, admin_id, "test", "no_token").await;
                return TelegramTestResponse::BadRequest(Json("Сначала введите токен бота".into()));
            }
        };
        match send_test_message(&token, chat_id).await {
            Ok(()) => {
                record_audit(&self.db, admin_id, "test", "delivered").await;
                TelegramTestResponse::Ok(Json(TelegramResultDto {
                    message: "Тестовое сообщение отправлено".into(),
                }))
            }
            Err(()) => {
                record_audit(&self.db, admin_id, "test", "telegram_error").await;
                TelegramTestResponse::TelegramError(Json("Telegram не принял тестовое сообщение. Проверьте токен, Chat ID и доступ бота к переписке.".into()))
            }
        }
    }
}

impl TelegramApi {
    async fn load_settings(&self) -> TelegramSaveResponse {
        match telegram_settings::Entity::find_by_id(SETTINGS_ID)
            .one(&self.db)
            .await
        {
            Ok(row) => TelegramSaveResponse::Ok(Json(TelegramSettingsDto {
                has_token: row.as_ref().is_some_and(|s| {
                    s.bot_token_ciphertext
                        .as_ref()
                        .is_some_and(|v| !v.is_empty())
                }) || env::var("TELEGRAM_BOT_TOKEN").is_ok_and(|v| !v.trim().is_empty()),
                chat_id: row.and_then(|s| s.chat_id),
            })),
            Err(_) => {
                TelegramSaveResponse::Error(Json("Не удалось прочитать настройки Telegram".into()))
            }
        }
    }
}

pub async fn resolve_bot_token(
    db: &DatabaseConnection,
    override_token: Option<&str>,
) -> Result<String, ()> {
    if let Some(token) = override_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        return if valid_bot_token(token) {
            Ok(token.to_string())
        } else {
            Err(())
        };
    }
    if let Ok(Some(row)) = telegram_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await
    {
        if let Some(ciphertext) = row.bot_token_ciphertext.filter(|s| !s.is_empty()) {
            return DbEncryptor::new().decrypt(&ciphertext).map_err(|_| ());
        }
    }
    env::var("TELEGRAM_BOT_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| valid_bot_token(token))
        .ok_or(())
}

async fn persist_settings(
    db: &DatabaseConnection,
    request: &SaveTelegramSettingsRequest,
    _admin_id: Uuid,
) -> Result<(), ()> {
    let existing = telegram_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await
        .map_err(|_| ())?;
    let token_ciphertext = match request
        .bot_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(token) => Some(DbEncryptor::new().encrypt(token).map_err(|_| ())?),
        None => existing
            .as_ref()
            .and_then(|row| row.bot_token_ciphertext.clone()),
    };
    let chat_id = if request.clear_chat_id.unwrap_or(false) {
        None
    } else {
        request
            .chat_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| existing.as_ref().and_then(|row| row.chat_id.clone()))
    };
    let now = Utc::now().naive_utc();
    let active = telegram_settings::ActiveModel {
        id: Set(SETTINGS_ID),
        bot_token_ciphertext: Set(token_ciphertext),
        chat_id: Set(chat_id),
        updated_at: Set(now),
    };
    if existing.is_some() {
        active.update(db).await.map_err(|_| ())?;
    } else {
        active.insert(db).await.map_err(|_| ())?;
    }
    Ok(())
}

pub(crate) async fn record_audit(
    db: &DatabaseConnection,
    admin_id: Uuid,
    action: &str,
    outcome: &str,
) {
    let record = telegram_audit_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        admin_id: Set(admin_id),
        action: Set(action.to_string()),
        outcome: Set(outcome.to_string()),
        created_at: Set(Utc::now().naive_utc()),
    };
    if record.insert(db).await.is_err() {
        warn!(
            "[telegram.audit] could not persist action={} outcome={}",
            action, outcome
        );
    }
}

fn valid_bot_token(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 20
        && id.bytes().all(|b| b.is_ascii_digit())
        && (20..=256).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn valid_chat_id(chat_id: &str) -> bool {
    !chat_id.is_empty()
        && chat_id.len() <= 24
        && chat_id
            .strip_prefix('-')
            .unwrap_or(chat_id)
            .bytes()
            .all(|b| b.is_ascii_digit())
}

fn api_url(token: &str, method: &str) -> String {
    format!("https://api.telegram.org/bot{token}/{method}")
}

async fn detect_chat_id(token: &str) -> Result<Option<String>, ()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| ())?;
    let response = client
        .get(api_url(token, "getUpdates"))
        .query(&[("limit", "100"), ("timeout", "0")])
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let payload: Value = response.json().await.map_err(|_| ())?;
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(());
    }
    let updates = payload.get("result").and_then(Value::as_array).ok_or(())?;
    let mut matches: Vec<(i64, String)> = updates
        .iter()
        .filter_map(|update| {
            let update_id = update.get("update_id")?.as_i64().unwrap_or_default();
            [
                "message",
                "edited_message",
                "channel_post",
                "edited_channel_post",
                "my_chat_member",
                "chat_member",
                "business_message",
            ]
            .iter()
            .find_map(|key| update.get(*key)?.get("chat")?.get("id")?.as_i64())
            .map(|id| (update_id, id.to_string()))
        })
        .collect();
    matches.sort_by_key(|(update_id, _)| *update_id);
    Ok(matches.pop().map(|(_, chat_id)| chat_id))
}

pub(crate) async fn send_message(token: &str, chat_id: &str, text: &str) -> Result<(), ()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| ())?;
    let response = client
        .post(api_url(token, "sendMessage"))
        .json(&serde_json::json!({ "chat_id": chat_id, "text": text }))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let payload: Value = response.json().await.map_err(|_| ())?;
    if payload.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(())
    }
}

async fn send_test_message(token: &str, chat_id: &str) -> Result<(), ()> {
    send_message(
        token,
        chat_id,
        "ANet VPN: тестовое сообщение из панели управления.",
    )
    .await
}
