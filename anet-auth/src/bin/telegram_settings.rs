use anet_auth::{api::telegram::TelegramApi, migration::Migrator};
use log::info;
use poem::{Route, Server, listener::TcpListener};
use poem_openapi::OpenApiService;
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter(Some("sqlx"), log::LevelFilter::Warn)
        .init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = Database::connect(&database_url).await?;
    // Idempotent migration adds Telegram settings/audit storage to the existing DB.
    Migrator::up(&db, None).await?;

    let bind_to = env::var("TELEGRAM_BIND_TO").unwrap_or_else(|_| "0.0.0.0:3001".into());
    let api_service = OpenApiService::new(TelegramApi { db }, "ANet Telegram Settings API", "1.0");
    let app = Route::new().nest("/api/v1", api_service);

    info!("ANet Telegram settings API started on {}", bind_to);
    Server::new(TcpListener::bind(&bind_to)).run(app).await?;
    Ok(())
}
