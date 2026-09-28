use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT NULL;",
        )
        .await?;
        db.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS telegram_settings (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                bot_token_ciphertext TEXT NULL,
                chat_id TEXT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS telegram_audit_events (
                id UUID PRIMARY KEY,
                admin_id UUID NOT NULL,
                action VARCHAR(32) NOT NULL,
                outcome VARCHAR(32) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS telegram_audit_events_created_at_idx
                ON telegram_audit_events (created_at DESC);
            "#,
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            "DROP TABLE IF EXISTS telegram_audit_events; DROP TABLE IF EXISTS telegram_settings; ALTER TABLE users DROP COLUMN IF EXISTS telegram_chat_id;",
        )
        .await?;
        Ok(())
    }
}
