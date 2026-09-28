use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE IF NOT EXISTS telegram_link_requests (\
                    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,\
                    token_hash TEXT NOT NULL,\
                    expires_at TIMESTAMP NOT NULL\
                );\
                CREATE INDEX IF NOT EXISTS telegram_link_requests_expires_at_idx \
                    ON telegram_link_requests (expires_at);",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS telegram_link_requests;")
            .await?;
        Ok(())
    }
}
