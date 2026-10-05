use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(
            "ALTER TABLE servers ADD COLUMN crypto_algorithm TEXT NOT NULL DEFAULT 'chacha20-poly1305' CHECK (crypto_algorithm IN ('chacha20-poly1305', 'kuznyechik-mgm'))",
        ).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE servers DROP COLUMN crypto_algorithm")
            .await?;
        Ok(())
    }
}
