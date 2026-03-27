//! SQLite secret store backend.

use std::path::Path;

use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::store::{
    BatchUpdateItem, CipherAlgorithm, SecretKind, SecretMetadata, SecretStore, StoreSecretParams, StoredSecret,
};
use crate::types::{SecretId, SecretName};

/// SQLite-backed implementation of [`SecretStore`].
///
/// Stores encrypted secrets in a single SQLite database file. Suitable
/// for developer laptops and single-host deployments. All values are
/// opaque blobs—this layer never sees plaintext.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Open (or create) a SQLite store at the given path.
    ///
    /// Creates the database file and schema if they do not already exist.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        sqlx::query(include_str!("../../sql/sqlite_secrets.sql"))
            .execute(&pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl SecretStore for SqliteStore {
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret> {
        let id = SecretId::new();
        let now = Utc::now();
        let id_str = id.as_uuid().to_string();
        let name_str = params.name.as_str().to_string();
        let algorithm_str = serialize_algorithm(&params.algorithm);
        let kind_str = serialize_kind(&params.kind);
        let now_str = now.to_rfc3339();

        sqlx::query(
            "INSERT INTO secrets (id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
        )
        .bind(&id_str)
        .bind(&name_str)
        .bind(&params.ciphertext)
        .bind(&params.nonce)
        .bind(&algorithm_str)
        .bind(&kind_str)
        .bind(&params.description)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e && db_err.message().contains("UNIQUE constraint failed") {
                    return Error::SecretAlreadyExists(params.name.clone());
            }
            Error::Storage(format!("insert failed: {e}"))
        })?;

        Ok(StoredSecret {
            id,
            name: params.name,
            ciphertext: params.ciphertext,
            nonce: params.nonce,
            algorithm: params.algorithm,
            kind: params.kind,
            description: params.description,
            created_at: now,
            updated_at: now,
            version: 1,
        })
    }

    async fn get(&self, name: &SecretName) -> Result<StoredSecret> {
        let name_str = name.as_str().to_string();
        let row = sqlx::query(
            "SELECT id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version
             FROM secrets WHERE name = ?",
        )
        .bind(&name_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("query failed: {e}")))?
        .ok_or_else(|| Error::SecretNotFound(name.clone()))?;

        row_to_stored_secret(&row)
    }

    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret> {
        let name_str = name.as_str().to_string();
        let now_str = Utc::now().to_rfc3339();
        let algorithm_str = serialize_algorithm(&algorithm);

        let result = sqlx::query(
            "UPDATE secrets SET ciphertext = ?, nonce = ?, algorithm = ?, updated_at = ?, version = version + 1
             WHERE name = ?",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&algorithm_str)
        .bind(&now_str)
        .bind(&name_str)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("update failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(Error::SecretNotFound(name.clone()));
        }

        self.get(name).await
    }

    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Storage(format!("failed to begin transaction: {e}")))?;

        for item in &updates {
            let name_str = item.name.as_str().to_string();
            let now_str = Utc::now().to_rfc3339();
            let algorithm_str = serialize_algorithm(&item.algorithm);

            let result = sqlx::query(
                "UPDATE secrets SET ciphertext = ?, nonce = ?, algorithm = ?, updated_at = ?, version = version + 1 WHERE name = ?",
            )
            .bind(&item.ciphertext)
            .bind(&item.nonce)
            .bind(&algorithm_str)
            .bind(&now_str)
            .bind(&name_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Storage(format!("batch update failed: {e}")))?;

            if result.rows_affected() == 0 {
                return Err(Error::SecretNotFound(item.name.clone()));
            }
        }

        tx.commit()
            .await
            .map_err(|e| Error::Storage(format!("transaction commit failed: {e}")))?;

        Ok(())
    }

    async fn delete(&self, name: &SecretName) -> Result<()> {
        let name_str = name.as_str().to_string();
        let result = sqlx::query("DELETE FROM secrets WHERE name = ?")
            .bind(&name_str)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("delete failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(Error::SecretNotFound(name.clone()));
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<SecretMetadata>> {
        let rows = sqlx::query("SELECT id, name, kind, description, created_at, updated_at, version FROM secrets")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("list query failed: {e}")))?;

        let mut result = Vec::with_capacity(rows.len());
        for row in &rows {
            let id_str: String = row.try_get("id").map_err(|e| Error::Storage(e.to_string()))?;
            let id_uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
            let name_str: String = row.try_get("name").map_err(|e| Error::Storage(e.to_string()))?;
            let kind_str: String = row.try_get("kind").map_err(|e| Error::Storage(e.to_string()))?;
            let description: Option<String> = row.try_get("description").map_err(|e| Error::Storage(e.to_string()))?;
            let created_at_str: String = row.try_get("created_at").map_err(|e| Error::Storage(e.to_string()))?;
            let updated_at_str: String = row.try_get("updated_at").map_err(|e| Error::Storage(e.to_string()))?;
            let version: i32 = row.try_get("version").map_err(|e| Error::Storage(e.to_string()))?;

            result.push(SecretMetadata {
                id: SecretId::from_uuid(id_uuid),
                name: SecretName::new(name_str),
                kind: deserialize_kind(&kind_str)?,
                description,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| Error::Storage(format!("invalid created_at: {e}")))?
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|e| Error::Storage(format!("invalid updated_at: {e}")))?
                    .with_timezone(&Utc),
                version: version as u32,
            });
        }
        Ok(result)
    }
}

// -- Serde helpers --

fn serialize_algorithm(alg: &CipherAlgorithm) -> String {
    serde_json::to_string(alg).expect("CipherAlgorithm serialization should never fail")
}

fn deserialize_algorithm(s: &str) -> Result<CipherAlgorithm> {
    serde_json::from_str(s).map_err(|e| Error::Storage(format!("invalid algorithm value: {e}")))
}

fn serialize_kind(kind: &SecretKind) -> String {
    serde_json::to_string(kind).expect("SecretKind serialization should never fail")
}

fn deserialize_kind(s: &str) -> Result<SecretKind> {
    serde_json::from_str(s).map_err(|e| Error::Storage(format!("invalid kind value: {e}")))
}

fn row_to_stored_secret(row: &sqlx::sqlite::SqliteRow) -> Result<StoredSecret> {
    let id_str: String = row.try_get("id").map_err(|e| Error::Storage(e.to_string()))?;
    let id_uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
    let name_str: String = row.try_get("name").map_err(|e| Error::Storage(e.to_string()))?;
    let algorithm_str: String = row.try_get("algorithm").map_err(|e| Error::Storage(e.to_string()))?;
    let kind_str: String = row.try_get("kind").map_err(|e| Error::Storage(e.to_string()))?;
    let description: Option<String> = row.try_get("description").map_err(|e| Error::Storage(e.to_string()))?;
    let created_at_str: String = row.try_get("created_at").map_err(|e| Error::Storage(e.to_string()))?;
    let updated_at_str: String = row.try_get("updated_at").map_err(|e| Error::Storage(e.to_string()))?;
    let version: i32 = row.try_get("version").map_err(|e| Error::Storage(e.to_string()))?;
    let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(|e| Error::Storage(e.to_string()))?;
    let nonce: Vec<u8> = row.try_get("nonce").map_err(|e| Error::Storage(e.to_string()))?;

    Ok(StoredSecret {
        id: SecretId::from_uuid(id_uuid),
        name: SecretName::new(name_str),
        ciphertext,
        nonce,
        algorithm: deserialize_algorithm(&algorithm_str)?,
        kind: deserialize_kind(&kind_str)?,
        description,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| Error::Storage(format!("invalid created_at: {e}")))?
            .with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| Error::Storage(format!("invalid updated_at: {e}")))?
            .with_timezone(&Utc),
        version: version as u32,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use crate::store::CipherAlgorithm;

    async fn test_store() -> (SqliteStore, NamedTempFile) {
        let tmp = NamedTempFile::new().expect("should create temp file");
        let store = SqliteStore::new(tmp.path()).await.expect("should create store");
        (store, tmp)
    }

    fn test_params(name: &str) -> StoreSecretParams {
        StoreSecretParams {
            name: SecretName::new(name),
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            algorithm: CipherAlgorithm::Aes256Gcm,
            kind: SecretKind::Pat,
            description: Some("test secret".into()),
        }
    }

    #[tokio::test]
    async fn put_and_get_round_trip() {
        let (store, _tmp) = test_store().await;
        let params = test_params("my-secret");
        let stored = store.put(params).await.expect("should put secret");
        assert_eq!(stored.name, SecretName::new("my-secret"));
        assert_eq!(stored.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(stored.algorithm, CipherAlgorithm::Aes256Gcm);
        assert_eq!(stored.kind, SecretKind::Pat);
        assert_eq!(stored.version, 1);
        let fetched = store
            .get(&SecretName::new("my-secret"))
            .await
            .expect("should get secret");
        assert_eq!(fetched.name, stored.name);
        assert_eq!(fetched.ciphertext, stored.ciphertext);
        assert_eq!(fetched.nonce, stored.nonce);
    }

    #[tokio::test]
    async fn put_duplicate_name_errors() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("dup")).await.expect("should put first secret");
        let result = store.put(test_params("dup")).await;
        assert!(result.is_err());
        let err = result.expect_err("duplicate put should fail").to_string();
        assert!(err.contains("already exists"), "error was: {err}");
    }

    #[tokio::test]
    async fn get_missing_errors() {
        let (store, _tmp) = test_store().await;
        let result = store.get(&SecretName::new("nonexistent")).await;
        assert!(result.is_err());
        let err = result.expect_err("get nonexistent should fail").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    async fn update_increments_version() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("versioned")).await.expect("should put secret");
        let updated = store
            .update(
                &SecretName::new("versioned"),
                vec![10, 20, 30],
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                CipherAlgorithm::Aes256Gcm,
            )
            .await
            .expect("should update secret");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.ciphertext, vec![10, 20, 30]);
    }

    #[tokio::test]
    async fn update_missing_errors() {
        let (store, _tmp) = test_store().await;
        let result = store
            .update(&SecretName::new("ghost"), vec![1], vec![2], CipherAlgorithm::Aes256Gcm)
            .await;
        assert!(result.is_err());
        let err = result.expect_err("update nonexistent should fail").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    async fn delete_removes_secret() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("doomed")).await.expect("should put secret");
        store
            .delete(&SecretName::new("doomed"))
            .await
            .expect("should delete secret");
        let result = store.get(&SecretName::new("doomed")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_missing_errors() {
        let (store, _tmp) = test_store().await;
        let result = store.delete(&SecretName::new("nope")).await;
        assert!(result.is_err());
        let err = result.expect_err("delete nonexistent should fail").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    async fn list_returns_metadata() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("first")).await.expect("should put first secret");
        store
            .put(test_params("second"))
            .await
            .expect("should put second secret");
        let list = store.list().await.expect("should list secrets");
        assert_eq!(list.len(), 2);
        let names: Vec<String> = list.iter().map(|m| m.name.as_str().to_string()).collect();
        assert!(names.contains(&"first".to_string()));
        assert!(names.contains(&"second".to_string()));
        for m in &list {
            assert_eq!(m.kind, SecretKind::Pat);
            assert_eq!(m.version, 1);
        }
    }
}
