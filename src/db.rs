use rusqlite::Connection;
use tokio::sync::{Mutex, MutexGuard};

use crate::error::AppError;

pub struct Db {
    pub conn: Mutex<Connection>,
}

pub struct InstanceMeta {
    pub key_pepper: Vec<u8>,
    pub kdf_salt: Vec<u8>,
}

impl Db {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub async fn lock_conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    pub async fn migrate(&self) -> Result<(), AppError> {
        let conn = self.lock_conn().await;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS principals (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                key_hash    BLOB NOT NULL UNIQUE,
                role        TEXT NOT NULL CHECK(role IN ('reader','writer','admin')),
                created_at  TEXT NOT NULL,
                revoked_at  TEXT,
                expires_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                path            TEXT NOT NULL UNIQUE,
                value_type      TEXT NOT NULL CHECK(value_type IN ('string','json')),
                encrypted_val   BLOB NOT NULL,
                nonce           BLOB NOT NULL,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                principal_id    INTEGER NOT NULL,
                action          TEXT NOT NULL,
                path            TEXT,
                detail          TEXT,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instance_meta (
                id          INTEGER PRIMARY KEY CHECK(id = 1),
                key_pepper  BLOB NOT NULL,
                kdf_salt    BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_active_name
                ON principals(name) WHERE revoked_at IS NULL;",
        )?;
        Ok(())
    }

    pub async fn get_instance_meta(&self) -> Result<Option<InstanceMeta>, AppError> {
        let conn = self.lock_conn().await;
        match conn.query_row(
            "SELECT key_pepper, kdf_salt FROM instance_meta WHERE id = 1",
            [],
            |row| {
                Ok(InstanceMeta {
                    key_pepper: row.get::<_, Vec<u8>>(0)?,
                    kdf_salt: row.get::<_, Vec<u8>>(1)?,
                })
            },
        ) {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::internal(format!(
                "failed to read instance_meta: {} (legacy schema? wipe DB and re-bootstrap)",
                e
            ))),
        }
    }

    pub async fn is_empty(&self) -> Result<bool, AppError> {
        let conn = self.lock_conn().await;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM principals", [], |r| r.get(0))?;
        Ok(count == 0)
    }

    pub async fn needs_bootstrap(&self) -> Result<bool, AppError> {
        let conn = self.lock_conn().await;
        let meta_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM instance_meta WHERE id = 1", [], |r| {
                r.get(0)
            })?;
        Ok(meta_count == 0)
    }

    pub async fn bootstrap_atomic(
        &self,
        key_pepper: &[u8],
        kdf_salt: &[u8],
        admin_name: &str,
        admin_key_hash: &[u8],
    ) -> Result<i64, AppError> {
        let mut conn = self.lock_conn().await;
        let tx = conn.transaction()?;
        let now = now_iso();
        tx.execute(
            "INSERT INTO instance_meta (id, key_pepper, kdf_salt, created_at) VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![key_pepper, kdf_salt, &now],
        )?;
        tx.execute(
            "INSERT INTO principals (name, key_hash, role, created_at) VALUES (?1, ?2, 'admin', ?3)",
            rusqlite::params![admin_name, admin_key_hash, &now],
        )?;
        let admin_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(admin_id)
    }

    pub async fn create_principal_atomic(
        &self,
        name: &str,
        key_hash: &[u8],
        role: crate::auth::Role,
        ttl_seconds: Option<u64>,
    ) -> Result<(i64, Option<String>), AppError> {
        let mut conn = self.lock_conn().await;
        let tx = conn.transaction()?;
        let now_s = now_secs();
        let now = format!("{}", now_s);
        let expires_at = ttl_seconds
            .and_then(|t| now_s.checked_add(t))
            .map(|s| format!("{}", s));
        tx.execute(
            "INSERT INTO principals (name, key_hash, role, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, key_hash, role.as_str(), &now, &expires_at],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok((id, expires_at))
    }

    pub async fn find_active_principal_by_name(
        &self,
        name: &str,
    ) -> Result<Option<crate::auth::Principal>, AppError> {
        let conn = self.lock_conn().await;
        match conn.query_row(
            "SELECT id, name, role, created_at, revoked_at, expires_at \
             FROM principals \
             WHERE name = ?1 AND revoked_at IS NULL",
            rusqlite::params![name],
            |row| {
                Ok(crate::auth::Principal {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    role: crate::auth::Role::parse(&row.get::<_, String>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    created_at: row.get(3)?,
                    revoked_at: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            },
        ) {
            Ok(p) => Ok(Some(p)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn count_active_admins_excluding(&self, id: i64) -> Result<i64, AppError> {
        let conn = self.lock_conn().await;
        let now_s = now_secs() as i64;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM principals \
             WHERE role = 'admin' \
               AND revoked_at IS NULL \
               AND id != ?1 \
               AND (expires_at IS NULL OR CAST(expires_at AS INTEGER) > ?2)",
            rusqlite::params![id, now_s],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    pub async fn rotate_principal_key_atomic(
        &self,
        id: i64,
        new_key_hash: &[u8],
    ) -> Result<(), AppError> {
        let conn = self.lock_conn().await;
        let affected = conn.execute(
            "UPDATE principals SET key_hash = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            rusqlite::params![new_key_hash, id],
        )?;
        if affected == 0 {
            return Err(AppError::not_found(
                "principal not found or already revoked",
            ));
        }
        Ok(())
    }

    pub async fn update_principal_atomic(
        &self,
        id: i64,
        new_name: Option<&str>,
        new_role: Option<crate::auth::Role>,
        new_expires_at: Option<Option<String>>,
    ) -> Result<(), AppError> {
        let mut sets: Vec<&str> = Vec::with_capacity(3);
        let name_owned: Option<String> = new_name.map(str::to_string);
        let role_owned: Option<String> = new_role.map(|r| r.as_str().to_string());
        let exp_owned: Option<Option<String>> = new_expires_at;
        if name_owned.is_some() {
            sets.push("name = ?");
        }
        if role_owned.is_some() {
            sets.push("role = ?");
        }
        if exp_owned.is_some() {
            sets.push("expires_at = ?");
        }
        if sets.is_empty() {
            return Ok(());
        }
        let sql = format!("UPDATE principals SET {} WHERE id = ?", sets.join(", "));

        let conn = self.lock_conn().await;
        let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(4);
        if let Some(n) = name_owned.as_ref() {
            params.push(n);
        }
        if let Some(r) = role_owned.as_ref() {
            params.push(r);
        }
        if let Some(e) = exp_owned.as_ref() {
            params.push(e);
        }
        params.push(&id);
        conn.execute(&sql, params.as_slice())?;
        Ok(())
    }

    pub async fn audit_log(
        &self,
        principal_id: i64,
        action: &str,
        path: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), AppError> {
        let conn = self.lock_conn().await;
        let now = now_iso();
        conn.execute(
            "INSERT INTO audit_log (principal_id, action, path, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![principal_id, action, path, detail.unwrap_or(""), &now],
        )?;
        Ok(())
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

pub fn now_iso() -> String {
    format!("{}", now_secs())
}
