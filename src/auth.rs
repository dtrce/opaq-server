use rusqlite::params;
use zeroize::Zeroizing;

use crate::crypto;
use crate::db::Db;
use crate::error::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Reader,
    Writer,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Reader => "reader",
            Role::Writer => "writer",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "reader" => Ok(Role::Reader),
            "writer" => Ok(Role::Writer),
            "admin" => Ok(Role::Admin),
            _ => Err(AppError::validation(
                "role must be 'reader', 'writer', or 'admin'",
            )),
        }
    }
}

#[derive(Debug)]
pub struct Principal {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
}

impl Principal {
    pub fn can_read(&self) -> bool {
        matches!(self.role, Role::Reader | Role::Writer | Role::Admin)
    }

    pub fn can_write(&self) -> bool {
        matches!(self.role, Role::Writer | Role::Admin)
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

pub struct CreatedKey {
    pub id: i64,
    pub name: String,
    pub key: Zeroizing<String>,
    pub role: Role,
    pub expires_at: Option<String>,
}

pub enum UpsertResult {
    Created(CreatedKey),
    Updated(Principal),
}

pub struct UpsertSpec<'a> {
    pub name: &'a str,
    pub role: Option<Role>,
    pub ttl_seconds: Option<u64>,
    pub clear_ttl: bool,
    pub rename: Option<&'a str>,
}

pub async fn upsert_principal(
    db: &Db,
    pepper: &[u8],
    spec: UpsertSpec<'_>,
) -> Result<UpsertResult, AppError> {
    let existing = db.find_active_principal_by_name(spec.name).await?;
    match existing {
        None => {
            if spec.rename.is_some() {
                return Err(AppError::not_found(
                    "principal does not exist; cannot rename a principal that doesn't exist",
                ));
            }
            let role = spec.role.unwrap_or(Role::Reader);
            let created =
                create_principal(db, pepper, spec.name, role, spec.ttl_seconds).await?;
            Ok(UpsertResult::Created(created))
        }
        Some(current) => {
            let target_role = spec.role.unwrap_or(current.role);
            if current.role == Role::Admin && target_role != Role::Admin {
                let remaining = db.count_active_admins_excluding(current.id).await?;
                if remaining == 0 {
                    return Err(AppError::forbidden(
                        "cannot demote the last admin",
                    ));
                }
            }

            if let Some(new_name) = spec.rename {
                if new_name != current.name {
                    if db.find_active_principal_by_name(new_name).await?.is_some() {
                        return Err(AppError::validation(format!(
                            "principal name '{}' is already in use",
                            new_name
                        )));
                    }
                }
            }

            let new_expires_at: Option<Option<String>> = if spec.clear_ttl {
                Some(None)
            } else if let Some(ttl) = spec.ttl_seconds {
                let now_s = crate::db::now_secs();
                let exp = now_s
                    .checked_add(ttl)
                    .ok_or_else(|| AppError::validation("ttl_seconds overflows"))?;
                Some(Some(format!("{}", exp)))
            } else {
                None
            };

            let role_change = if target_role != current.role {
                Some(target_role)
            } else {
                None
            };

            db.update_principal_atomic(
                current.id,
                spec.rename,
                role_change,
                new_expires_at.clone(),
            )
            .await?;

            let updated = Principal {
                id: current.id,
                name: spec.rename.map(str::to_string).unwrap_or(current.name),
                role: target_role,
                created_at: current.created_at,
                revoked_at: current.revoked_at,
                expires_at: match new_expires_at {
                    Some(v) => v,
                    None => current.expires_at,
                },
            };
            Ok(UpsertResult::Updated(updated))
        }
    }
}

pub async fn rotate_principal_key(
    db: &Db,
    pepper: &[u8],
    name: &str,
) -> Result<CreatedKey, AppError> {
    let current = db
        .find_active_principal_by_name(name)
        .await?
        .ok_or_else(|| AppError::not_found("principal not found or already revoked"))?;

    let new_api_key = crypto::generate_api_key();
    let new_key_hash = crypto::hash_key(&new_api_key, pepper)?;
    db.rotate_principal_key_atomic(current.id, &new_key_hash).await?;

    Ok(CreatedKey {
        id: current.id,
        name: current.name,
        key: new_api_key,
        role: current.role,
        expires_at: current.expires_at,
    })
}

pub async fn create_principal(
    db: &Db,
    pepper: &[u8],
    name: &str,
    role: Role,
    ttl_seconds: Option<u64>,
) -> Result<CreatedKey, AppError> {
    let new_api_key = crypto::generate_api_key();
    let new_key_hash = crypto::hash_key(&new_api_key, pepper)?;

    let (id, expires_at) = db
        .create_principal_atomic(name, &new_key_hash, role, ttl_seconds)
        .await?;

    Ok(CreatedKey {
        id,
        name: name.to_string(),
        key: new_api_key,
        role,
        expires_at,
    })
}

pub async fn authenticate(db: &Db, pepper: &[u8], api_key: &str) -> Result<Principal, AppError> {
    let key_hash = crypto::hash_key(api_key, pepper)?;
    let now_s = crate::db::now_secs() as i64;
    let principal = {
        let conn = db.lock_conn().await;
        conn.query_row(
            "SELECT id, name, role, created_at, revoked_at, expires_at \
             FROM principals \
             WHERE key_hash = ?1 \
               AND (expires_at IS NULL OR CAST(expires_at AS INTEGER) > ?2)",
            params![&key_hash, now_s],
            |row| {
                Ok(Principal {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    role: Role::parse(&row.get::<_, String>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    created_at: row.get(3)?,
                    revoked_at: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            },
        )
        .map_err(|_| AppError::unauthorized("invalid API key"))?
    };

    if principal.revoked_at.is_some() {
        return Err(AppError::unauthorized("API key has been revoked"));
    }

    Ok(principal)
}

pub async fn revoke_api_key(db: &Db, caller: &Principal, key_id: i64) -> Result<(), AppError> {
    if !caller.is_admin() {
        return Err(AppError::forbidden("only admins can revoke keys"));
    }
    let now = crate::db::now_iso();
    let affected = {
        let conn = db.lock_conn().await;
        let remaining_admins: i64 = conn.query_row(
            "SELECT COUNT(*) FROM principals WHERE role = 'admin' AND revoked_at IS NULL AND id != ?1",
            params![key_id],
            |row| row.get(0),
        )?;
        if remaining_admins == 0 {
            return Err(AppError::forbidden("cannot revoke the last admin key"));
        }
        conn.execute(
            "UPDATE principals SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![&now, key_id],
        )?
    };
    if affected == 0 {
        return Err(AppError::not_found("key not found or already revoked"));
    }

    db.audit_log(
        caller.id,
        "revoke_key",
        None,
        Some(&format!("revoked key_id={}", key_id)),
    )
    .await?;
    Ok(())
}

pub async fn list_api_keys(db: &Db, caller: &Principal) -> Result<Vec<Principal>, AppError> {
    if !caller.is_admin() {
        return Err(AppError::forbidden("only admins can list keys"));
    }
    let conn = db.lock_conn().await;
    let mut stmt = conn.prepare(
        "SELECT id, name, role, created_at, revoked_at, expires_at FROM principals ORDER BY id",
    )?;
    let keys = stmt
        .query_map([], |row| {
            Ok(Principal {
                id: row.get(0)?,
                name: row.get(1)?,
                role: Role::parse(&row.get::<_, String>(2)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                created_at: row.get(3)?,
                revoked_at: row.get(4)?,
                expires_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Db {
        let db = Db::open(":memory:").expect("open in-memory db");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn create_and_authenticate_reader_role() {
        let db = test_db().await;
        let pepper = b"test pepper";

        let created = create_principal(&db, pepper, "ci", Role::Reader, None)
            .await
            .expect("create key");
        let principal = authenticate(&db, pepper, &created.key)
            .await
            .expect("authenticate");

        assert_eq!(created.role, Role::Reader);
        assert_eq!(principal.role, Role::Reader);
        assert!(principal.can_read());
        assert!(!principal.can_write());
        assert!(!principal.is_admin());
        assert!(principal.expires_at.is_none());
    }

    #[tokio::test]
    async fn cannot_revoke_last_admin() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let admin = create_principal(&db, pepper, "root", Role::Admin, None)
            .await
            .expect("create admin");
        let principal = authenticate(&db, pepper, &admin.key)
            .await
            .expect("authenticate admin");

        let err = revoke_api_key(&db, &principal, principal.id)
            .await
            .expect_err("last admin revoke should fail");

        assert!(err.to_string().contains("last admin"));
    }

    #[tokio::test]
    async fn ttl_in_future_authenticates() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let created = create_principal(&db, pepper, "ci", Role::Reader, Some(3600))
            .await
            .expect("create key");
        let principal = authenticate(&db, pepper, &created.key)
            .await
            .expect("authenticate");
        assert!(principal.expires_at.is_some());
    }

    #[tokio::test]
    async fn expired_key_rejected() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let created = create_principal(&db, pepper, "ci", Role::Reader, Some(1))
            .await
            .expect("create key");

        let conn = db.lock_conn().await;
        conn.execute(
            "UPDATE principals SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params!["1", created.id],
        )
        .expect("backdate expiry");
        drop(conn);

        let err = authenticate(&db, pepper, &created.key)
            .await
            .expect_err("expired key auth should fail");
        assert!(err.to_string().contains("invalid API key"));
    }

    #[tokio::test]
    async fn no_ttl_means_no_expiry() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let created = create_principal(&db, pepper, "forever", Role::Reader, None)
            .await
            .expect("create key");
        assert!(created.expires_at.is_none());
        let principal = authenticate(&db, pepper, &created.key)
            .await
            .expect("authenticate");
        assert!(principal.expires_at.is_none());
    }

    #[tokio::test]
    async fn ttl_persists_expires_at_to_db() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let before = crate::db::now_secs();
        let created = create_principal(&db, pepper, "ci", Role::Reader, Some(3600))
            .await
            .expect("create key");
        let after = crate::db::now_secs();

        let exp_str = created.expires_at.as_ref().expect("expires_at set");
        let exp: u64 = exp_str.parse().expect("expires_at numeric");
        assert!(exp >= before + 3600);
        assert!(exp <= after + 3600);

        let principal = authenticate(&db, pepper, &created.key)
            .await
            .expect("authenticate");
        assert_eq!(principal.expires_at.as_deref(), Some(exp_str.as_str()));
    }

    #[tokio::test]
    async fn expired_returns_invalid_not_expired_message() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let created = create_principal(&db, pepper, "ci", Role::Reader, Some(1))
            .await
            .expect("create key");

        let conn = db.lock_conn().await;
        conn.execute(
            "UPDATE principals SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params!["1", created.id],
        )
        .expect("backdate expiry");
        drop(conn);

        let err = authenticate(&db, pepper, &created.key)
            .await
            .expect_err("expired key auth should fail");
        let msg = err.to_string();
        assert!(
            !msg.to_lowercase().contains("expired"),
            "should not leak expiry status; got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn valid_key_authenticates_when_another_key_expired() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let alive = create_principal(&db, pepper, "alive", Role::Reader, Some(3600))
            .await
            .expect("create alive");
        let dead = create_principal(&db, pepper, "dead", Role::Reader, Some(3600))
            .await
            .expect("create dead");

        let conn = db.lock_conn().await;
        conn.execute(
            "UPDATE principals SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params!["1", dead.id],
        )
        .expect("backdate expiry");
        drop(conn);

        authenticate(&db, pepper, &alive.key)
            .await
            .expect("alive key still valid");
        authenticate(&db, pepper, &dead.key)
            .await
            .expect_err("dead key rejected");
    }

    #[tokio::test]
    async fn revoked_unexpired_key_returns_revoked_error() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let admin = create_principal(&db, pepper, "root", Role::Admin, None)
            .await
            .expect("create admin");
        let admin_principal = authenticate(&db, pepper, &admin.key)
            .await
            .expect("authenticate admin");
        let target = create_principal(&db, pepper, "ci", Role::Reader, Some(3600))
            .await
            .expect("create target");

        revoke_api_key(&db, &admin_principal, target.id)
            .await
            .expect("revoke target");

        let err = authenticate(&db, pepper, &target.key)
            .await
            .expect_err("revoked key should fail");
        assert!(err.to_string().contains("revoked"), "got: {}", err);
    }

    #[tokio::test]
    async fn list_api_keys_includes_expires_at() {
        let db = test_db().await;
        let pepper = b"test pepper";
        let admin = create_principal(&db, pepper, "root", Role::Admin, None)
            .await
            .expect("create admin");
        let admin_principal = authenticate(&db, pepper, &admin.key)
            .await
            .expect("authenticate admin");
        create_principal(&db, pepper, "ci", Role::Reader, Some(7200))
            .await
            .expect("create with ttl");

        let listed = list_api_keys(&db, &admin_principal)
            .await
            .expect("list keys");
        let ci = listed
            .iter()
            .find(|p| p.name == "ci")
            .expect("ci principal listed");
        assert!(ci.expires_at.is_some());
        let admin_listed = listed
            .iter()
            .find(|p| p.name == "root")
            .expect("admin listed");
        assert!(admin_listed.expires_at.is_none());
    }
}
