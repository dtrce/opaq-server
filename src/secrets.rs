use std::sync::OnceLock;

use rusqlite::params;
use serde::ser::SerializeStruct;
use zeroize::Zeroizing;

use crate::auth::Principal;
use crate::crypto;
use crate::db::{now_iso, Db};
use crate::error::AppError;

fn segment_regex() -> &'static regex_lite::Regex {
    static RE: OnceLock<regex_lite::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex_lite::Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").expect("static regex pattern is valid")
    })
}

pub struct SecretData {
    pub path: String,
    pub value_type: String,
    pub value: Zeroizing<String>,
}

#[derive(serde::Serialize)]
pub struct SecretMeta {
    pub path: String,
    #[serde(rename = "type")]
    pub value_type: String,
}

struct SecretCipherRow {
    id: i64,
    path: String,
    value_type: String,
    encrypted_val: Vec<u8>,
    nonce: Vec<u8>,
}

pub struct ParsedPath<'a> {
    pub workspace: &'a str,
    pub project: &'a str,
    pub env: Option<&'a str>,
    pub key: &'a str,
}

impl serde::Serialize for SecretData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SecretData", 3)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("type", &self.value_type)?;
        state.serialize_field("value", self.value.as_str())?;
        state.end()
    }
}

fn validate_segment(name: &str, seg: &str) -> Result<(), AppError> {
    if seg.is_empty() || !segment_regex().is_match(seg) {
        return Err(AppError::validation(format!(
            "invalid {}: must be 1-64 chars matching [a-zA-Z0-9_-]",
            name
        )));
    }
    Ok(())
}

fn escape_like(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('%', r"\%")
        .replace('_', r"\_")
}

/// Decide whether a stored secret path belongs in a list scope.
///
/// `env=None` (project list) admits both project-scoped (3 segs) and any
/// env-scoped (4 segs) row under the project.
///
/// `env=Some(e)` admits the env-scoped rows for `e`. When `merge_project` is
/// true it also admits project-scoped rows of the project (which act as
/// fallback defaults), matching `opaq env` merge semantics.
fn path_in_scope(path: &str, ws: &str, proj: &str, env: Option<&str>, merge_project: bool) -> bool {
    let trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() < 3 || parts[0] != ws || parts[1] != proj {
        return false;
    }
    match parts.len() {
        3 => env.is_none() || merge_project,
        4 => match env {
            None => true,
            Some(e) => parts[2] == e,
        },
        _ => false,
    }
}

fn validate_parsed(p: &ParsedPath) -> Result<(), AppError> {
    validate_segment("workspace", p.workspace)?;
    validate_segment("project", p.project)?;
    if let Some(env) = p.env {
        validate_segment("env", env)?;
    }
    validate_segment("key", p.key)?;
    Ok(())
}

fn secret_aad(path: &str, value_type: &str) -> Vec<u8> {
    format!("opaq-secret-v1\0{}\0{}", path, value_type).into_bytes()
}

fn plaintext_to_string(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, AppError> {
    String::from_utf8(std::mem::take(&mut *plaintext))
        .map(Zeroizing::new)
        .map_err(|_| AppError::internal("decrypted value is not valid UTF-8"))
}

fn decrypt_secret_value(
    master_key: &[u8; 32],
    path: &str,
    value_type: &str,
    encrypted_val: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<String>, AppError> {
    let aad = secret_aad(path, value_type);
    let plaintext = crate::crypto::decrypt_value_with_aad(master_key, encrypted_val, nonce, &aad)?;
    plaintext_to_string(plaintext)
}

pub async fn rewrap_legacy_secret_values(db: &Db, master_key: &[u8; 32]) -> Result<(), AppError> {
    let rows: Vec<SecretCipherRow> = {
        let conn = db.lock_conn().await;
        let mut stmt =
            conn.prepare("SELECT id, path, value_type, encrypted_val, nonce FROM secrets")?;
        let collected = stmt
            .query_map([], |row| {
                Ok(SecretCipherRow {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    value_type: row.get(2)?,
                    encrypted_val: row.get(3)?,
                    nonce: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };

    for row in rows {
        let aad = secret_aad(&row.path, &row.value_type);
        if crate::crypto::decrypt_value_with_aad(master_key, &row.encrypted_val, &row.nonce, &aad)
            .is_ok()
        {
            continue;
        }

        let plaintext = crate::crypto::decrypt_value(master_key, &row.encrypted_val, &row.nonce)?;
        let (new_encrypted_val, new_nonce) =
            crate::crypto::encrypt_value_with_aad(master_key, &plaintext, &aad)?;
        let now = now_iso();
        let conn = db.lock_conn().await;
        conn.execute(
            "UPDATE secrets SET encrypted_val = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4",
            params![&new_encrypted_val, &new_nonce, &now, row.id],
        )?;
    }

    Ok(())
}

pub fn parse_path(path: &str) -> Result<ParsedPath<'_>, AppError> {
    let trimmed = path.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.iter().any(|s| s.is_empty()) {
        return Err(AppError::validation("path segments must not be empty"));
    }
    match parts.len() {
        3 => Ok(ParsedPath {
            workspace: parts[0],
            project: parts[1],
            env: None,
            key: parts[2],
        }),
        4 => Ok(ParsedPath {
            workspace: parts[0],
            project: parts[1],
            env: Some(parts[2]),
            key: parts[3],
        }),
        _ => Err(AppError::validation(
            "path must be /workspace/project/key or /workspace/project/env/key",
        )),
    }
}

pub async fn create_or_update(
    db: &Db,
    master_key: &[u8; 32],
    principal: &Principal,
    path: &str,
    value: &str,
    value_type: &str,
) -> Result<SecretMeta, AppError> {
    let parsed = parse_path(path)?;
    validate_parsed(&parsed)?;

    if value_type != "string" && value_type != "json" {
        return Err(AppError::validation("type must be 'string' or 'json'"));
    }
    if value_type == "json" {
        serde_json::from_str::<serde_json::Value>(value)
            .map_err(|_| AppError::validation("value is not valid JSON"))?;
    }

    if !principal.can_write() {
        return Err(AppError::forbidden("writer role required"));
    }

    let aad = secret_aad(path, value_type);
    let (encrypted_val, nonce) =
        crypto::encrypt_value_with_aad(master_key, value.as_bytes(), &aad)?;
    let now = now_iso();

    let conn = db.lock_conn().await;

    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM secrets WHERE path = ?1",
            params![path],
            |row| row.get(0),
        )
        .ok();

    if let Some(id) = existing {
        conn.execute(
            "UPDATE secrets SET encrypted_val=?1, nonce=?2, value_type=?3, updated_at=?4 WHERE id=?5",
            params![&encrypted_val, &nonce, value_type, &now, id],
        )?;
    } else {
        conn.execute(
            "INSERT INTO secrets (path, value_type, encrypted_val, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![path, value_type, &encrypted_val, &nonce, &now, &now],
        )?;
    }
    drop(conn);

    db.audit_log(principal.id, "put_secret", Some(path), Some(value_type))
        .await?;

    Ok(SecretMeta {
        path: path.to_string(),
        value_type: value_type.to_string(),
    })
}

pub async fn get(
    db: &Db,
    master_key: &[u8; 32],
    principal: &Principal,
    path: &str,
) -> Result<SecretData, AppError> {
    parse_path(path)?;
    if !principal.can_read() {
        return Err(AppError::forbidden("reader role required"));
    }

    let conn = db.lock_conn().await;
    let (value_type, encrypted_val, nonce) = conn
        .query_row(
            "SELECT value_type, encrypted_val, nonce FROM secrets WHERE path = ?1",
            params![path],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|_| AppError::not_found(format!("secret not found: {}", path)))?;

    drop(conn);

    let value = decrypt_secret_value(master_key, path, &value_type, &encrypted_val, &nonce)?;

    db.audit_log(principal.id, "get_secret", Some(path), None)
        .await?;

    Ok(SecretData {
        path: path.to_string(),
        value_type,
        value,
    })
}

pub async fn delete(
    db: &Db,
    _master_key: &[u8; 32],
    principal: &Principal,
    path: &str,
) -> Result<(), AppError> {
    parse_path(path)?;
    if !principal.can_write() {
        return Err(AppError::forbidden("writer role required"));
    }

    let affected = {
        let conn = db.lock_conn().await;
        conn.execute("DELETE FROM secrets WHERE path = ?1", params![path])?
    };
    if affected == 0 {
        return Err(AppError::not_found(format!("secret not found: {}", path)));
    }

    db.audit_log(principal.id, "delete_secret", Some(path), None)
        .await?;

    Ok(())
}

pub async fn list_project(
    db: &Db,
    principal: &Principal,
    ws: &str,
    proj: &str,
) -> Result<Vec<SecretMeta>, AppError> {
    validate_segment("workspace", ws)?;
    validate_segment("project", proj)?;

    if !principal.can_read() {
        return Err(AppError::forbidden("reader role required"));
    }

    let prefix = format!("/{}/{}/", escape_like(ws), escape_like(proj));
    let conn = db.lock_conn().await;
    let mut stmt = conn.prepare(
        r"SELECT path, value_type FROM secrets WHERE path LIKE ?1 ESCAPE '\' ORDER BY path",
    )?;
    let metas = stmt
        .query_map(params![format!("{}%", prefix)], |row| {
            Ok(SecretMeta {
                path: row.get(0)?,
                value_type: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(metas)
}

pub async fn list_with_values(
    db: &Db,
    master_key: &[u8; 32],
    principal: &Principal,
    ws: &str,
    proj: &str,
    env: Option<&str>,
    merge_project: bool,
) -> Result<Vec<SecretData>, AppError> {
    if !principal.can_read() {
        return Err(AppError::forbidden("reader role required"));
    }
    validate_segment("workspace", ws)?;
    validate_segment("project", proj)?;
    if let Some(e) = env {
        validate_segment("env", e)?;
    }
    let query_prefix = match (env, merge_project) {
        (Some(e), false) => format!(
            "/{}/{}/{}/",
            escape_like(ws),
            escape_like(proj),
            escape_like(e)
        ),
        _ => format!("/{}/{}/", escape_like(ws), escape_like(proj)),
    };

    let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = {
        let conn = db.lock_conn().await;
        let mut stmt = conn.prepare(
            r"SELECT path, value_type, encrypted_val, nonce FROM secrets WHERE path LIKE ?1 ESCAPE '\' ORDER BY path",
        )?;
        let collected = stmt
            .query_map(params![format!("{}%", query_prefix)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };

    let mut out = Vec::with_capacity(rows.len());
    for (path, vtype, ct, nonce) in rows {
        if !path_in_scope(&path, ws, proj, env, merge_project) {
            continue;
        }
        let value = decrypt_secret_value(master_key, &path, &vtype, &ct, &nonce)?;
        out.push(SecretData {
            path,
            value_type: vtype,
            value,
        });
    }

    let scope_label = match env {
        None => format!("/{}/{}", ws, proj),
        Some(e) => format!("/{}/{}/{}", ws, proj, e),
    };
    db.audit_log(
        principal.id,
        "list_with_values",
        Some(&scope_label),
        Some(&format!("count={}", out.len())),
    )
    .await?;

    Ok(out)
}

pub async fn list(
    db: &Db,
    principal: &Principal,
    ws: &str,
    proj: &str,
    env: &str,
    merge_project: bool,
) -> Result<Vec<SecretMeta>, AppError> {
    validate_segment("workspace", ws)?;
    validate_segment("project", proj)?;
    validate_segment("env", env)?;

    if !principal.can_read() {
        return Err(AppError::forbidden("reader role required"));
    }

    let query_prefix = if merge_project {
        format!("/{}/{}/", escape_like(ws), escape_like(proj))
    } else {
        format!(
            "/{}/{}/{}/",
            escape_like(ws),
            escape_like(proj),
            escape_like(env)
        )
    };
    let conn = db.lock_conn().await;
    let mut stmt = conn.prepare(
        r"SELECT path, value_type FROM secrets WHERE path LIKE ?1 ESCAPE '\' ORDER BY path",
    )?;
    let metas = stmt
        .query_map(params![format!("{}%", query_prefix)], |row| {
            Ok(SecretMeta {
                path: row.get(0)?,
                value_type: row.get(1)?,
            })
        })?
        .filter_map(|r| match r {
            Ok(m) if path_in_scope(&m.path, ws, proj, Some(env), merge_project) => Ok(m).into(),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(metas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Principal, Role};
    use crate::crypto;

    async fn test_db() -> Db {
        let db = Db::open(":memory:").expect("open in-memory db");
        db.migrate().await.expect("migrate");
        db
    }

    fn principal(role: Role) -> Principal {
        Principal {
            id: 1,
            name: "test".to_string(),
            role,
            created_at: "0".to_string(),
            revoked_at: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn reader_can_read_but_not_write() {
        let db = test_db().await;
        let key = crypto::generate_master_key();
        let admin = principal(Role::Admin);
        let reader = principal(Role::Reader);

        create_or_update(
            &db,
            &key,
            &admin,
            "/acme/api/prod/SECRET",
            "value",
            "string",
        )
        .await
        .expect("admin write");

        let data = get(&db, &key, &reader, "/acme/api/prod/SECRET")
            .await
            .expect("reader read");
        assert_eq!(data.value.as_str(), "value");

        let err = match create_or_update(
            &db,
            &key,
            &reader,
            "/acme/api/prod/OTHER",
            "value",
            "string",
        )
        .await
        {
            Ok(_) => panic!("reader write should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("write"));
    }

    #[tokio::test]
    async fn writer_can_read_write_and_delete() {
        let db = test_db().await;
        let key = crypto::generate_master_key();
        let writer = principal(Role::Writer);

        create_or_update(
            &db,
            &key,
            &writer,
            "/acme/api/prod/SECRET",
            "value",
            "string",
        )
        .await
        .expect("writer write");
        let data = get(&db, &key, &writer, "/acme/api/prod/SECRET")
            .await
            .expect("writer read");
        assert_eq!(data.value.as_str(), "value");
        delete(&db, &key, &writer, "/acme/api/prod/SECRET")
            .await
            .expect("writer delete");
    }

    #[tokio::test]
    async fn legacy_ciphertexts_are_rewrapped_with_associated_data() {
        let db = test_db().await;
        let key = crypto::generate_master_key();
        let reader = principal(Role::Reader);
        let path = "/acme/api/prod/SECRET";
        let value_type = "string";
        let (legacy_ct, legacy_nonce) =
            crypto::encrypt_value(&key, b"value").expect("legacy encrypt");
        let now = now_iso();

        {
            let conn = db.lock_conn().await;
            conn.execute(
                "INSERT INTO secrets (path, value_type, encrypted_val, nonce, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![path, value_type, &legacy_ct, &legacy_nonce, &now, &now],
            )
            .expect("insert legacy row");
        }

        rewrap_legacy_secret_values(&db, &key)
            .await
            .expect("rewrap legacy rows");

        let data = get(&db, &key, &reader, path)
            .await
            .expect("read rewrapped value");
        assert_eq!(data.value.as_str(), "value");

        let conn = db.lock_conn().await;
        let (rewrapped_ct, rewrapped_nonce): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT encrypted_val, nonce FROM secrets WHERE path = ?1",
                params![path],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load rewrapped row");
        assert!(
            crypto::decrypt_value(&key, &rewrapped_ct, &rewrapped_nonce).is_err(),
            "rewrapped value must not decrypt without associated data"
        );
    }
}
