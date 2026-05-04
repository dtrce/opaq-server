use salvo::prelude::*;

use super::shared::{require_admin, state};
use crate::auth::{self, Role, UpsertResult, UpsertSpec};
use crate::error::AppError;

#[handler]
pub(crate) async fn upsert_principal(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(req, depot).await?;
    let body: serde_json::Value = req.parse_json().await?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("name (string) is required"))?
        .to_string();

    let role = match body.get("role") {
        Some(serde_json::Value::Null) | None => None,
        Some(v) => {
            Some(Role::parse(v.as_str().ok_or_else(|| {
                AppError::validation("role must be a string")
            })?)?)
        }
    };

    let clear_ttl = body
        .get("clear_ttl")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let ttl_seconds = match body.get("ttl_seconds") {
        Some(serde_json::Value::Null) | None => None,
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| AppError::validation("ttl_seconds must be a positive integer"))?,
        ),
    };
    if matches!(ttl_seconds, Some(0)) {
        return Err(AppError::validation("ttl_seconds must be greater than 0"));
    }
    if clear_ttl && ttl_seconds.is_some() {
        return Err(AppError::validation(
            "ttl_seconds and clear_ttl are mutually exclusive",
        ));
    }

    let rename_owned = body
        .get("rename")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let st = state(depot)?;
    let result = auth::upsert_principal(
        &st.db,
        &st.key_pepper,
        UpsertSpec {
            name: &name,
            role,
            ttl_seconds,
            clear_ttl,
            rename: rename_owned.as_deref(),
        },
    )
    .await?;

    let body = match result {
        UpsertResult::Created(k) => serde_json::json!({
            "action": "created",
            "id": k.id,
            "name": k.name,
            "role": k.role,
            "expires_at": k.expires_at,
            "key": k.key.as_str(),
        }),
        UpsertResult::Updated(p) => serde_json::json!({
            "action": "updated",
            "id": p.id,
            "name": p.name,
            "role": p.role,
            "expires_at": p.expires_at,
        }),
    };
    Ok(Json(body))
}
