use std::sync::Arc;

use salvo::prelude::*;
use zeroize::Zeroizing;

use crate::auth::{self, Principal};
use crate::db::Db;
use crate::error::AppError;
use crate::secrets;

pub(crate) const REQUEST_BODY_MAX_BYTES: usize = 1024 * 1024;

pub(crate) struct AppState {
    pub(crate) db: Db,
    pub(crate) key_pepper: Zeroizing<Vec<u8>>,
    pub(crate) master_key: Zeroizing<[u8; 32]>,
}

pub(crate) fn state(depot: &Depot) -> Result<Arc<AppState>, AppError> {
    depot
        .obtain::<Arc<AppState>>()
        .cloned()
        .map_err(|_| AppError::internal("server state not initialized"))
}

pub(crate) fn require_param(req: &mut Request, name: &str) -> Result<String, AppError> {
    req.param::<String>(name)
        .ok_or_else(|| AppError::validation(format!("missing path parameter '{}'", name)))
}

pub(crate) fn require_id_param(req: &mut Request, name: &str) -> Result<i64, AppError> {
    let raw = require_param(req, name)?;
    raw.parse::<i64>()
        .map_err(|_| AppError::validation(format!("'{}' must be an integer", name)))
}

pub(crate) struct AuthContext {
    pub principal: Principal,
    pub master_key: Zeroizing<[u8; 32]>,
}

pub(crate) async fn extract_principal(
    req: &mut Request,
    depot: &Depot,
) -> Result<AuthContext, AppError> {
    let api_key = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::unauthorized("missing Authorization: Bearer <key> header"))?
        .to_owned();
    let api_key = Zeroizing::new(api_key);

    let st = state(depot)?;
    let principal = auth::authenticate(&st.db, &st.key_pepper, &api_key).await?;
    Ok(AuthContext {
        principal,
        master_key: st.master_key.clone(),
    })
}

pub(crate) async fn require_admin(
    req: &mut Request,
    depot: &Depot,
) -> Result<AuthContext, AppError> {
    let ctx = extract_principal(req, depot).await?;
    if !ctx.principal.is_admin() {
        return Err(AppError::forbidden("admin access required"));
    }
    Ok(ctx)
}

pub(crate) fn env_secret_path(req: &mut Request) -> Result<String, AppError> {
    let ws = require_param(req, "workspace")?;
    let proj = require_param(req, "project")?;
    let env = require_param(req, "env")?;
    let key = require_param(req, "key")?;
    Ok(format!("/{}/{}/{}/{}", ws, proj, env, key))
}

pub(crate) fn project_secret_path(req: &mut Request) -> Result<String, AppError> {
    let ws = require_param(req, "workspace")?;
    let proj = require_param(req, "project")?;
    let key = require_param(req, "pkey")?;
    Ok(format!("/{}/{}/{}", ws, proj, key))
}

fn check_content_type(req: &Request) -> Result<(), AppError> {
    let ct = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(AppError::validation(
            "Content-Type must be application/json",
        ));
    }
    Ok(())
}

pub(crate) async fn parse_json_request(req: &mut Request) -> Result<serde_json::Value, AppError> {
    check_content_type(req)?;
    req.parse_json_with_max_size(REQUEST_BODY_MAX_BYTES)
        .await
        .map_err(|err| {
            let msg = err.to_string();
            if msg.to_ascii_lowercase().contains("length limit") {
                AppError::validation("request body too large")
            } else {
                AppError::from(err)
            }
        })
}

pub(crate) async fn put_at(
    req: &mut Request,
    depot: &mut Depot,
    path: &str,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let body = parse_json_request(req).await?;
    let value = body["value"]
        .as_str()
        .ok_or_else(|| AppError::validation("missing 'value'"))?;
    let value_type = body["type"].as_str().unwrap_or("string");

    let st = state(depot)?;
    let meta = secrets::create_or_update(
        &st.db,
        &ctx.master_key,
        &ctx.principal,
        path,
        value,
        value_type,
    )
    .await?;
    Ok(Json(serde_json::to_value(meta)?))
}

pub(crate) async fn get_at(
    req: &mut Request,
    depot: &mut Depot,
    path: &str,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let st = state(depot)?;
    let data = secrets::get(&st.db, &ctx.master_key, &ctx.principal, path).await?;
    Ok(Json(serde_json::to_value(data)?))
}

pub(crate) async fn delete_at(
    req: &mut Request,
    depot: &mut Depot,
    path: &str,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let st = state(depot)?;
    secrets::delete(&st.db, &ctx.master_key, &ctx.principal, path).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_json_request_rejects_bodies_over_limit_without_trusting_content_length() {
        let oversized_value = "x".repeat(REQUEST_BODY_MAX_BYTES + 1);
        let body = serde_json::json!({ "value": oversized_value }).to_string();
        let mut req = Request::new();
        req.headers_mut().insert(
            "content-type",
            "application/json".parse().expect("valid header"),
        );
        req.replace_body(salvo::http::ReqBody::from(body));

        let err = parse_json_request(&mut req)
            .await
            .expect_err("oversized json should be rejected");

        assert!(err.to_string().contains("body"));
    }
}
