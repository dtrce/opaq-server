use salvo::prelude::*;

use super::shared::{extract_principal, state};
use crate::auth;
use crate::error::AppError;

#[handler]
pub(crate) async fn rotate_principal(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let body: serde_json::Value = req.parse_json().await?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("name (string) is required"))?;

    if !ctx.principal.is_admin() && ctx.principal.name != name {
        return Err(AppError::forbidden(
            "non-admin principals can only rotate their own key",
        ));
    }

    let st = state(depot)?;
    let key = auth::rotate_principal_key(&st.db, &st.key_pepper, name).await?;
    Ok(Json(serde_json::json!({
        "id":         key.id,
        "name":       key.name,
        "role":       key.role,
        "key":        key.key.as_str(),
        "expires_at": key.expires_at,
    })))
}
