use salvo::prelude::*;

use super::shared::{require_admin, state};
use crate::auth;
use crate::error::AppError;

#[handler]
pub(crate) async fn list_principals(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = require_admin(req, depot).await?;
    let st = state(depot)?;
    let principals = auth::list_api_keys(&st.db, &ctx.principal).await?;
    Ok(Json(serde_json::json!(principals
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "role": p.role,
                "created_at": p.created_at,
                "revoked_at": p.revoked_at,
                "expires_at": p.expires_at,
            })
        })
        .collect::<Vec<_>>())))
}
