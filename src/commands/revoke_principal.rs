use salvo::prelude::*;

use super::shared::{require_admin, require_id_param, state};
use crate::auth;
use crate::error::AppError;

#[handler]
pub(crate) async fn revoke_principal(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = require_admin(req, depot).await?;
    let id = require_id_param(req, "id")?;
    let st = state(depot)?;
    auth::revoke_api_key(&st.db, &ctx.principal, id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
