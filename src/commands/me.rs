use salvo::prelude::*;

use super::shared::extract_principal;
use crate::error::AppError;

#[handler]
pub(crate) async fn me(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    Ok(Json(serde_json::json!({
        "principal": {
            "id": ctx.principal.id,
            "name": ctx.principal.name,
            "role": ctx.principal.role,
            "expires_at": ctx.principal.expires_at,
        }
    })))
}
