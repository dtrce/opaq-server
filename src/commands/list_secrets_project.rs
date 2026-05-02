use salvo::prelude::*;

use super::shared::{extract_principal, require_param, state};
use crate::error::AppError;
use crate::secrets;

#[handler]
pub(crate) async fn list_secrets_project(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let ws = require_param(req, "workspace")?;
    let proj = require_param(req, "project")?;
    let with_values = req.query::<bool>("values").unwrap_or(false);

    let st = state(depot)?;
    if with_values {
        let items = secrets::list_with_values(
            &st.db,
            &ctx.master_key,
            &ctx.principal,
            &ws,
            &proj,
            None,
            true,
        )
        .await?;
        Ok(Json(serde_json::to_value(items)?))
    } else {
        let metas = secrets::list_project(&st.db, &ctx.principal, &ws, &proj).await?;
        Ok(Json(serde_json::to_value(metas)?))
    }
}
