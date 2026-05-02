use salvo::prelude::*;

use super::shared::{extract_principal, require_param, state};
use crate::error::AppError;
use crate::secrets;

#[handler]
pub(crate) async fn list_secrets(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = extract_principal(req, depot).await?;
    let ws = require_param(req, "workspace")?;
    let proj = require_param(req, "project")?;
    let env = require_param(req, "env")?;
    let with_values = req.query::<bool>("values").unwrap_or(false);
    let merge = req.query::<bool>("merge").unwrap_or(true);

    let st = state(depot)?;
    if with_values {
        let items = secrets::list_with_values(
            &st.db,
            &ctx.master_key,
            &ctx.principal,
            &ws,
            &proj,
            Some(&env),
            merge,
        )
        .await?;
        Ok(Json(serde_json::to_value(items)?))
    } else {
        let metas = secrets::list(&st.db, &ctx.principal, &ws, &proj, &env, merge).await?;
        Ok(Json(serde_json::to_value(metas)?))
    }
}
