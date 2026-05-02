use salvo::prelude::*;

use super::shared::{delete_at, project_secret_path};
use crate::error::AppError;

#[handler]
pub(crate) async fn delete_secret_proj(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let path = project_secret_path(req)?;
    delete_at(req, depot, &path).await
}
