use salvo::prelude::*;

use super::shared::{get_at, project_secret_path};
use crate::error::AppError;

#[handler]
pub(crate) async fn get_secret_proj(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let path = project_secret_path(req)?;
    get_at(req, depot, &path).await
}
