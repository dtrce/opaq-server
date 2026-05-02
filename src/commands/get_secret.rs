use salvo::prelude::*;

use super::shared::{env_secret_path, get_at};
use crate::error::AppError;

#[handler]
pub(crate) async fn get_secret(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let path = env_secret_path(req)?;
    get_at(req, depot, &path).await
}
