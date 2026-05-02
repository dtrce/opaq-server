use salvo::prelude::*;

use super::shared::{env_secret_path, put_at};
use crate::error::AppError;

#[handler]
pub(crate) async fn put_secret(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let path = env_secret_path(req)?;
    put_at(req, depot, &path).await
}
