use salvo::prelude::*;

#[handler]
pub(crate) async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}
