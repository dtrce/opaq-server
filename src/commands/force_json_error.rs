use salvo::prelude::*;

#[handler]
pub(crate) async fn force_json_error(res: &mut Response, ctrl: &mut FlowCtrl) {
    let status = res.status_code.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let reason = status.canonical_reason().unwrap_or("error");
    res.render(Json(serde_json::json!({
        "error": reason,
        "status": status.as_u16(),
    })));
    ctrl.skip_rest();
}
