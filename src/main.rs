mod auth;
mod commands;
mod config;
mod crypto;
mod db;
mod error;
mod secrets;

use std::sync::Arc;

use salvo::prelude::*;
use zeroize::Zeroizing;

use crate::commands::delete_secret::delete_secret;
use crate::commands::delete_secret_proj::delete_secret_proj;
use crate::commands::force_json_error::force_json_error;
use crate::commands::get_secret::get_secret;
use crate::commands::get_secret_proj::get_secret_proj;
use crate::commands::healthz::healthz;
use crate::commands::list_principals::list_principals;
use crate::commands::list_secrets::list_secrets;
use crate::commands::list_secrets_project::list_secrets_project;
use crate::commands::me::me;
use crate::commands::put_secret::put_secret;
use crate::commands::put_secret_proj::put_secret_proj;
use crate::commands::revoke_principal::revoke_principal;
use crate::commands::rotate_principal::rotate_principal;
use crate::commands::upsert_principal::upsert_principal;
use crate::commands::shared::AppState;
use crate::config::ServerConfig;
use crate::db::Db;

#[handler]
async fn security_headers(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    res.headers_mut()
        .insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    res.headers_mut()
        .insert("X-Frame-Options", "DENY".parse().unwrap());
    ctrl.call_next(req, depot, res).await;
}

async fn run() -> Result<(), String> {
    tracing_subscriber::fmt::init();

    let config = ServerConfig::default();
    if let Some(err) = &config.master_key_error {
        return Err(err.clone());
    }
    let passphrase = config
        .master_passphrase
        .ok_or_else(|| "OPAQ_MASTER_KEY is required to start the server".to_string())?;

    let db = Db::open(&config.db_path).map_err(|e| format!("failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("failed to run migrations: {}", e))?;

    let needs_bootstrap = db
        .needs_bootstrap()
        .await
        .map_err(|e| format!("db check failed: {}", e))?;

    if needs_bootstrap {
        if !db
            .is_empty()
            .await
            .map_err(|e| format!("db check failed: {}", e))?
        {
            return Err("database has principals but no instance_meta — refusing to bootstrap (re-deploy on a fresh DB or migrate manually)".to_string());
        }
        let pepper = crypto::random_bytes(32);
        let kdf_salt = crypto::random_bytes(32);
        let admin_key = crypto::generate_api_key();
        let admin_key_hash = crypto::hash_key(&admin_key, &pepper)
            .map_err(|e| format!("failed to hash admin key: {}", e))?;

        db.bootstrap_atomic(&pepper, &kdf_salt, "root", &admin_key_hash)
            .await
            .map_err(|e| format!("bootstrap failed: {}", e))?;

        println!("Root admin API key: {}", admin_key.as_str());
        println!("SAVE THIS KEY. It will not be shown again.");
    }

    let meta = db
        .get_instance_meta()
        .await
        .map_err(|e| format!("failed to load instance metadata: {}", e))?
        .ok_or_else(|| "instance_meta missing after bootstrap".to_string())?;

    let master_key = crypto::derive_master_key(&passphrase, &meta.kdf_salt)
        .map_err(|e| format!("failed to derive master key: {}", e))?;

    let state = Arc::new(AppState {
        db,
        key_pepper: Zeroizing::new(meta.key_pepper),
        master_key,
    });

    let router = Router::new()
        .hoop(security_headers)
        .hoop(salvo::affix_state::inject(state))
        .push(Router::with_path("healthz").get(healthz))
        .push(Router::with_path("api/v1/me").get(me))
        .push(Router::with_path("api/v1/principals").get(list_principals))
        .push(Router::with_path("api/v1/principals/{id}").delete(revoke_principal))
        .push(Router::with_path("api/v1/principals").put(upsert_principal))
        .push(Router::with_path("api/v1/principals/rotate").post(rotate_principal))
        .push(Router::with_path("api/v1/secrets/{workspace}/{project}/{env}/{key}").put(put_secret))
        .push(Router::with_path("api/v1/secrets/{workspace}/{project}/{env}/{key}").get(get_secret))
        .push(
            Router::with_path("api/v1/secrets/{workspace}/{project}/{env}/{key}")
                .delete(delete_secret),
        )
        .push(Router::with_path("api/v1/secrets/{workspace}/{project}/{pkey}").put(put_secret_proj))
        .push(Router::with_path("api/v1/secrets/{workspace}/{project}/{pkey}").get(get_secret_proj))
        .push(
            Router::with_path("api/v1/secrets/{workspace}/{project}/{pkey}")
                .delete(delete_secret_proj),
        )
        .push(Router::with_path("api/v1/list/{workspace}/{project}/{env}").get(list_secrets))
        .push(Router::with_path("api/v1/list/{workspace}/{project}").get(list_secrets_project));

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("opaq server listening on {}", addr);
    let acceptor = TcpListener::new(&addr).bind().await;
    let service =
        Service::new(router).catcher(salvo::catcher::Catcher::default().hoop(force_json_error));
    Server::new(acceptor).serve(service).await;
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::ExitCode::FAILURE
        }
    }
}
