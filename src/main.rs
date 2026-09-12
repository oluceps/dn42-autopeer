use axum::{routing::post, Router};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use std::net::SocketAddr;
use tokio::net::TcpListener;

mod error;
mod challenge;
mod handle;
mod manager;
mod netlink;
mod peer;
mod persist;
mod template;
mod wg_pubkey;

use handle::{AppState, ApiDoc, create_peer, update_peer, delete_peer};
use manager::PeerManager;
use persist::PeerStore;

#[tokio::main]
async fn main() {
    println!("Initializing DN42 Autopeer Web Server...");

    // Setup configuration from environment
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://dummy:dummy@localhost/dummy".to_string());
    let bird_conf_dir = std::env::var("BIRD_CONF_DIR").unwrap_or_else(|_| "/var/lib/autopeer".to_string());
    
    // Ensure the config directory exists
    std::fs::create_dir_all(&bird_conf_dir).ok();

    println!("Using Database: {}", db_url);
    println!("Using BIRD config dir: {}", bird_conf_dir);

    let wg_privkey = std::env::var("WG_PRIVATE_KEY").unwrap_or_else(|_| "q1z/aK6XjHhKxXjVvV/5lD9hW2l8aU+21u6Vz9+Y1gQ=".to_string());
    
    let db = PeerStore::new().await.expect("Failed to initialize database");
    
    let peer_manager = Arc::new(PeerManager::new(
        db,
        bird_conf_dir,
        wg_privkey,
        4242420291, // local ASN
    ));

    let state = AppState {
        manager: peer_manager,
    };

    let app = Router::new()
        .route("/api/peers", post(create_peer).patch(update_peer).delete(delete_peer))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on http://{}", addr);
    println!("Swagger UI available at http://{}/swagger-ui/", addr);
    
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Listening on 0.0.0.0:8080...");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    println!("Shutdown signal received, starting graceful shutdown...");
}
