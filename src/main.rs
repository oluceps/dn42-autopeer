use axum::{routing::post, Router};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{CorsLayer, Any};

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
    let wg_pubkey = std::env::var("WG_PUBLIC_KEY").unwrap_or_else(|_| "dummy_pubkey_replace_me=".to_string());
    let public_endpoint = std::env::var("PUBLIC_ENDPOINT").unwrap_or_else(|_| "dn42-node.example.com".to_string());
    let bird_socket = std::env::var("BIRD_SOCKET").unwrap_or_else(|_| "/run/bird/bird.ctl".to_string());
    let local_asn = std::env::var("LOCAL_ASN")
        .unwrap_or_else(|_| "4242420291".to_string())
        .parse::<u32>()
        .expect("LOCAL_ASN must be a valid u32 integer");
    
    let db = PeerStore::new().await.expect("Failed to initialize database");
    
    let peer_manager = Arc::new(PeerManager::new(
        db,
        bird_conf_dir,
        bird_socket,
        wg_privkey,
        wg_pubkey,
        public_endpoint,
        local_asn, // local ASN
    ));

    let state = AppState {
        manager: peer_manager,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/peers", post(create_peer).patch(update_peer).delete(delete_peer))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state)
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid u16 integer");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on http://{}", addr);
    println!("Swagger UI available at http://{}/swagger-ui/", addr);
    
    let listener = TcpListener::bind(addr).await.unwrap();
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
