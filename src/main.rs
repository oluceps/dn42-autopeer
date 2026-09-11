use axum::{routing::{post, patch, delete}, Router};
use std::sync::Arc;
use dashmap::DashMap;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use std::net::SocketAddr;
use tokio::net::TcpListener;

mod error;
mod handle;
mod peer;
mod persist;
mod template;
mod wg_pubkey;

use handle::{AppState, ApiDoc, create_peer, update_peer, delete_peer};

#[tokio::main]
async fn main() {
    println!("Initializing DN42 Autopeer Web Server...");

    let state = AppState {
        peers: Arc::new(DashMap::new()),
        bird_conf_dir: "/etc/bird/peers".to_string(),
        local_wg_privkey: "dummy_privkey".to_string(),
    };

    let app = Router::new()
        .route("/api/peers", post(create_peer).patch(update_peer).delete(delete_peer))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on http://{}", addr);
    println!("Swagger UI available at http://{}/swagger-ui/", addr);
    
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
