use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod challenge;
mod error;
mod handle;
mod manager;
mod netlink;
mod peer;
mod persist;
mod template;
mod wg_pubkey;

use challenge::RequestAuthorizer;
use handle::{
    AppState, create_challenge, create_peer, delete_peer, get_peers, openapi_json, update_peer,
};
use manager::PeerManager;
use persist::PeerStore;
use wireguard_control::Key;

#[tokio::main]
async fn main() {
    println!("Initializing DN42 Autopeer Web Server...");

    let bird_conf_dir =
        std::env::var("BIRD_CONF_DIR").unwrap_or_else(|_| "/var/lib/autopeer".to_string());

    std::fs::create_dir_all(&bird_conf_dir).expect("Failed to create the BIRD config directory");

    println!("Using BIRD config dir: {}", bird_conf_dir);

    let (wg_privkey, wg_pubkey) = load_wg_keypair();
    let public_endpoint =
        std::env::var("PUBLIC_ENDPOINT").unwrap_or_else(|_| "dn42-node.example.com".to_string());
    let bird_socket =
        std::env::var("BIRD_SOCKET").unwrap_or_else(|_| "/run/bird/bird.ctl".to_string());
    let local_asn = std::env::var("LOCAL_ASN")
        .unwrap_or_else(|_| "4242420291".to_string())
        .parse::<u32>()
        .expect("LOCAL_ASN must be a valid u32 integer");

    let db = PeerStore::new()
        .await
        .expect("Failed to initialize database");
    let authorizer =
        RequestAuthorizer::new(db.clone()).expect("Failed to initialize request authentication");

    let listener_pool = db.pool.clone();

    let peer_manager = Arc::new(PeerManager::new(
        db,
        bird_conf_dir,
        bird_socket,
        wg_privkey,
        wg_pubkey,
        public_endpoint,
        local_asn, // local ASN
    ));
    peer_manager
        .recover()
        .await
        .expect("Failed to recover peer state");

    let nft_reconciler = Arc::clone(&peer_manager);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = nft_reconciler.sync_nft_ports().await {
                eprintln!("Could not synchronize nftables ports: {error}");
            }
        }
    });

    let sync_manager = Arc::clone(&peer_manager);
    tokio::spawn(async move {
        let mut listener = sqlx::postgres::PgListener::connect_with(&listener_pool)
            .await
            .expect("Failed to connect to database listener");
        listener
            .listen("peer_changes")
            .await
            .expect("Failed to listen on peer_changes channel");
        println!("Listening for peer_changes via PostgreSQL NOTIFY...");
        loop {
            match listener.recv().await {
                Ok(notification) => {
                    let payload = notification.payload();
                    #[derive(serde::Deserialize)]
                    struct PeerChange {
                        peer_id: u32,
                        asn: u32,
                        peer_name: String,
                        iface_name: String,
                    }
                    if let Ok(change) = serde_json::from_str::<PeerChange>(payload) {
                        println!(
                            "Passive sync for peer_id {} (AS{})",
                            change.peer_id, change.asn
                        );
                        if let Err(e) = sync_manager
                            .passive_sync_peer(
                                change.peer_id,
                                change.asn,
                                &change.peer_name,
                                &change.iface_name,
                            )
                            .await
                        {
                            eprintln!("Passive sync failed for peer {}: {}", change.peer_name, e);
                        }
                    } else {
                        eprintln!("Received invalid payload on peer_changes: {}", payload);
                    }
                }
                Err(e) => {
                    eprintln!("Database listener error: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if let Ok(mut new_listener) =
                        sqlx::postgres::PgListener::connect_with(&listener_pool).await
                    {
                        if new_listener.listen("peer_changes").await.is_ok() {
                            listener = new_listener;
                        }
                    }
                }
            }
        }
    });

    let state = AppState {
        manager: peer_manager,
        authorizer,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/challenges", post(create_challenge))
        .route("/api/peers/{asn}", get(get_peers))
        .route(
            "/api/peers",
            post(create_peer).patch(update_peer).delete(delete_peer),
        )
        .route("/api-docs/openapi.json", get(openapi_json))
        .with_state(state)
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid u16 integer");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on http://{}", addr);
    println!(
        "OpenAPI specification available at http://{}/api-docs/openapi.json",
        addr
    );

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn load_wg_keypair() -> (String, String) {
    let private_key = std::env::var("WG_PRIVATE_KEY").expect("WG_PRIVATE_KEY is required");
    let public_key = std::env::var("WG_PUBLIC_KEY").expect("WG_PUBLIC_KEY is required");
    let parsed_private = Key::from_base64(&private_key)
        .expect("WG_PRIVATE_KEY must be a valid WireGuard private key");
    let parsed_public =
        Key::from_base64(&public_key).expect("WG_PUBLIC_KEY must be a valid WireGuard public key");
    assert_eq!(
        parsed_private.get_public(),
        parsed_public,
        "WG_PUBLIC_KEY does not match WG_PRIVATE_KEY"
    );
    (private_key, public_key)
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
