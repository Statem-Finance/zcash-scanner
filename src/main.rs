//! Statem Zcash scanner — internal, stateless shielded-scanning microservice.
//!
//! Capability-scoped (NOT a generic platform): exactly two endpoints.
//!   POST /zcash/scan         UFVK + height range  -> received + spent notes (values only)
//!   POST /zcash/verify-spend UFVK + memo + height  -> matching {txid,height} or null
//!
//! Hard rules enforced here:
//!   * The UFVK is wrapped in `SecretString`, used only within the request, and
//!     zeroized on drop. It is never logged, never returned, never persisted.
//!   * Scan output carries values + heights + txids ONLY. Memos are dropped — the
//!     sole exception is `verify-spend`, which matches (but never returns) the one
//!     challenge memo.
//!   * Auth: every request must carry `X-Scanner-Auth` equal to the shared secret,
//!     compared in constant time. The service binds to private networking only.

mod config;
mod error;
mod lightwalletd;
mod scan;

use axum::{
    extract::State,
    http::HeaderMap,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use config::Config;
use error::ScanError;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
}

// ── HTTP envelopes ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScanRequest {
    /// ZIP-316 Unified Full Viewing Key. Transient secret.
    ufvk: String,
    from_height: u64,
    /// null ⇒ scan to the current chain tip (the scanner resolves it).
    to_height: Option<u64>,
}

/// One note movement. Deliberately memo-free.
#[derive(Serialize)]
struct NoteRecord {
    /// Value in zatoshis (1 ZEC = 100_000_000 zat). Node converts to ZEC.
    value_zat: u64,
    height: u64,
    /// Block time (unix seconds) — lets the Node value each movement at its date
    /// without a separate height→time lookup.
    time: u64,
    txid: String,
    /// "sapling" | "orchard".
    pool: String,
}

#[derive(Serialize)]
struct ScanResponse {
    received: Vec<NoteRecord>,
    spent: Vec<NoteRecord>,
    scanned_to_height: u64,
}

#[derive(Deserialize)]
struct VerifySpendRequest {
    ufvk: String,
    /// The session challenge memo to match against decrypted outputs.
    expected_memo: String,
    from_height: u64,
    to_height: Option<u64>,
}

#[derive(Serialize)]
struct SpendMatch {
    txid: String,
    height: u64,
}

#[derive(Serialize)]
struct VerifySpendResponse {
    /// null when no spend carrying the memo was observed in the window.
    matched: Option<SpendMatch>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn scan_handler(
    State(st): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, ScanError> {
    if let Some(to) = req.to_height {
        if to < req.from_height {
            return Err(ScanError::BadRequest("to_height < from_height".into()));
        }
        if to - req.from_height > st.cfg.max_scan_blocks {
            return Err(ScanError::BadRequest(
                "range exceeds max_scan_blocks".into(),
            ));
        }
    }
    // Wrap immediately so the raw key can't accidentally be logged/returned.
    let ufvk = SecretString::from(req.ufvk);
    let out = scan::scan_range(&st.cfg, &ufvk, req.from_height, req.to_height).await?;
    // `ufvk` drops here → zeroized.
    let map = |n: scan::Note| NoteRecord {
        value_zat: n.value_zat,
        height: n.height,
        time: n.time,
        txid: n.txid,
        pool: n.pool,
    };
    Ok(Json(ScanResponse {
        received: out.received.into_iter().map(map).collect(),
        spent: out.spent.into_iter().map(map).collect(),
        scanned_to_height: out.scanned_to_height,
    }))
}

async fn verify_spend_handler(
    State(st): State<AppState>,
    Json(req): Json<VerifySpendRequest>,
) -> Result<Json<VerifySpendResponse>, ScanError> {
    let ufvk = SecretString::from(req.ufvk);
    let matched = scan::verify_spend(
        &st.cfg,
        &ufvk,
        &req.expected_memo,
        req.from_height,
        req.to_height,
    )
    .await?;
    Ok(Json(VerifySpendResponse {
        matched: matched.map(|m| SpendMatch {
            txid: m.txid,
            height: m.height,
        }),
    }))
}

async fn health() -> &'static str {
    "ok"
}

// ── Auth middleware (constant-time shared-secret) ────────────────────────────

async fn auth(
    State(st): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, ScanError> {
    let presented = headers
        .get("x-scanner-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = st.cfg.shared_secret.expose_secret();
    // Constant-time compare; equal-length guard avoids leaking length via timing.
    let ok =
        presented.len() == expected.len() && presented.as_bytes().ct_eq(expected.as_bytes()).into();
    if !ok {
        return Err(ScanError::Unauthorized);
    }
    Ok(next.run(req).await)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load a local .env if present (dev convenience). In prod, real env vars win —
    // dotenvy never overrides an already-set variable.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zcash_scanner=info,tower_http=warn".into()),
        )
        .init();

    let cfg = Arc::new(Config::from_env()?);
    let state = AppState { cfg: cfg.clone() };

    let app = Router::new()
        .route("/zcash/scan", post(scan_handler))
        .route("/zcash/verify-spend", post(verify_spend_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        // /healthz is unauthenticated so the platform can probe it.
        .route("/healthz", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("zcash-scanner listening on {}", cfg.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
