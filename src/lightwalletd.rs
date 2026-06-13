//! lightwalletd / Zaino gRPC client wrapper.
//!
//! Uses the tonic `CompactTxStreamerClient` pre-generated in
//! `zcash_client_backend::proto::service`. TLS is enabled for the `https://` zec.rocks
//! fleet. This module only fetches data; all decryption happens in scan.rs.
//!
//! ⚠️ UNVERIFIED — see scan.rs banner. API names below target a recent
//! zcash_client_backend; pin + adjust on a real toolchain.

use crate::error::ScanError;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec, TxFilter,
};
use zcash_client_backend::proto::compact_formats::CompactBlock;

pub type Client = CompactTxStreamerClient<Channel>;

/// Map an upstream error to `ScanError::Upstream`, logging the real cause first so
/// a 502 isn't opaque. (lightwalletd / tonic errors carry the actual reason.)
fn upstream<E: std::fmt::Debug>(ctx: &'static str) -> impl Fn(E) -> ScanError {
    move |e| {
        tracing::error!("lightwalletd {ctx} error: {e:?}");
        ScanError::Upstream
    }
}

/// Connect to the lightwalletd endpoint (TLS for https URLs), retrying a few times
/// on transient failures (network blips / ECONNRESET are common).
pub async fn connect(url: &str) -> Result<Client, ScanError> {
    let mut endpoint = Channel::from_shared(url.to_string())
        .map_err(upstream("from_shared(bad LIGHTWALLETD_URL?)"))?;
    if url.starts_with("https://") {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(upstream("tls_config"))?;
    }
    let mut last: Option<String> = None;
    for attempt in 0..3 {
        match endpoint.connect().await {
            Ok(channel) => return Ok(CompactTxStreamerClient::new(channel)),
            Err(e) => {
                last = Some(format!("{e:?}"));
                tracing::warn!("lightwalletd connect attempt {} failed: {e:?}", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_millis(400 * (attempt + 1))).await;
            }
        }
    }
    tracing::error!("lightwalletd connect failed after retries: {:?}", last);
    Err(ScanError::Upstream)
}

/// Current chain tip height.
pub async fn latest_height(client: &mut Client) -> Result<u64, ScanError> {
    let resp = client
        .get_latest_block(ChainSpec {}).await.map_err(upstream("get_latest_block"))?;
    Ok(resp.into_inner().height)
}

/// The commitment-tree state at `height` (used to seed note positions for the
/// first scanned block). Returns the raw `TreeState` so scan.rs can read the
/// sapling/orchard frontier sizes from it.
pub async fn tree_state(
    client: &mut Client,
    height: u64,
) -> Result<zcash_client_backend::proto::service::TreeState, ScanError> {
    let resp = client
        .get_tree_state(BlockId { height, hash: vec![] }).await.map_err(upstream("get_tree_state"))?;
    Ok(resp.into_inner())
}

/// Stream every CompactBlock in `[start, end]` (inclusive).
pub async fn block_range(
    client: &mut Client,
    start: u64,
    end: u64,
) -> Result<tonic::Streaming<CompactBlock>, ScanError> {
    let range = BlockRange {
        start: Some(BlockId { height: start, hash: vec![] }),
        end: Some(BlockId { height: end, hash: vec![] }),
        pool_types: vec![], // all pools
    };
    let resp = client
        .get_block_range(range).await.map_err(upstream("get_block_range"))?;
    Ok(resp.into_inner())
}

/// Fetch a full raw transaction by txid (needed to read memos for verify-spend —
/// compact blocks omit the full ciphertext).
pub async fn get_transaction(
    client: &mut Client,
    txid: Vec<u8>,
) -> Result<Vec<u8>, ScanError> {
    let resp = client
        .get_transaction(TxFilter { block: None, index: 0, hash: txid }).await.map_err(upstream("get_transaction"))?;
    Ok(resp.into_inner().data)
}
