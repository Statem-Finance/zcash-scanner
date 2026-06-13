//! Shielded scanning + challenge-spend matching.
//!
//! Implemented against the librustzcash git HEAD (zcash_client_backend 0.14 /
//! zcash_primitives 0.28 / orchard 0.14) pinned in Cargo.toml — the crates.io
//! releases are uninstallable (orchard 0.10 yanked). Compiles against that HEAD.
//!
//! ⚠️ Still validate end-to-end against `https://testnet.zec.rocks:443`
//! (ZCASH_NETWORK=test) with a UFVK whose balance/history you can independently
//! confirm before trusting any figure on a real proof-of-funds document.
//!
//! Design:
//!   * UFVK → `ScanningKeys` (account id = 0u32).
//!   * Seed note positions from the commitment-tree state at (from-1) via
//!     `GetTreeState` → `to_chain_state()` → frontier `tree_size()`.
//!   * Stream `CompactBlock`s; `scan_block` (with an empty `Nullifiers`, since the
//!     incremental constructors are crate-private) trial-decrypts RECEIVED notes and
//!     yields their nullifiers. Accumulate `nullifier → (value)`.
//!   * SPENT: match each raw `CompactTx`'s spend/action nullifiers against the
//!     accumulated received nullifiers (the spending tx's id comes from `CompactTx.txid`).
//!   * `verify_spend`: locate wallet spends, fetch the full tx, decrypt outputs and
//!     match the one challenge memo (memo is matched, never returned/logged).

use crate::config::Config;
use crate::error::ScanError;
use crate::lightwalletd;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::decrypt_transaction;
use zcash_client_backend::scanning::{scan_block, Nullifiers, ScanningKeys};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::Memo;

/// A decrypted note movement — values + location only, never a memo.
pub struct Note {
    pub value_zat: u64,
    pub height: u64,
    pub time: u64,
    pub txid: String,
    pub pool: String, // "sapling" | "orchard"
}

pub struct ScanOutput {
    pub received: Vec<Note>,
    pub spent: Vec<Note>,
    pub scanned_to_height: u64,
}

pub struct SpendMatch {
    pub txid: String,
    pub height: u64,
}

fn network_for(cfg: &Config) -> Network {
    match cfg.network.as_str() {
        "test" => Network::TestNetwork,
        _ => Network::MainNetwork,
    }
}

fn parse_ufvk(cfg: &Config, ufvk: &SecretString) -> Result<UnifiedFullViewingKey, ScanError> {
    UnifiedFullViewingKey::decode(&network_for(cfg), ufvk.expose_secret())
        .map_err(|_| ScanError::BadRequest("invalid UFVK (ZIP-316)".into()))
}

/// BlockMetadata for `height` (the pre-`from` block) so the first scanned block
/// gets correct note positions → correct nullifiers.
async fn seed_metadata(
    client: &mut lightwalletd::Client,
    height: u64,
) -> Result<BlockMetadata, ScanError> {
    let ts = lightwalletd::tree_state(client, height).await?;
    let chain_state = ts.to_chain_state().map_err(|e| {
        tracing::error!("to_chain_state error: {e:?}");
        ScanError::Upstream
    })?;
    let sapling_size = chain_state.final_sapling_tree().tree_size() as u32;
    let orchard_size = chain_state.final_orchard_tree().tree_size() as u32;
    Ok(BlockMetadata::from_parts(
        chain_state.block_height(),
        chain_state.block_hash(),
        Some(sapling_size),
        Some(orchard_size),
    ))
}

/// Scan [from, to|tip] for the UFVK's received + spent notes.
pub async fn scan_range(
    cfg: &Config,
    ufvk: &SecretString,
    from: u64,
    to: Option<u64>,
) -> Result<ScanOutput, ScanError> {
    let network = network_for(cfg);
    let ufvk = parse_ufvk(cfg, ufvk)?;
    let has_sapling = ufvk.sapling().is_some();
    let has_orchard = ufvk.orchard().is_some();
    let keys = ScanningKeys::from_account_ufvks([(0u32, ufvk)]);
    // If the UFVK carried no shielded keys (e.g. a transparent-only UFVK), no
    // shielded note can ever decrypt — log it so a "zero balance" is explained.
    tracing::info!(
        "scan: ufvk has sapling={has_sapling} orchard={has_orchard}; scanning_keys sapling={} orchard={}",
        keys.sapling().len(),
        keys.orchard().len()
    );
    // Incremental Nullifiers constructors are crate-private, so spend detection is
    // done manually below from the raw block; scan_block gets an empty set.
    let nullifiers = Nullifiers::<u32>::empty();

    let mut client = lightwalletd::connect(&cfg.lightwalletd_url).await?;
    let tip = lightwalletd::latest_height(&mut client).await?;
    let to = to.unwrap_or(tip).min(tip);
    if from > to {
        return Ok(ScanOutput {
            received: vec![],
            spent: vec![],
            scanned_to_height: to,
        });
    }
    // Guard against an infeasible scan (e.g. birthday=0 → genesis→tip = millions of
    // blocks). Applies to a to-tip scan, which the HTTP handler can't pre-check.
    if to - from > cfg.max_scan_blocks {
        tracing::error!(
            "scan range {from}..{to} exceeds max_scan_blocks {}",
            cfg.max_scan_blocks
        );
        return Err(ScanError::BadRequest(format!(
            "scan range too large ({} blocks; max {}). Use a more recent birthday height.",
            to - from,
            cfg.max_scan_blocks
        )));
    }

    let mut prior: Option<BlockMetadata> = if from > 0 {
        Some(seed_metadata(&mut client, from - 1).await?)
    } else {
        None
    };

    tracing::info!(
        "scan: range {from}..={to} (tip={tip}), {} blocks",
        to - from + 1
    );

    let mut received: Vec<Note> = Vec::new();
    let mut spent: Vec<Note> = Vec::new();
    // nullifier hex → spent-note value (we record the original received value).
    let mut received_nf: HashMap<String, u64> = HashMap::new();
    // Diagnostics: total shielded outputs the wallet saw in-range (decrypted or not
    // — note: compact blocks only carry the wallet's own/enc-detectable outputs, so
    // this is roughly "candidate outputs scan_block produced").
    let mut blocks_seen: u64 = 0;
    let mut raw_outputs: u64 = 0;
    let mut raw_actions: u64 = 0;

    let mut stream = lightwalletd::block_range(&mut client, from, to).await?;
    let mut scanned_to = from.saturating_sub(1);

    while let Some(block) = stream.message().await.map_err(|e| {
        tracing::error!("block stream error: {e:?}");
        ScanError::Upstream
    })? {
        let height = block.height;
        let time = block.time as u64;
        blocks_seen += 1;
        for ctx in &block.vtx {
            raw_outputs += ctx.outputs.len() as u64;
            raw_actions += ctx.actions.len() as u64;
        }

        let scanned = scan_block(&network, block.clone(), &keys, &nullifiers, prior.as_ref())
            .map_err(|e| {
                tracing::error!("scan_block error at height {height}: {e:?}");
                ScanError::Internal
            })?;

        for tx in scanned.transactions() {
            let txid = hex::encode(tx.txid().as_ref());
            for out in tx.sapling_outputs() {
                let value = out.note().value().inner();
                received.push(Note {
                    value_zat: value,
                    height,
                    time,
                    txid: txid.clone(),
                    pool: "sapling".into(),
                });
                if let Some(nf) = out.nf() {
                    received_nf.insert(hex::encode(nf.0), value);
                }
            }
            for out in tx.orchard_outputs() {
                let value = out.note().value().inner();
                received.push(Note {
                    value_zat: value,
                    height,
                    time,
                    txid: txid.clone(),
                    pool: "orchard".into(),
                });
                if let Some(nf) = out.nf() {
                    received_nf.insert(hex::encode(nf.to_bytes()), value);
                }
            }
        }

        // Spends: match raw spend/action nullifiers against our received notes.
        for ctx in &block.vtx {
            let txid = hex::encode(&ctx.txid);
            for s in &ctx.spends {
                if let Some(value) = received_nf.get(&hex::encode(&s.nf)) {
                    spent.push(Note {
                        value_zat: *value,
                        height,
                        time,
                        txid: txid.clone(),
                        pool: "sapling".into(),
                    });
                }
            }
            for a in &ctx.actions {
                if let Some(value) = received_nf.get(&hex::encode(&a.nullifier)) {
                    spent.push(Note {
                        value_zat: *value,
                        height,
                        time,
                        txid: txid.clone(),
                        pool: "orchard".into(),
                    });
                }
            }
        }

        prior = Some(scanned.to_block_metadata());
        scanned_to = height;
    }

    let total_received: u64 = received.iter().map(|n| n.value_zat).sum();
    let total_spent: u64 = spent.iter().map(|n| n.value_zat).sum();
    tracing::info!(
        "scan done: {blocks_seen} blocks (raw sapling_outputs={raw_outputs} orchard_actions={raw_actions}); \
         received {} notes = {total_received} zat; spent {} notes = {total_spent} zat; \
         net balance = {} zat",
        received.len(),
        spent.len(),
        total_received.saturating_sub(total_spent)
    );

    Ok(ScanOutput {
        received,
        spent,
        scanned_to_height: scanned_to,
    })
}

/// Find a wallet spend carrying `expected_memo` within the window.
pub async fn verify_spend(
    cfg: &Config,
    ufvk: &SecretString,
    expected_memo: &str,
    from: u64,
    to: Option<u64>,
) -> Result<Option<SpendMatch>, ScanError> {
    let scan = scan_range(cfg, ufvk, from, to).await?;
    tracing::info!(
        "verify_spend: checking {} detected spend(s) for the challenge memo",
        scan.spent.len()
    );
    let mut client = lightwalletd::connect(&cfg.lightwalletd_url).await?;
    for s in &scan.spent {
        let raw =
            lightwalletd::get_transaction(&mut client, hex::decode(&s.txid).unwrap_or_default())
                .await?;
        if memo_matches(cfg, ufvk, &raw, s.height, expected_memo) {
            tracing::info!(
                "verify_spend: memo matched in spend tx at height {}",
                s.height
            );
            return Ok(Some(SpendMatch {
                txid: s.txid.clone(),
                height: s.height,
            }));
        }
    }
    tracing::info!("verify_spend: no spend carried the challenge memo (→ visibility_only)");
    Ok(None)
}

/// Decrypt a full transaction's shielded outputs and test whether any output's
/// memo equals `expected`. This is the control-proof seam: a spend that carries the
/// session challenge memo proves the holder controls the SPENDING key (a viewing key
/// can produce neither the spend nor the memo on an output it authored).
///
/// We parse the raw tx, then `decrypt_transaction` trial-decrypts every Sapling and
/// Orchard output with the UFVK's incoming viewing keys (external + internal scopes),
/// returning each recovered memo. We compare only TEXT memos and never log/return the
/// memo bytes. Any decryption/parse failure ⇒ false (no false positive possible).
fn memo_matches(
    cfg: &Config,
    ufvk: &SecretString,
    raw_tx: &[u8],
    height: u64,
    expected: &str,
) -> bool {
    let network = network_for(cfg);
    let ufvk = match parse_ufvk(cfg, ufvk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let block_height = BlockHeight::from_u32(height as u32);
    let branch_id = BranchId::for_height(&network, block_height);
    let tx = match Transaction::read(raw_tx, branch_id) {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("memo_matches: tx parse failed at height {height}: {e:?}");
            return false;
        }
    };

    let mut ufvks: HashMap<u32, UnifiedFullViewingKey> = HashMap::new();
    ufvks.insert(0u32, ufvk);

    let decrypted = decrypt_transaction(&network, Some(block_height), None, &tx, &ufvks);

    let want = expected.trim();
    let is_match = |memo_bytes: &zcash_protocol::memo::MemoBytes| -> bool {
        matches!(Memo::try_from(memo_bytes), Ok(Memo::Text(t)) if t.trim() == want)
    };

    decrypted
        .sapling_outputs()
        .iter()
        .any(|o| is_match(o.memo()))
        || decrypted
            .orchard_outputs()
            .iter()
            .any(|o| is_match(o.memo()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(network: &str) -> Config {
        Config {
            bind_addr: "0.0.0.0:0".into(),
            lightwalletd_url: "https://example:443".into(),
            shared_secret: SecretString::from("test-secret".to_string()),
            network: network.to_string(),
            max_scan_blocks: 100,
        }
    }

    #[test]
    fn network_for_maps_test_and_main() {
        assert!(matches!(
            network_for(&test_cfg("test")),
            Network::TestNetwork
        ));
        assert!(matches!(
            network_for(&test_cfg("main")),
            Network::MainNetwork
        ));
        // Anything unrecognised falls back to mainnet — a safer default than panicking.
        assert!(matches!(
            network_for(&test_cfg("wat")),
            Network::MainNetwork
        ));
    }

    #[test]
    fn parse_ufvk_rejects_garbage() {
        let cfg = test_cfg("main");
        assert!(parse_ufvk(&cfg, &SecretString::from("not-a-ufvk".to_string())).is_err());
        assert!(parse_ufvk(&cfg, &SecretString::from(String::new())).is_err());
    }

    #[test]
    fn memo_matches_is_false_on_invalid_input() {
        // The core security guarantee: a bad UFVK or an unparseable transaction can
        // NEVER yield a true "ownership verified". It must return false — and never
        // panic — so an unverifiable input degrades to visibility_only, not control.
        let cfg = test_cfg("main");
        let bad_ufvk = SecretString::from("not-a-ufvk".to_string());
        assert!(!memo_matches(&cfg, &bad_ufvk, &[], 1_000_000, "memo"));
        assert!(!memo_matches(
            &cfg,
            &bad_ufvk,
            &[0x00, 0x01, 0x02],
            1_000_000,
            "memo"
        ));
    }
}
