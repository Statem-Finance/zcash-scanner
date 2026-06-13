//! Runtime configuration, all from environment. No secrets on disk.

use secrecy::SecretString;
use std::env;

#[derive(Clone)]
pub struct Config {
    /// Address to bind the internal HTTP server to. MUST be a private interface
    /// (Railway private networking). Default binds all interfaces inside the
    /// container; the deploy is responsible for keeping it off the public net.
    pub bind_addr: String,
    /// lightwalletd / Zaino gRPC endpoint, e.g. `https://zec.rocks:443`. Required.
    pub lightwalletd_url: String,
    /// Shared secret the Node API must present in `X-Scanner-Auth`. Required.
    pub shared_secret: SecretString,
    /// "main" | "test". Selects network constants for key parsing + scanning.
    pub network: String,
    /// Hard cap on the number of blocks a single scan may span, so a pathological
    /// range can't pin the service. The Node side also caps the statement period.
    pub max_scan_blocks: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind_addr: opt("SCANNER_BIND_ADDR", "0.0.0.0:8080"),
            // Public mainnet lightwalletd (Electric Coin Co. / zec.rocks fleet,
            // ~0.99 30-day uptime). Override for testnet with
            // https://testnet.zec.rocks:443 (+ ZCASH_NETWORK=test), or a regional
            // node: https://{na,eu,ap}.zec.rocks:443.
            lightwalletd_url: opt("LIGHTWALLETD_URL", "https://zec.rocks:443"),
            shared_secret: SecretString::from(req("SCANNER_SHARED_SECRET")?),
            network: opt("ZCASH_NETWORK", "main"),
            max_scan_blocks: env::var("SCANNER_MAX_SCAN_BLOCKS")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(2_000_000),
        })
    }
}

/// Required var — errors if unset OR empty (a blank `.env` line is a misconfig).
fn req(key: &str) -> anyhow::Result<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(anyhow::anyhow!("missing/empty required env var: {key}")),
    }
}

/// Optional var with a default — treats unset OR empty (a blank `.env` line) as
/// "use the default", so `KEY=` doesn't override with an empty string.
fn opt(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}
