# zcash-scanner

Internal, stateless Zcash **shielded-scanning** microservice for Statem. It owns the
only shielded trial-decryption in the system — the Node backend never decrypts
shielded data itself, it calls this service over private networking.

> **Sibling project.** This lives at `Solana stmt/zcash-scanner/`, beside
> `solana-statement-backend/` (not inside it). It deploys as its own Railway
> service.

## What it does

Two capability-scoped endpoints (not a generic platform):

| Method | Path | In | Out |
|---|---|---|---|
| POST | `/zcash/scan` | `{ ufvk, from_height, to_height }` | `{ received[], spent[], scanned_to_height }` — notes are `{ value_zat, height, txid, pool }`, **no memos** |
| POST | `/zcash/verify-spend` | `{ ufvk, expected_memo, from_height, to_height? }` | `{ matched: { txid, height } \| null }` |
| GET | `/healthz` | — | `ok` (unauthenticated, for platform probes) |

## Hard rules (enforced in code)

- **UFVK is transient.** Wrapped in `SecretString`, used only within the request,
  zeroized on drop. Never logged, returned, or persisted. No database.
- **Memos dropped.** `/zcash/scan` never reads memos. `/zcash/verify-spend` reads a
  memo only to match the one session challenge memo; it never returns or logs it.
- **Auth.** Every request must carry `X-Scanner-Auth: <SCANNER_SHARED_SECRET>`,
  compared in constant time. Bind to **private networking only** — never expose
  this service publicly.

## Configuration (env)

| Var | Required | Default | Notes |
|---|---|---|---|
| `LIGHTWALLETD_URL` | | `https://zec.rocks:443` | lightwalletd / Zaino gRPC endpoint. Defaults to the zec.rocks mainnet fleet (~0.99 uptime). Testnet: `https://testnet.zec.rocks:443` (+ `ZCASH_NETWORK=test`). Regional: `https://{na,eu,ap}.zec.rocks:443`. |
| `SCANNER_SHARED_SECRET` | ✅ | — | Must match the Node backend's `ZCASH_SCANNER_SECRET`. |
| `SCANNER_BIND_ADDR` | | `0.0.0.0:8080` | Private interface only. |
| `ZCASH_NETWORK` | | `main` | `main` \| `test`. |
| `SCANNER_MAX_SCAN_BLOCKS` | | `2000000` | Per-request range cap. |

## Railway deploy

1. New service from this directory; Railway builds the `Dockerfile`.
2. Attach it to the **private network**; do **not** add a public domain.
3. Set `LIGHTWALLETD_URL` + `SCANNER_SHARED_SECRET`.
4. Point the Node backend at it via `ZCASH_SCANNER_URL` (private URL) +
   `ZCASH_SCANNER_SECRET` (same value as `SCANNER_SHARED_SECRET`).

## ⚠️ Implementation status (read before deploying)

**✅ COMPILES** against the librustzcash **git HEAD** pinned in `Cargo.toml`
(`zcash_client_backend 0.14` / `zcash_primitives 0.28` / `orchard 0.14`, `tonic 0.14`).
The crates.io releases are uninstallable — orchard 0.10.x is fully yanked but the
published `zcash_primitives`/`zcash_client_backend` still pin `^0.10`, so the deps
are git-pinned. **`cargo build` succeeds (clean, no warnings).** Still UNRUN — no
lightwalletd validation has been done; see below.

The full pipeline is implemented:

- `lightwalletd.rs` — tonic `CompactTxStreamerClient` (connect/TLS, latest height,
  tree state, block-range stream, get-transaction).
- `scan.rs` — `scan_range` parses the UFVK → `ScanningKeys`, seeds positions from the
  pre-`from` tree state, streams `CompactBlock`s, trial-decrypts **received** notes via
  `scan_block`, and matches **spent** notes by nullifier from the raw block.
  `verify_spend` scans for wallet spends then fetches the full tx to match the memo.

Tree-position seeding is implemented (`seed_metadata` → `TreeState::to_chain_state()`
→ frontier `tree_size()`), so note positions/nullifiers are correct from any birthday.

**One safe seam remains:** `memo_matches()` (the shielded ownership challenge) returns
`false` until implemented — parse the full tx and try-decrypt its outputs to read the
memo (`Transaction::read` + `try_note_decryption` for Sapling/Orchard). It is left
`false` ON PURPOSE: that's the one place a wrong impl would emit a FALSE "ownership
verified", so never-match is safer than guess. Effect today: shielded statements stay
`visibility_only` even after a real challenge spend (the balance/history scan is
unaffected).

**Before trusting any figure:** run it and **validate end-to-end against
`https://testnet.zec.rocks:443`** (`ZCASH_NETWORK=test`) with a UFVK whose
balance/history you can independently confirm. Then implement `memo_matches` and
re-test the shielded ownership path with a known memo'd self-transfer.
