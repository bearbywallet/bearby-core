use crate::evm::RequiredTxParams;
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use electrum_client::{Batch, Client as ElectrumClient, ConfigBuilder, ElectrumApi, Param};
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use history::status::TransactionStatus;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::btc_utils::{
    gap_window_indices, used_indices, AddressChain, BtcAddressEntry, ByteCodec, Utxo,
};
use proto::tx::{TransactionReceipt, TransactionRequest};
use rand::seq::SliceRandom;
use rpc::common::NetworkConfigTrait;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use token::ft::FToken;

const DEFAULT_FEE_RATE_BTC: f64 = 0.00001;
const SATOSHIS_PER_BTC: f64 = 100_000_000.0;
const BYTES_PER_KB: f64 = 1000.0;
const DEFAULT_TX_SIZE_BYTES: u64 = 250;
const HISTORY_BATCH_CHUNK: usize = 50;
/// Cap missing-txid fetches per balance-sync so a large restore makes
/// bounded progress under the shared electrum timeout budget.
const BACKFILL_MAX_PER_SYNC: usize = 200; // 4 chunks of HISTORY_BATCH_CHUNK
const BTC_TOTAL_TIMEOUT_SECS: u64 = 60;
const BTC_MIN_PER_NODE_TIMEOUT: Duration = Duration::from_secs(5);
const BTC_PARALLEL_GUARD_SECS: u64 = 150;

type ChainLayout = Vec<(bitcoin::AddressType, Vec<usize>, Vec<usize>)>;

fn calculate_tx_vsize(tx: &TransactionRequest) -> u64 {
    match tx {
        TransactionRequest::Bitcoin((btc_tx, metadata, _)) => {
            let (input_vsize, output_vsize) = if let Some(ref addr) = metadata.signer {
                match addr.get_bitcoin_address_type() {
                    Ok(bitcoin::AddressType::P2wpkh) => (68, 31),
                    Ok(bitcoin::AddressType::P2tr) => (58, 43),
                    _ => (148, 34),
                }
            } else {
                (148, 34)
            };

            (btc_tx.input.len() * input_vsize + btc_tx.output.len() * output_vsize + 10) as u64
        }
        _ => DEFAULT_TX_SIZE_BYTES,
    }
}

fn f64_to_sat(v: f64) -> u64 {
    v.max(0.0).min(u64::MAX as f64).ceil() as u64
}

fn btc_fee_rate_to_sat_per_byte(fee_btc: f64) -> u64 {
    if fee_btc < 0.0 {
        f64_to_sat(DEFAULT_FEE_RATE_BTC * SATOSHIS_PER_BTC / BYTES_PER_KB)
    } else {
        f64_to_sat(fee_btc * SATOSHIS_PER_BTC / BYTES_PER_KB)
    }
}

fn build_required_params(
    slow_rate: u64,
    market_rate: u64,
    fast_rate: u64,
    vsize: u64,
) -> RequiredTxParams {
    use crate::evm::GasFeeHistory;

    let slow_fee_sat = U256::from(vsize * slow_rate);
    let market_fee_sat = U256::from(vsize * market_rate);
    let fast_fee_sat = U256::from(vsize * fast_rate);

    RequiredTxParams {
        gas_price: U256::from(market_rate),
        max_priority_fee: U256::ZERO,
        fee_history: GasFeeHistory {
            max_fee: U256::from(fast_rate),
            priority_fee: U256::ZERO,
            base_fee: U256::from(slow_rate),
        },
        tx_estimate_gas: U256::from(vsize),
        blob_base_fee: U256::ZERO,
        nonce: 0,
        slow: slow_fee_sat,
        market: market_fee_sat,
        fast: fast_fee_sat,
        current: market_fee_sat,
    }
}

fn parse_fee_histogram(value: &serde_json::Value) -> Option<(u64, u64, u64)> {
    let histogram = value.as_array()?;

    if histogram.is_empty() {
        return None;
    }

    let mut min_fee_rate = f64::MAX;

    for entry in histogram {
        let arr = entry.as_array()?;
        if arr.len() != 2 {
            continue;
        }

        let fee_rate = arr[0].as_f64()?;
        if fee_rate > 0.0 && fee_rate < min_fee_rate {
            min_fee_rate = fee_rate;
        }
    }

    if min_fee_rate == f64::MAX || min_fee_rate <= 0.0 {
        min_fee_rate = 1.0;
    }

    let slow_rate = f64_to_sat(min_fee_rate.max(1.0));
    let market_rate = f64_to_sat(min_fee_rate * 1.10);
    let fast_rate = f64_to_sat(min_fee_rate * 1.15);

    Some((slow_rate, market_rate, fast_rate))
}

/// Extract confirmation state from a verbose `blockchain.transaction.get` response.
/// Electrum verbose responses carry `confirmations` (u64, absent/0 while in mempool);
/// some servers only expose `height` (> 0 once mined).
fn btc_tx_confirmed(result: &serde_json::Value) -> bool {
    if let Some(c) = result.get("confirmations").and_then(|c| c.as_u64()) {
        return c > 0;
    }
    result
        .get("height")
        .and_then(|h| h.as_i64())
        .map(|h| h > 0)
        .unwrap_or(false)
}

/// Timestamp (ms) from a verbose tx response; `None` for mempool txs.
fn btc_tx_timestamp_ms(result: &serde_json::Value) -> Option<u64> {
    result
        .get("blocktime")
        .or_else(|| result.get("time"))
        .and_then(|t| t.as_u64())
        .map(|secs| secs * 1000)
}

/// Compute received/sent satoshis and witness UTXOs for a BTC tx relative to our scripts.
/// `witness_utxos` is filled only when every prevout resolves (fully-owned outgoing tx).
fn btc_history_io(
    tx: &bitcoin::Transaction,
    our_scripts: &HashSet<bitcoin::ScriptBuf>,
    parents: &HashMap<bitcoin::Txid, &bitcoin::Transaction>,
) -> (u64, u64, Vec<bitcoin::TxOut>) {
    let received: u64 = tx
        .output
        .iter()
        .filter(|o| our_scripts.contains(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .sum();

    let mut prevouts: Vec<Option<bitcoin::TxOut>> = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        let prev = parents
            .get(&input.previous_output.txid)
            .and_then(|p| p.output.get(input.previous_output.vout as usize))
            .cloned();
        prevouts.push(prev);
    }

    let sent: u64 = prevouts
        .iter()
        .flatten()
        .filter(|o| our_scripts.contains(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .sum();

    let all_resolved = prevouts.iter().all(Option::is_some);
    let witness_utxos: Vec<bitcoin::TxOut> = if all_resolved {
        prevouts.into_iter().flatten().collect()
    } else {
        Vec::with_capacity(0)
    };

    (received, sent, witness_utxos)
}

/// Per-run constants + precomputed io for building one history entry without
/// re-borrowing the parent map (enables a zero-clone consume of `fetched`).
struct BtcEntryBuildCtx<'a> {
    txid: bitcoin::Txid,
    tx: bitcoin::Transaction,
    result: &'a serde_json::Value,
    received: u64,
    sent: u64,
    witness_utxos: Vec<bitcoin::TxOut>,
    chain_hash: u64,
    symbol: &'a str,
    decimals: u8,
    selected_account: &'a Address,
    now_ms: u64,
}

fn build_btc_historical_entry(ctx: BtcEntryBuildCtx<'_>) -> HistoricalTransaction {
    let net_amount = ctx.received.abs_diff(ctx.sent);
    let confirmed = btc_tx_confirmed(ctx.result);

    HistoricalTransaction {
        status: if confirmed {
            TransactionStatus::Success
        } else {
            TransactionStatus::Pending
        },
        metadata: proto::tx::TransactionMetadata {
            chain_hash: ctx.chain_hash,
            hash: Some(ctx.txid.to_string()),
            info: None,
            icon: None,
            title: None,
            // First-writer-wins attribution: signer/token_info are relative to the
            // currently selected account's chains. A tx that also touches another
            // account is not re-attributed when that account syncs later (txid is
            // already in known). For pure receives, signer is the selected wallet
            // address (not the external sender) — intentional v1 trade-off.
            signer: Some(ctx.selected_account.clone()),
            token_info: Some((U256::from(net_amount), ctx.decimals, ctx.symbol.to_owned())),
            broadcast: true,
        },
        evm: None,
        scilla: None,
        btc: Some((
            ctx.tx,
            proto::btc_tx::BitcoinMetadata {
                witness_utxos: ctx.witness_utxos,
                input_meta: Vec::with_capacity(0),
            },
        )),
        tron: None,
        solana: None,
        signed_message: None,
        timestamp: btc_tx_timestamp_ms(ctx.result).unwrap_or(ctx.now_ms),
    }
}

/// Decode verbose `blockchain.transaction.get` results for a chunk of txids.
/// Missing/invalid entries are skipped (RBF-replaced, pruned, malformed hex)
/// so one bad txid cannot poison the rest of the backfill.
fn parse_tx_get_results(
    chunk: &[bitcoin::Txid],
    results: impl IntoIterator<Item = serde_json::Value>,
) -> Vec<(bitcoin::Txid, bitcoin::Transaction, serde_json::Value)> {
    use bitcoin::consensus::encode::deserialize_hex;

    let mut out = Vec::with_capacity(chunk.len());
    for (txid, result) in chunk.iter().zip(results) {
        let Some(hex) = result.get("hex").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(tx) = deserialize_hex::<bitcoin::Transaction>(hex) else {
            continue;
        };
        out.push((*txid, tx, result));
    }
    out
}

/// True when the electrum error indicates a dead/unreachable node (failover),
/// as opposed to an application-level response (e.g. unknown txid → skip).
fn is_electrum_transport_error(err: &electrum_client::Error) -> bool {
    use electrum_client::Error as E;
    // Application-level responses: server spoke — skip the txid, do not fail over.
    if matches!(
        err,
        E::Protocol(_)
            | E::InvalidResponse(_)
            | E::Message(_)
            | E::JSON(_)
            | E::Hex(_)
            | E::Bitcoin(_)
            | E::AlreadySubscribed(_)
            | E::NotSubscribed(_)
    ) {
        return false;
    }
    match err {
        E::AllAttemptsErrored(errs) => {
            !errs.is_empty() && errs.iter().all(is_electrum_transport_error)
        }
        // IO / TLS / DNS / lock / IPC / connection setup: node is dead.
        _ => true,
    }
}

fn sorted_chain_keys(
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
) -> Vec<bitcoin::AddressType> {
    let mut keys: Vec<_> = chains.keys().copied().collect();
    keys.sort_by_key(|k| k.to_byte());
    keys
}

fn build_layout<F>(chains: &HashMap<bitcoin::AddressType, AddressChain>, select: F) -> ChainLayout
where
    F: Fn(&[BtcAddressEntry]) -> Vec<usize>,
{
    let keys = sorted_chain_keys(chains);
    let mut layout = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(chain) = chains.get(&key) {
            layout.push((key, select(&chain.external), select(&chain.internal)));
        }
    }
    layout
}

fn layout_is_empty(layout: &ChainLayout) -> bool {
    layout
        .iter()
        .all(|(_, external, internal)| external.is_empty() && internal.is_empty())
}

fn prune_unused_btc_chains(chains: &mut HashMap<bitcoin::AddressType, AddressChain>) {
    chains.retain(|addr_type, chain| {
        if matches!(*addr_type, bitcoin::AddressType::P2wpkh) {
            return true;
        }
        // For non-P2wpkh chains: remove individual entries with no history,
        // keep only entries that have transaction history.
        chain.external.retain(|e| !e.history.is_empty());
        chain.internal.retain(|e| !e.history.is_empty());
        !chain.external.is_empty() || !chain.internal.is_empty()
    });
}

fn scripts_for_layout(
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
    layout: &ChainLayout,
) -> Result<Vec<bitcoin::ScriptBuf>> {
    let capacity = layout.iter().map(|(_, e, i)| e.len() + i.len()).sum();
    let mut scripts = Vec::with_capacity(capacity);
    for (key, ext_idx, int_idx) in layout {
        let Some(chain) = chains.get(key) else {
            continue;
        };
        for (slice, indices) in [(&chain.external, ext_idx), (&chain.internal, int_idx)] {
            for &i in indices {
                let entry = slice.get(i).ok_or_else(|| {
                    NetworkErrors::RPCError(format!("entry {i} missing for {key:?}"))
                })?;
                let addr = entry
                    .address
                    .to_bitcoin_addr()
                    .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;
                scripts.push(addr.script_pubkey());
            }
        }
    }
    Ok(scripts)
}

fn apply_results<T>(
    chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    layout: &ChainLayout,
    mut results: Vec<Vec<T>>,
    mut apply: impl FnMut(&mut BtcAddressEntry, Vec<T>),
) -> Result<()> {
    let mut cursor = 0usize;
    for (key, ext_idx, int_idx) in layout {
        let Some(chain) = chains.get_mut(key) else {
            continue;
        };
        for (slice, indices) in [
            (chain.external.as_mut_slice(), ext_idx),
            (chain.internal.as_mut_slice(), int_idx),
        ] {
            for &i in indices {
                let slot = results.get_mut(cursor).ok_or_else(|| {
                    NetworkErrors::RPCError(format!("missing batch result at {cursor}"))
                })?;
                let taken = std::mem::take(slot);
                cursor = cursor.saturating_add(1);
                let entry = slice.get_mut(i).ok_or_else(|| {
                    NetworkErrors::RPCError(format!("entry {i} missing for {key:?}"))
                })?;
                apply(entry, taken);
            }
        }
    }
    if cursor != results.len() {
        return Err(NetworkErrors::RPCError(format!(
            "batch returned {} results for {cursor} scripts",
            results.len()
        )));
    }
    Ok(())
}

// --- Per-client chunked fetch helpers (called inside blocking tasks) ---

fn fetch_history_chunked(
    client: &ElectrumClient,
    scripts: &[bitcoin::ScriptBuf],
) -> Result<Vec<Vec<electrum_client::GetHistoryRes>>> {
    let mut all = Vec::with_capacity(scripts.len());
    for chunk in scripts.chunks(HISTORY_BATCH_CHUNK) {
        let refs: Vec<&bitcoin::Script> = chunk.iter().map(|s| s.as_ref()).collect();
        all.extend(
            client
                .batch_script_get_history(&refs)
                .map_err(|e| NetworkErrors::RPCError(format!("batch history: {e}")))?,
        );
    }
    Ok(all)
}

fn fetch_unspent_chunked(
    client: &ElectrumClient,
    scripts: &[bitcoin::ScriptBuf],
) -> Result<Vec<Vec<electrum_client::ListUnspentRes>>> {
    let mut all = Vec::with_capacity(scripts.len());
    for chunk in scripts.chunks(HISTORY_BATCH_CHUNK) {
        let refs: Vec<&bitcoin::Script> = chunk.iter().map(|s| s.as_ref()).collect();
        all.extend(
            client
                .batch_script_list_unspent(&refs)
                .map_err(|e| NetworkErrors::RPCError(format!("batch unspent: {e}")))?,
        );
    }
    Ok(all)
}

// --- Node-level sync fetch fns: try each node in order until one succeeds ---
// These are called inside spawn_blocking so they can be fully synchronous.

fn fetch_history_from_nodes(
    node_urls: Vec<String>,
    scripts: Vec<bitcoin::ScriptBuf>,
    total_timeout: Duration,
    min_per_node: Duration,
) -> Result<Vec<Vec<electrum_client::GetHistoryRes>>> {
    let start = std::time::Instant::now();
    let mut last_error = None;
    for (i, url) in node_urls.iter().enumerate() {
        let remaining = total_timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        let nodes_left = (node_urls.len() - i) as u32;
        let per_attempt = (remaining / nodes_left.max(1)).max(min_per_node);
        let config = ConfigBuilder::new()
            .timeout(Some(per_attempt))
            .retry(0)
            .build();
        match ElectrumClient::from_config(url, config) {
            Ok(client) => match fetch_history_chunked(&client, &scripts) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    last_error = Some(e);
                }
            },
            Err(e) => {
                last_error = Some(NetworkErrors::RPCError(e.to_string()));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| NetworkErrors::RPCError("No RPC nodes".into())))
}

fn fetch_unspent_from_nodes(
    node_urls: Vec<String>,
    scripts: Vec<bitcoin::ScriptBuf>,
    total_timeout: Duration,
    min_per_node: Duration,
) -> Result<Vec<Vec<electrum_client::ListUnspentRes>>> {
    let start = std::time::Instant::now();
    let mut last_error = None;
    for (i, url) in node_urls.iter().enumerate() {
        let remaining = total_timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        let nodes_left = (node_urls.len() - i) as u32;
        let per_attempt = (remaining / nodes_left.max(1)).max(min_per_node);
        let config = ConfigBuilder::new()
            .timeout(Some(per_attempt))
            .retry(0)
            .build();
        match ElectrumClient::from_config(url, config) {
            Ok(client) => match fetch_unspent_chunked(&client, &scripts) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    last_error = Some(e);
                }
            },
            Err(e) => {
                last_error = Some(NetworkErrors::RPCError(e.to_string()));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| NetworkErrors::RPCError("No RPC nodes".into())))
}

// --- Parallel orchestrators: shard by address type, assign distinct primary nodes ---

type HistoryShard = (ChainLayout, Vec<Vec<electrum_client::GetHistoryRes>>);
type UnspentShard = (ChainLayout, Vec<Vec<electrum_client::ListUnspentRes>>);

async fn parallel_fetch_history(
    nodes: &[String],
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
    layout: &ChainLayout,
) -> Result<Vec<HistoryShard>> {
    parallel_fetch_impl(nodes, chains, layout, |node_urls, scripts| {
        fetch_history_from_nodes(
            node_urls,
            scripts,
            Duration::from_secs(BTC_TOTAL_TIMEOUT_SECS),
            BTC_MIN_PER_NODE_TIMEOUT,
        )
    })
    .await
}

async fn parallel_fetch_unspent(
    nodes: &[String],
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
    layout: &ChainLayout,
) -> Result<Vec<UnspentShard>> {
    parallel_fetch_impl(nodes, chains, layout, |node_urls, scripts| {
        fetch_unspent_from_nodes(
            node_urls,
            scripts,
            Duration::from_secs(BTC_TOTAL_TIMEOUT_SECS),
            BTC_MIN_PER_NODE_TIMEOUT,
        )
    })
    .await
}

/// Split `layout` into per-address-type shards, assign each a distinct primary node
/// (via list rotation), and run all shards concurrently via `spawn_blocking`.
async fn parallel_fetch_impl<T, F>(
    nodes: &[String],
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
    layout: &ChainLayout,
    fetch_fn: F,
) -> Result<Vec<(ChainLayout, Vec<Vec<T>>)>>
where
    T: Send + 'static,
    F: Fn(Vec<String>, Vec<bitcoin::ScriptBuf>) -> Result<Vec<Vec<T>>> + Send + Sync + 'static,
{
    if nodes.is_empty() {
        return Err(NetworkErrors::RPCError("No RPC nodes configured".into()));
    }

    let mut shuffled: Vec<String> = nodes.to_vec();
    shuffled.shuffle(&mut rand::rng());
    let num_nodes = shuffled.len();

    // Build one shard per address type present in the layout.
    let shards: Vec<(ChainLayout, Vec<bitcoin::ScriptBuf>)> = layout
        .iter()
        .filter_map(|(addr_type, ext_idx, int_idx)| {
            let sub = vec![(*addr_type, ext_idx.clone(), int_idx.clone())];
            let scripts = scripts_for_layout(chains, &sub).ok()?;
            if scripts.is_empty() {
                None
            } else {
                Some((sub, scripts))
            }
        })
        .collect();

    if shards.is_empty() {
        return Ok(vec![]);
    }

    use std::sync::Arc;
    let fetch_fn = Arc::new(fetch_fn);
    let mut set: tokio::task::JoinSet<Result<(ChainLayout, Vec<Vec<T>>)>> =
        tokio::task::JoinSet::new();

    for (i, (sub_layout, scripts)) in shards.into_iter().enumerate() {
        // Rotate so shard i starts at a different node than shard i-1.
        let mut shard_nodes = shuffled.clone();
        shard_nodes.rotate_left(i % num_nodes);
        let fetch_fn = Arc::clone(&fetch_fn);

        set.spawn_blocking(move || {
            let results = fetch_fn(shard_nodes, scripts)?;
            Ok((sub_layout, results))
        });
    }

    tokio::time::timeout(Duration::from_secs(BTC_PARALLEL_GUARD_SECS), async {
        let mut out = Vec::new();
        while let Some(res) = set.join_next().await {
            out.push(res.map_err(|e| NetworkErrors::RPCError(e.to_string()))??);
        }
        Ok(out)
    })
    .await
    .map_err(|_| {
        NetworkErrors::RPCError(format!(
            "parallel BTC sync timed out after {BTC_PARALLEL_GUARD_SECS}s"
        ))
    })?
}

impl NetworkProvider {
    fn with_electrum_client<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut(&ElectrumClient) -> Result<T>,
    {
        let start = std::time::Instant::now();
        let total_deadline = Duration::from_secs(BTC_TOTAL_TIMEOUT_SECS);
        let mut last_error = None;

        let mut urls: Vec<&String> = self.config.nodes().iter().collect();
        urls.shuffle(&mut rand::rng());

        for (i, url) in urls.iter().enumerate() {
            let remaining = total_deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }
            let nodes_left = (urls.len() - i) as u32;
            let per_attempt = (remaining / nodes_left.max(1)).max(BTC_MIN_PER_NODE_TIMEOUT);
            if per_attempt.is_zero() {
                break;
            }

            let config = ConfigBuilder::new()
                .timeout(Some(per_attempt))
                .retry(0)
                .build();

            match ElectrumClient::from_config(url, config) {
                Ok(client) => match operation(&client) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    last_error = Some(NetworkErrors::RPCError(e.to_string()));
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No RPC URLs configured".to_string())))
    }
}

#[async_trait]
pub trait BtcOperations {
    async fn btc_get_current_block_number(&self) -> Result<u64>;
    async fn btc_estimate_params_batch(&self, tx: &TransactionRequest) -> Result<RequiredTxParams>;
    async fn btc_estimate_block_time(&self) -> Result<u64>;
    async fn btc_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn btc_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn btc_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
        selected_account: &Address,
    ) -> Result<()>;
    /// Fetch full transaction objects for txids present in `chains` entry.history
    /// but absent from `known_ids` (the wallet's stored history for this chain).
    /// `known_txs` supplies full bodies for parent/prevout lookup only (borrowed —
    /// no clone of stored history on the steady-state path).
    /// Returns ready-to-store HistoricalTransaction entries.
    /// Issues NO network calls when nothing is missing.
    /// Unfetchable txids (RBF-replaced, pruned) are skipped; partial results are OK.
    async fn btc_scan_history_txns(
        &self,
        chains: &HashMap<bitcoin::AddressType, AddressChain>,
        known_ids: &HashSet<bitcoin::Txid>,
        known_txs: &HashMap<bitcoin::Txid, &bitcoin::Transaction>,
        selected_account: &Address,
    ) -> Result<Vec<HistoricalTransaction>>;
    async fn btc_list_unspent(
        &self,
        address: &Address,
    ) -> Result<Vec<electrum_client::ListUnspentRes>>;
    async fn batch_script_get_history(
        &self,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()>;
    async fn batch_btc_list_unspent(
        &self,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()>;
}

#[async_trait]
impl BtcOperations for NetworkProvider {
    async fn btc_get_current_block_number(&self) -> Result<u64> {
        self.with_electrum_client(|client| {
            let header_notification = client.block_headers_subscribe().map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get block header: {}", e))
            })?;
            Ok(header_notification.height as u64)
        })
    }

    async fn btc_estimate_params_batch(&self, tx: &TransactionRequest) -> Result<RequiredTxParams> {
        const FAST_BLOCKS: usize = 1;
        const MARKET_BLOCKS: usize = 3;
        const SLOW_BLOCKS: usize = 6;

        let vsize = calculate_tx_vsize(tx);

        self.with_electrum_client(|client| {
            let mut batch = Batch::default();
            batch.raw("mempool.get_fee_histogram".to_string(), vec![]);

            let results = client.batch_call(&batch);

            if let Ok(histogram_results) = results {
                if let Some(histogram_value) = histogram_results.first() {
                    if let Some((slow_rate, market_rate, fast_rate)) =
                        parse_fee_histogram(histogram_value)
                    {
                        return Ok(build_required_params(
                            slow_rate,
                            market_rate,
                            fast_rate,
                            vsize,
                        ));
                    }
                }
            }

            let mut batch = Batch::default();
            batch.estimate_fee(FAST_BLOCKS, None);
            batch.estimate_fee(MARKET_BLOCKS, None);
            batch.estimate_fee(SLOW_BLOCKS, None);

            let results = client
                .batch_call(&batch)
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to estimate fee: {}", e)))?;

            let fast_fee_btc = results
                .first()
                .and_then(|v| v.as_f64())
                .unwrap_or(DEFAULT_FEE_RATE_BTC);
            let market_fee_btc = results
                .get(1)
                .and_then(|v| v.as_f64())
                .unwrap_or(DEFAULT_FEE_RATE_BTC);
            let slow_fee_btc = results
                .get(2)
                .and_then(|v| v.as_f64())
                .unwrap_or(DEFAULT_FEE_RATE_BTC);

            let fast_rate = btc_fee_rate_to_sat_per_byte(fast_fee_btc).max(1);
            let market_rate = btc_fee_rate_to_sat_per_byte(market_fee_btc).max(1);
            let slow_rate = btc_fee_rate_to_sat_per_byte(slow_fee_btc).max(1);

            Ok(build_required_params(
                slow_rate,
                market_rate,
                fast_rate,
                vsize,
            ))
        })
    }

    async fn btc_estimate_block_time(&self) -> Result<u64> {
        const BLOCK_SAMPLE_SIZE: usize = 100;

        self.with_electrum_client(|client| {
            let current_header = client.block_headers_subscribe().map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get current block: {}", e))
            })?;

            let current_height = current_header.height;
            let start_height = current_height.saturating_sub(BLOCK_SAMPLE_SIZE);

            let heights = vec![start_height as u32, current_height as u32];
            let headers = client.batch_block_header(heights).map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get block headers: {}", e))
            })?;

            if headers.len() < 2 {
                return Ok(600);
            }

            let time_diff = headers[1].time.saturating_sub(headers[0].time);
            let block_diff = current_height.saturating_sub(start_height);

            if block_diff == 0 || time_diff == 0 {
                return Ok(600);
            }

            let avg_block_time = time_diff as u64 / block_diff as u64;

            if avg_block_time == 0 {
                return Ok(1);
            }

            Ok(avg_block_time)
        })
    }

    async fn btc_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        if txns.is_empty() {
            return Ok(());
        }

        self.with_electrum_client(|client| {
            use bitcoin::consensus::encode::deserialize_hex;
            use bitcoin::Txid;
            use std::collections::HashMap;
            use std::str::FromStr;

            let mut ordered_txids: Vec<Txid> = Vec::with_capacity(txns.len());
            let mut txid_to_idx: HashMap<Txid, usize> = HashMap::with_capacity(txns.len());

            for (idx, tx) in txns.iter().enumerate() {
                if tx.status != TransactionStatus::Pending {
                    continue;
                }

                let txid = tx.get_btc().map(|(t, _)| t.compute_txid()).or_else(|| {
                    tx.metadata
                        .hash
                        .as_deref()
                        .and_then(|s| Txid::from_str(s).ok())
                });

                if let Some(txid) = txid {
                    if txid_to_idx.insert(txid, idx).is_none() {
                        ordered_txids.push(txid);
                    }
                }
            }

            if ordered_txids.is_empty() {
                return Ok(());
            }

            let mut batch = Batch::default();
            for txid in &ordered_txids {
                batch.raw(
                    "blockchain.transaction.get".to_string(),
                    vec![Param::String(txid.to_string()), Param::Bool(true)],
                );
            }

            let results = client.batch_call(&batch).map_err(|e| {
                NetworkErrors::RPCError(format!("transaction.get batch failed: {}", e))
            })?;

            if results.len() != ordered_txids.len() {
                return Err(NetworkErrors::RPCError(format!(
                    "transaction.get batch returned {} results for {} txids",
                    results.len(),
                    ordered_txids.len()
                )));
            }

            for (i, txid) in ordered_txids.iter().enumerate() {
                let Some(&original_idx) = txid_to_idx.get(txid) else {
                    continue;
                };
                let result = &results[i];

                let hex = result.get("hex").and_then(|v| v.as_str()).ok_or_else(|| {
                    NetworkErrors::RPCError(format!(
                        "missing 'hex' in transaction.get response for {}",
                        txid
                    ))
                })?;

                let transaction: bitcoin::Transaction = deserialize_hex(hex).map_err(|e| {
                    NetworkErrors::RPCError(format!("failed to decode tx {} hex: {}", txid, e))
                })?;

                let tx_ref = &mut txns[original_idx];
                tx_ref.update_btc_tx(transaction);
                tx_ref.status = if btc_tx_confirmed(result) {
                    TransactionStatus::Success
                } else {
                    TransactionStatus::Pending
                };
            }

            Ok(())
        })
    }

    async fn btc_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        for tx_receipt in &txns {
            if !tx_receipt.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }
        }

        for tx_receipt in txns.iter_mut() {
            if let TransactionReceipt::Bitcoin((tx, metadata, _btc_meta)) = tx_receipt {
                let txid = self.with_electrum_client(|client| {
                    let txid = client.transaction_broadcast(tx).map_err(|e| {
                        NetworkErrors::RPCError(format!("Failed to broadcast transaction: {}", e))
                    })?;

                    Ok(txid)
                })?;

                metadata.hash = Some(txid.to_string());
            } else {
                return Err(NetworkErrors::RPCError(
                    "Expected Bitcoin transaction".to_string(),
                ));
            }
        }

        Ok(txns)
    }

    async fn btc_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
        selected_account: &Address,
    ) -> Result<()> {
        if tokens.is_empty() || chains.is_empty() {
            return Ok(());
        }

        let no_recorded_balance = tokens
            .iter()
            .find(|t| t.native)
            .map(|t| !t.balances.contains_key(&selected_account.to_hash()))
            .unwrap_or(true);

        let no_history = chains.values().all(|c| {
            c.external.iter().all(|e| e.history.is_empty())
                && c.internal.iter().all(|e| e.history.is_empty())
        });

        let nodes = self.config.nodes().to_vec();

        if no_recorded_balance && no_history {
            // Full scan: history across all addresses in parallel, then UTXOs for used ones.
            let full = build_layout(chains, |entries| (0..entries.len()).collect());
            if !layout_is_empty(&full) {
                for (sub_layout, results) in parallel_fetch_history(&nodes, chains, &full).await? {
                    apply_results(chains, &sub_layout, results, |entry, history| {
                        entry.history = history.into_iter().map(|h| h.tx_hash).collect();
                    })?;
                }
                prune_unused_btc_chains(chains);

                let used = build_layout(chains, used_indices);
                if !layout_is_empty(&used) {
                    for (sub_layout, results) in
                        parallel_fetch_unspent(&nodes, chains, &used).await?
                    {
                        apply_results(chains, &sub_layout, results, |entry, unspents| {
                            entry.utxos = unspents.into_iter().map(Utxo::from).collect();
                        })?;
                    }
                }
            }
        } else {
            // Frontier scan: gap-window history + UTXO refresh for used addresses — in parallel.
            let frontier = build_layout(chains, gap_window_indices);
            if !layout_is_empty(&frontier) {
                for (sub_layout, results) in
                    parallel_fetch_history(&nodes, chains, &frontier).await?
                {
                    apply_results(chains, &sub_layout, results, |entry, history| {
                        if !history.is_empty() {
                            entry.history = history.into_iter().map(|h| h.tx_hash).collect();
                        }
                    })?;
                }
            }

            let used = build_layout(chains, used_indices);
            if !layout_is_empty(&used) {
                for (sub_layout, results) in parallel_fetch_unspent(&nodes, chains, &used).await? {
                    apply_results(chains, &sub_layout, results, |entry, unspents| {
                        entry.utxos = unspents.into_iter().map(Utxo::from).collect();
                    })?;
                }
            }

            prune_unused_btc_chains(chains);
        }

        let total: u64 = chains
            .values()
            .flat_map(|chain| chain.external.iter().chain(chain.internal.iter()))
            .flat_map(|entry| entry.utxos.iter())
            .map(|u| u.value)
            .sum();

        for token in tokens.iter_mut() {
            if token.native {
                token
                    .balances
                    .insert(selected_account.to_hash(), U256::from(total));
            }
        }

        Ok(())
    }

    async fn btc_scan_history_txns(
        &self,
        chains: &HashMap<bitcoin::AddressType, AddressChain>,
        known_ids: &HashSet<bitcoin::Txid>,
        known_txs: &HashMap<bitcoin::Txid, &bitcoin::Transaction>,
        selected_account: &Address,
    ) -> Result<Vec<HistoricalTransaction>> {
        // 1. Dedupe all txids across every entry (ext+int, all address types);
        //    a tx spending our utxo and paying our change appears in several entries.
        //    Iterate sorted address-type keys so a capped backfill makes deterministic
        //    progress across successive syncs.
        let approx_history: usize = chains
            .values()
            .flat_map(|c| c.external.iter().chain(c.internal.iter()))
            .map(|e| e.history.len())
            .sum();
        let mut missing: Vec<bitcoin::Txid> =
            Vec::with_capacity(approx_history.min(BACKFILL_MAX_PER_SYNC));
        let mut seen: HashSet<bitcoin::Txid> = HashSet::with_capacity(approx_history);
        for key in sorted_chain_keys(chains) {
            let Some(chain) = chains.get(&key) else {
                continue;
            };
            for entry in chain.external.iter().chain(chain.internal.iter()) {
                for txid in &entry.history {
                    if !known_ids.contains(txid) && seen.insert(*txid) {
                        missing.push(*txid);
                    }
                }
            }
        }

        if missing.is_empty() {
            return Ok(Vec::new()); // steady state: zero node requests
        }

        // Bounded progress under the shared electrum timeout budget.
        if missing.len() > BACKFILL_MAX_PER_SYNC {
            missing.truncate(BACKFILL_MAX_PER_SYNC);
        }

        // 2. Our scripts, for direction/amount computation.
        let entry_count: usize = chains
            .values()
            .map(|c| c.external.len() + c.internal.len())
            .sum();
        let mut our_scripts: HashSet<bitcoin::ScriptBuf> = HashSet::with_capacity(entry_count);
        for chain in chains.values() {
            for entry in chain.external.iter().chain(chain.internal.iter()) {
                if let Ok(addr) = entry.address.to_bitcoin_addr() {
                    our_scripts.insert(addr.script_pubkey());
                }
            }
        }

        // 3. Fetch verbose tx objects, chunked, through node-failover.
        //    One unfetchable txid must not poison the whole batch (RBF/dropped).
        //    Permanently missing txids stay in entry.history and are re-tried on
        //    every sync (cheap: one slot in a batch); a tombstone/negative-cache
        //    is future work if that ever shows up in profiles.
        let chain_hash = self.config.hash();
        let (symbol, decimals) = self
            .config
            .ftokens
            .iter()
            .find(|t| t.native)
            .map(|t| (t.symbol.clone(), t.decimals))
            .unwrap_or_else(|| ("BTC".to_string(), 8));

        let fetched: Vec<(bitcoin::Txid, bitcoin::Transaction, serde_json::Value)> =
            self.with_electrum_client(|client| {
                let mut out = Vec::with_capacity(missing.len());
                for chunk in missing.chunks(HISTORY_BATCH_CHUNK) {
                    let mut batch = Batch::default();
                    for txid in chunk {
                        batch.raw(
                            "blockchain.transaction.get".to_string(),
                            vec![Param::String(txid.to_string()), Param::Bool(true)],
                        );
                    }
                    let results = match client.batch_call(&batch) {
                        Ok(r) if r.len() == chunk.len() => r,
                        _ => {
                            // Batch poisoned (e.g. RBF-replaced txid) or node glitch —
                            // fall back to per-txid calls.
                            // Protocol errors (unknown txid) → skip that tx.
                            // Transport errors on every call → node dead, fail over.
                            let mut per_tx = Vec::with_capacity(chunk.len());
                            let mut transport_errors = 0usize;
                            for txid in chunk {
                                match client.raw_call(
                                    "blockchain.transaction.get",
                                    [
                                        Param::String(txid.to_string()),
                                        Param::Bool(true),
                                    ],
                                ) {
                                    Ok(val) => per_tx.push(val),
                                    Err(e) if is_electrum_transport_error(&e) => {
                                        transport_errors += 1;
                                        per_tx.push(serde_json::Value::Null);
                                    }
                                    Err(_) => {
                                        // Application-level (Protocol, etc.): skip txid.
                                        per_tx.push(serde_json::Value::Null);
                                    }
                                }
                            }
                            if transport_errors == chunk.len() {
                                return Err(NetworkErrors::RPCError(
                                    "transaction.get fallback: all calls failed".to_string(),
                                ));
                            }
                            per_tx
                        }
                    };
                    out.extend(parse_tx_get_results(chunk, results));
                }
                Ok(out)
            })?;

        // 4. Parent lookup = known_txs ∪ fetched. Any input WE own was funded by a tx
        //    that touched our address, so its parent is guaranteed to be in this map;
        //    unresolvable parents belong to other people's inputs (pure receives).
        let mut parents: HashMap<bitcoin::Txid, &bitcoin::Transaction> =
            HashMap::with_capacity(known_txs.len() + fetched.len());
        for (id, tx) in known_txs {
            parents.insert(*id, *tx);
        }
        for (txid, tx, _) in &fetched {
            parents.insert(*txid, tx);
        }

        // 5. Two-pass build: compute borrow-dependent io while parents is live,
        //    then drop parents and move txs out of fetched (no full-tx clone).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ios: Vec<(u64, u64, Vec<bitcoin::TxOut>)> = fetched
            .iter()
            .map(|(_, tx, _)| btc_history_io(tx, &our_scripts, &parents))
            .collect();
        drop(parents);

        let mut history = Vec::with_capacity(fetched.len());
        for ((txid, tx, result), (received, sent, witness_utxos)) in
            fetched.into_iter().zip(ios)
        {
            history.push(build_btc_historical_entry(BtcEntryBuildCtx {
                txid,
                tx,
                result: &result,
                received,
                sent,
                witness_utxos,
                chain_hash,
                symbol: &symbol,
                decimals,
                selected_account,
                now_ms,
            }));
        }

        Ok(history)
    }

    async fn btc_list_unspent(
        &self,
        address: &Address,
    ) -> Result<Vec<electrum_client::ListUnspentRes>> {
        let btc_addr = address
            .to_bitcoin_addr()
            .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;
        let script = btc_addr.script_pubkey();

        let unspents = self.with_electrum_client(|client| {
            client
                .script_list_unspent(script.as_ref())
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to list unspent: {}", e)))
        })?;
        Ok(unspents)
    }

    async fn batch_script_get_history(
        &self,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()> {
        if chains.is_empty() {
            return Ok(());
        }

        let layout = build_layout(chains, |entries| (0..entries.len()).collect());
        if layout_is_empty(&layout) {
            return Ok(());
        }

        let nodes = self.config.nodes().to_vec();
        for (sub_layout, results) in parallel_fetch_history(&nodes, chains, &layout).await? {
            apply_results(chains, &sub_layout, results, |entry, history| {
                entry.history = history.into_iter().map(|h| h.tx_hash).collect();
            })?;
        }
        prune_unused_btc_chains(chains);
        Ok(())
    }

    async fn batch_btc_list_unspent(
        &self,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()> {
        if chains.is_empty() {
            return Ok(());
        }

        let layout = build_layout(chains, used_indices);
        if layout_is_empty(&layout) {
            return Ok(());
        }

        let nodes = self.config.nodes().to_vec();
        for (sub_layout, results) in parallel_fetch_unspent(&nodes, chains, &layout).await? {
            apply_results(chains, &sub_layout, results, |entry, unspents| {
                entry.utxos = unspents.into_iter().map(Utxo::from).collect();
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_data::{gen_btc_testnet_conf, gen_btc_token};

    #[tokio::test]
    async fn test_get_block_number_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let block_number = provider.btc_get_current_block_number().await.unwrap();
        assert!(block_number > 0);
    }

    #[tokio::test]
    async fn test_update_balances_btc() {
        use crypto::bip49::{DerivationPath, DerivationType};
        use crypto::slip44;
        use proto::btc_utils::BtcAddressEntry;

        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let mut btc_token = gen_btc_token();

        let test_addr = "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z";
        let addr = Address::Secp256k1Bitcoin(test_addr.as_bytes().to_vec());

        let path = DerivationPath::new(
            slip44::BITCOIN,
            DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP84_PURPOSE,
        );
        let entry = BtcAddressEntry {
            address: addr.clone(),
            path,
            history: vec![],
            utxos: vec![],
        };
        let mut chains: HashMap<bitcoin::AddressType, AddressChain> = HashMap::new();
        chains.insert(
            bitcoin::AddressType::P2wpkh,
            AddressChain {
                external: vec![entry.clone()],
                internal: vec![entry],
            },
        );

        let tokens_refs = vec![&mut btc_token];

        provider
            .btc_update_balances(tokens_refs, &mut chains, &addr)
            .await
            .unwrap();

        assert!(btc_token.balances.contains_key(&addr.to_hash()));
    }

    #[tokio::test]
    async fn test_estimate_block_time_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let block_time = provider.btc_estimate_block_time().await.unwrap();

        assert!(block_time > 0);
    }

    #[tokio::test]
    async fn test_estimate_params_batch_btc() {
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut};
        use proto::tx::TransactionMetadata;

        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_metadata = TransactionMetadata::default();
        assert!(tx_metadata.broadcast);
        let tx_request = TransactionRequest::Bitcoin((
            dummy_tx,
            tx_metadata,
            proto::btc_tx::BitcoinMetadata {
                witness_utxos: vec![],
                input_meta: vec![],
            },
        ));

        let params = provider
            .btc_estimate_params_batch(&tx_request)
            .await
            .unwrap();

        assert!(params.gas_price > U256::ZERO);
        assert_eq!(params.max_priority_fee, U256::ZERO);
        assert_eq!(params.blob_base_fee, U256::ZERO);
        assert!(params.tx_estimate_gas > U256::ZERO);
        assert!(params.slow > U256::ZERO);
        assert!(params.market > U256::ZERO);
        assert!(params.fast > U256::ZERO);
        assert_eq!(params.current, params.market);
        assert!(params.slow <= params.market);
        assert!(params.market <= params.fast);
    }

    #[test]
    fn test_parse_fee_histogram_correct_units() {
        use serde_json::json;

        let histogram = json!([[20.0, 100000], [10.0, 100000], [5.0, 100000]]);

        let result = parse_fee_histogram(&histogram);

        assert!(result.is_some());
        let (slow, market, fast) = result.unwrap();

        assert_eq!(slow, 5);
        assert_eq!(market, 6);
        assert_eq!(fast, 6);
        assert!(slow <= market);
        assert!(market <= fast);
    }

    #[test]
    fn test_parse_fee_histogram_min_fee_extraction() {
        use serde_json::json;

        let histogram = json!([
            [100.0, 50000],
            [50.0, 100000],
            [10.0, 200000],
            [3.0, 300000]
        ]);

        let result = parse_fee_histogram(&histogram);
        assert!(result.is_some());
        let (slow, market, fast) = result.unwrap();

        assert_eq!(slow, 3);
        assert_eq!(market, 4);
        assert_eq!(fast, 4);
    }

    #[test]
    fn test_parse_fee_histogram_empty() {
        use serde_json::json;

        let histogram = json!([]);
        let result = parse_fee_histogram(&histogram);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_fee_histogram_fallback_to_minimum() {
        use serde_json::json;

        let histogram = json!([[0.5, 100000]]);

        let result = parse_fee_histogram(&histogram);
        assert!(result.is_some());
        let (slow, market, fast) = result.unwrap();

        assert_eq!(slow, 1);
        assert_eq!(market, 1);
        assert_eq!(fast, 1);
    }

    fn anvil_seed() -> secrecy::SecretBox<[u8; config::sha::SHA512_SIZE]> {
        use config::bip39::EN_WORDS;
        use pqbip39::mnemonic::Mnemonic;
        use secrecy::SecretString;
        use test_data::ANVIL_MNEMONIC;

        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        mnemonic.to_seed(&SecretString::from("")).unwrap()
    }

    #[tokio::test]
    async fn test_batch_script_get_history_empty_chains() {
        use test_data::gen_btc_regtest_conf;

        let provider = NetworkProvider::new(gen_btc_regtest_conf());
        let mut chains: HashMap<bitcoin::AddressType, AddressChain> = HashMap::new();

        provider
            .batch_script_get_history(&mut chains)
            .await
            .unwrap();

        assert!(chains.is_empty());
    }

    #[tokio::test]
    async fn test_batch_script_get_history_account_zero() {
        use proto::btc_utils::{derive_btc_addresses_from_xpubs, BtcAccountXpubsInput, GAP_LIMIT};
        use test_data::gen_btc_regtest_conf;

        let provider = NetworkProvider::new(gen_btc_regtest_conf());
        let seed = anvil_seed();

        let xpubs = BtcAccountXpubsInput::from_seed(&seed, 0, bitcoin::Network::Bitcoin).unwrap();
        let mut chains = HashMap::new();
        derive_btc_addresses_from_xpubs(
            &xpubs,
            0,
            bitcoin::Network::Bitcoin,
            0,
            GAP_LIMIT,
            &mut chains,
        )
        .unwrap();

        let original_lengths: HashMap<bitcoin::AddressType, usize> =
            chains.iter().map(|(k, c)| (*k, c.external.len())).collect();

        provider
            .batch_script_get_history(&mut chains)
            .await
            .unwrap();

        // P2WPKH is unconditionally retained and its entries are never pruned,
        // so its length is preserved regardless of on-chain history.
        assert!(
            chains.contains_key(&bitcoin::AddressType::P2wpkh),
            "P2WPKH must survive pruning"
        );
        assert_eq!(
            chains[&bitcoin::AddressType::P2wpkh].external.len(),
            original_lengths[&bitcoin::AddressType::P2wpkh],
            "P2WPKH external entries must never be pruned"
        );

        // All other address types are pruned: only entries with on-chain history survive.
        for (addr_type, chain) in &chains {
            if *addr_type == bitcoin::AddressType::P2wpkh {
                continue;
            }
            for entry in chain.external.iter().chain(chain.internal.iter()) {
                assert!(
                    !entry.history.is_empty(),
                    "{:?} entry with empty history survived pruning",
                    addr_type
                );
            }
        }
    }

    #[test]
    fn test_prune_unused_btc_chains() {
        use crypto::bip49::{DerivationPath, DerivationType};
        use crypto::slip44;
        use proto::btc_utils::{AddressChain, BtcAddressEntry};
        use std::str::FromStr;

        let mk_entry = |has_history: bool| -> BtcAddressEntry {
            BtcAddressEntry {
                address: Address::Secp256k1Bitcoin(b"bc1qtest".to_vec()),
                path: DerivationPath::new(
                    slip44::BITCOIN,
                    DerivationType::AddressIndex(0, 0, 0),
                    DerivationPath::BIP84_PURPOSE,
                ),
                history: if has_history {
                    vec![bitcoin::Txid::from_str(
                        "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f",
                    )
                    .unwrap()]
                } else {
                    Vec::new()
                },
                utxos: Vec::new(),
            }
        };

        let mk_chain = |has_history: bool| -> AddressChain {
            AddressChain {
                external: vec![mk_entry(has_history)],
                internal: vec![mk_entry(has_history)],
            }
        };

        // P2wpkh always survives, even with no history.
        {
            let mut chains = HashMap::new();
            chains.insert(bitcoin::AddressType::P2wpkh, mk_chain(false));
            prune_unused_btc_chains(&mut chains);
            assert_eq!(chains.len(), 1);
            assert!(chains.contains_key(&bitcoin::AddressType::P2wpkh));
        }

        // P2tr, P2pkh, P2sh all pruned when no history.
        {
            let mut chains = HashMap::new();
            chains.insert(bitcoin::AddressType::P2tr, mk_chain(false));
            chains.insert(bitcoin::AddressType::P2pkh, mk_chain(false));
            chains.insert(bitcoin::AddressType::P2sh, mk_chain(false));
            prune_unused_btc_chains(&mut chains);
            assert!(chains.is_empty());
        }

        // Non-P2wpkh without history: chain removed entirely.
        {
            let mut chains = HashMap::new();
            chains.insert(bitcoin::AddressType::P2tr, mk_chain(true));
            chains.insert(bitcoin::AddressType::P2pkh, mk_chain(false));
            prune_unused_btc_chains(&mut chains);
            assert_eq!(chains.len(), 1);
            assert!(chains.contains_key(&bitcoin::AddressType::P2tr));
            let p2tr = chains.get(&bitcoin::AddressType::P2tr).unwrap();
            assert_eq!(p2tr.external.len(), 1); // entry with history kept
            assert_eq!(p2tr.internal.len(), 1); // entry with history kept
        }

        // P2wpkh always survives; non-P2wpkh with history survives but empty entries removed.
        {
            let mut chains = HashMap::new();
            chains.insert(bitcoin::AddressType::P2wpkh, mk_chain(false));
            chains.insert(bitcoin::AddressType::P2tr, mk_chain(true));
            chains.insert(bitcoin::AddressType::P2pkh, mk_chain(false));
            prune_unused_btc_chains(&mut chains);
            assert_eq!(chains.len(), 2);
            assert!(chains.contains_key(&bitcoin::AddressType::P2wpkh));
            assert!(chains.contains_key(&bitcoin::AddressType::P2tr));
            assert!(!chains.contains_key(&bitcoin::AddressType::P2pkh));
        }

        // History in internal chain only: external pruned, internal kept.
        {
            let mut chains = HashMap::new();
            chains.insert(
                bitcoin::AddressType::P2tr,
                AddressChain {
                    external: vec![mk_entry(false)],
                    internal: vec![mk_entry(true)],
                },
            );
            prune_unused_btc_chains(&mut chains);
            assert!(chains.contains_key(&bitcoin::AddressType::P2tr));
            let p2tr = chains.get(&bitcoin::AddressType::P2tr).unwrap();
            assert!(p2tr.external.is_empty()); // no-history entry removed
            assert_eq!(p2tr.internal.len(), 1); // history entry kept
        }
    }

    #[test]
    fn test_btc_tx_confirmed() {
        use serde_json::json;

        assert!(btc_tx_confirmed(&json!({"confirmations": 3})));
        assert!(!btc_tx_confirmed(&json!({"confirmations": 0})));
        assert!(btc_tx_confirmed(&json!({"height": 812345})));
        assert!(!btc_tx_confirmed(&json!({"height": 0})));
        assert!(!btc_tx_confirmed(&json!({})));
        // Regression: weight must never be treated as confirmations.
        assert!(!btc_tx_confirmed(&json!({"weight": 565})));
        // confirmations takes precedence over height.
        assert!(!btc_tx_confirmed(
            &json!({"confirmations": 0, "height": 812345})
        ));
        assert!(btc_tx_confirmed(
            &json!({"confirmations": 1, "height": 0})
        ));
    }

    #[test]
    fn test_btc_tx_timestamp_ms() {
        use serde_json::json;

        assert_eq!(
            btc_tx_timestamp_ms(&json!({"blocktime": 1_700_000_000})),
            Some(1_700_000_000_000)
        );
        assert_eq!(
            btc_tx_timestamp_ms(&json!({"time": 1_700_000_001})),
            Some(1_700_000_001_000)
        );
        // blocktime preferred over time.
        assert_eq!(
            btc_tx_timestamp_ms(&json!({"blocktime": 100, "time": 200})),
            Some(100_000)
        );
        assert_eq!(btc_tx_timestamp_ms(&json!({})), None);
    }

    #[test]
    fn test_btc_history_io_direction_and_amount() {
        use bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
            Transaction, TxIn, TxOut, Witness,
        };
        use serde_json::json;
        use std::str::FromStr;

        let our_script = ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::from_str("00112233445566778899aabbccddeeff00112233").unwrap(),
        );
        let their_script = ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::from_str("ffeeddccbbaa99887766554433221100ffeeddcc").unwrap(),
        );

        let mut our_scripts = HashSet::with_capacity(1);
        our_scripts.insert(our_script.clone());

        // Parent funds our script with 50_000 sats.
        let parent_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: our_script.clone(),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        // Pure receive: someone pays us 10_000 (no resolvable prevouts we own).
        let receive_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_str(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: our_script.clone(),
            }],
        };
        let parents_empty: HashMap<bitcoin::Txid, &Transaction> = HashMap::new();
        let (recv, sent, witness) = btc_history_io(&receive_tx, &our_scripts, &parents_empty);
        assert_eq!(recv, 10_000);
        assert_eq!(sent, 0);
        assert!(witness.is_empty(), "unresolved prevouts → no witness_utxos");

        // Outgoing: we spend the parent and pay them 40_000, change 9_000 to us.
        let send_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: their_script,
                },
                TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: our_script.clone(),
                },
            ],
        };
        let mut parents: HashMap<bitcoin::Txid, &Transaction> = HashMap::with_capacity(1);
        parents.insert(parent_txid, &parent_tx);
        let (recv, sent, witness) = btc_history_io(&send_tx, &our_scripts, &parents);
        assert_eq!(recv, 9_000);
        assert_eq!(sent, 50_000);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].value.to_sat(), 50_000);

        let net = recv.abs_diff(sent);
        assert_eq!(net, 41_000); // 50k sent − 9k change

        let send_txid = send_tx.compute_txid();
        let result = json!({
            "confirmations": 2,
            "blocktime": 1_700_000_000,
            "hex": "00"
        });
        let selected = Address::Secp256k1Bitcoin(b"bc1qtest".to_vec());
        let entry = build_btc_historical_entry(BtcEntryBuildCtx {
            txid: send_txid,
            tx: send_tx,
            result: &result,
            received: recv,
            sent,
            witness_utxos: witness,
            chain_hash: 42,
            symbol: "BTC",
            decimals: 8,
            selected_account: &selected,
            now_ms: 99,
        });
        assert_eq!(entry.status, TransactionStatus::Success);
        assert_eq!(entry.timestamp, 1_700_000_000_000);
        assert_eq!(entry.metadata.chain_hash, 42);
        assert_eq!(
            entry.metadata.token_info,
            Some((U256::from(41_000u64), 8, "BTC".to_string()))
        );
        let (_, meta) = entry.get_btc().expect("btc payload");
        assert_eq!(meta.witness_utxos.len(), 1);
    }

    #[test]
    fn test_is_electrum_transport_error() {
        use electrum_client::Error as E;
        use std::io::{Error as IoError, ErrorKind};

        assert!(
            is_electrum_transport_error(&E::IOError(IoError::from(ErrorKind::ConnectionRefused))),
            "IO errors are transport"
        );
        assert!(
            !is_electrum_transport_error(&E::Protocol(serde_json::json!("tx not found"))),
            "Protocol (unknown txid) must not trigger failover"
        );
        assert!(
            !is_electrum_transport_error(&E::Message("no such tx".into())),
            "application Message must not trigger failover"
        );
        assert!(
            is_electrum_transport_error(&E::AllAttemptsErrored(vec![E::IOError(
                IoError::from(ErrorKind::TimedOut)
            )])),
            "all-transport AllAttemptsErrored is transport"
        );
        assert!(
            !is_electrum_transport_error(&E::AllAttemptsErrored(vec![E::Protocol(
                serde_json::json!(null)
            )])),
            "all-protocol AllAttemptsErrored is not transport"
        );
    }

    #[test]
    fn test_parse_tx_get_results_skips_unfetchable() {
        use bitcoin::consensus::encode::serialize_hex;
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxOut};
        use serde_json::json;
        use std::str::FromStr;

        let good_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let good_txid = good_tx.compute_txid();
        let good_hex = serialize_hex(&good_tx);

        let bad_txid = bitcoin::Txid::from_str(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let poison_txid = bitcoin::Txid::from_str(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap();
        let malformed_txid = bitcoin::Txid::from_str(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();

        let chunk = [bad_txid, good_txid, poison_txid, malformed_txid];
        let results = vec![
            serde_json::Value::Null, // unfetchable
            json!({"hex": good_hex, "confirmations": 1}),
            json!({}),               // missing hex
            json!({"hex": "not-valid-hex"}),
        ];

        let parsed = parse_tx_get_results(&chunk, results);
        assert_eq!(parsed.len(), 1, "only the valid tx must survive");
        assert_eq!(parsed[0].0, good_txid);
        assert_eq!(parsed[0].1.compute_txid(), good_txid);
        assert!(btc_tx_confirmed(&parsed[0].2));
    }
}
