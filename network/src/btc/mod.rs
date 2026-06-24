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
use std::collections::HashMap;
use std::time::Duration;
use token::ft::FToken;

const DEFAULT_FEE_RATE_BTC: f64 = 0.00001;
const SATOSHIS_PER_BTC: f64 = 100_000_000.0;
const BYTES_PER_KB: f64 = 1000.0;
const DEFAULT_TX_SIZE_BYTES: u64 = 250;
const HISTORY_BATCH_CHUNK: usize = 50;
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
    eprintln!(
        "[btc-net] history shard: {} scripts, {} candidate nodes, budget={}s",
        scripts.len(),
        node_urls.len(),
        total_timeout.as_secs()
    );
    for (i, url) in node_urls.iter().enumerate() {
        let remaining = total_timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            eprintln!("[btc-net] history shard: total budget exhausted after {} attempts", i);
            break;
        }
        let nodes_left = (node_urls.len() - i) as u32;
        let per_attempt = (remaining / nodes_left.max(1)).max(min_per_node);
        eprintln!(
            "[btc-net] history shard: trying node[{}] {} (timeout={}ms)",
            i,
            url,
            per_attempt.as_millis()
        );
        let config = ConfigBuilder::new()
            .timeout(Some(per_attempt))
            .retry(0)
            .build();
        match ElectrumClient::from_config(url, config) {
            Ok(client) => match fetch_history_chunked(&client, &scripts) {
                Ok(r) => {
                    eprintln!(
                        "[btc-net] history shard: OK from {} in {}ms",
                        url,
                        start.elapsed().as_millis()
                    );
                    return Ok(r);
                }
                Err(e) => {
                    eprintln!("[btc-net] history shard: node {} op failed: {}", url, e);
                    last_error = Some(e);
                }
            },
            Err(e) => {
                eprintln!("[btc-net] history shard: node {} connect failed: {}", url, e);
                last_error = Some(NetworkErrors::RPCError(e.to_string()));
            }
        }
    }
    eprintln!(
        "[btc-net] history shard: all nodes failed after {}ms",
        start.elapsed().as_millis()
    );
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
    eprintln!(
        "[btc-net] utxo shard: {} scripts, {} candidate nodes, budget={}s",
        scripts.len(),
        node_urls.len(),
        total_timeout.as_secs()
    );
    for (i, url) in node_urls.iter().enumerate() {
        let remaining = total_timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            eprintln!("[btc-net] utxo shard: total budget exhausted after {} attempts", i);
            break;
        }
        let nodes_left = (node_urls.len() - i) as u32;
        let per_attempt = (remaining / nodes_left.max(1)).max(min_per_node);
        eprintln!(
            "[btc-net] utxo shard: trying node[{}] {} (timeout={}ms)",
            i,
            url,
            per_attempt.as_millis()
        );
        let config = ConfigBuilder::new()
            .timeout(Some(per_attempt))
            .retry(0)
            .build();
        match ElectrumClient::from_config(url, config) {
            Ok(client) => match fetch_unspent_chunked(&client, &scripts) {
                Ok(r) => {
                    eprintln!(
                        "[btc-net] utxo shard: OK from {} in {}ms",
                        url,
                        start.elapsed().as_millis()
                    );
                    return Ok(r);
                }
                Err(e) => {
                    eprintln!("[btc-net] utxo shard: node {} op failed: {}", url, e);
                    last_error = Some(e);
                }
            },
            Err(e) => {
                eprintln!("[btc-net] utxo shard: node {} connect failed: {}", url, e);
                last_error = Some(NetworkErrors::RPCError(e.to_string()));
            }
        }
    }
    eprintln!(
        "[btc-net] utxo shard: all nodes failed after {}ms",
        start.elapsed().as_millis()
    );
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

    eprintln!(
        "[btc-net] parallel fetch: {} total nodes available (shuffled)",
        num_nodes
    );

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
        eprintln!("[btc-net] parallel fetch: no non-empty shards, skipping");
        return Ok(vec![]);
    }

    eprintln!(
        "[btc-net] parallel fetch: spawning {} shards concurrently",
        shards.len()
    );

    use std::sync::Arc;
    let fetch_fn = Arc::new(fetch_fn);
    let mut set: tokio::task::JoinSet<Result<(ChainLayout, Vec<Vec<T>>)>> =
        tokio::task::JoinSet::new();

    for (i, (sub_layout, scripts)) in shards.into_iter().enumerate() {
        // Rotate so shard i starts at a different node than shard i-1.
        let mut shard_nodes = shuffled.clone();
        shard_nodes.rotate_left(i % num_nodes);
        let primary = shard_nodes.first().cloned().unwrap_or_default();
        let addr_type = sub_layout.first().map(|(t, _, _)| format!("{t:?}")).unwrap_or_default();
        eprintln!(
            "[btc-net] shard[{}] addr_type={} scripts={} primary_node={}",
            i,
            addr_type,
            scripts.len(),
            primary
        );
        let fetch_fn = Arc::clone(&fetch_fn);

        set.spawn_blocking(move || {
            let results = fetch_fn(shard_nodes, scripts)?;
            Ok((sub_layout, results))
        });
    }

    let overall_start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(BTC_PARALLEL_GUARD_SECS),
        async {
            let mut out = Vec::new();
            while let Some(res) = set.join_next().await {
                out.push(res.map_err(|e| NetworkErrors::RPCError(e.to_string()))??);
            }
            Ok(out)
        },
    )
    .await
    .map_err(|_| {
        NetworkErrors::RPCError(format!(
            "parallel BTC sync timed out after {BTC_PARALLEL_GUARD_SECS}s"
        ))
    })?;

    match &result {
        Ok(shards) => eprintln!(
            "[btc-net] parallel fetch: all {} shards done in {}ms",
            shards.len(),
            overall_start.elapsed().as_millis()
        ),
        Err(e) => eprintln!(
            "[btc-net] parallel fetch: failed after {}ms: {}",
            overall_start.elapsed().as_millis(),
            e
        ),
    }

    result
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

        eprintln!(
            "[btc-net] single-call: {} candidate nodes, budget={}s",
            urls.len(),
            BTC_TOTAL_TIMEOUT_SECS
        );

        for (i, url) in urls.iter().enumerate() {
            let remaining = total_deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                eprintln!("[btc-net] single-call: budget exhausted after {} attempts", i);
                break;
            }
            let nodes_left = (urls.len() - i) as u32;
            let per_attempt =
                (remaining / nodes_left.max(1)).max(BTC_MIN_PER_NODE_TIMEOUT);
            if per_attempt.is_zero() {
                break;
            }

            eprintln!(
                "[btc-net] single-call: trying node[{}] {} (timeout={}ms)",
                i,
                url,
                per_attempt.as_millis()
            );

            let config = ConfigBuilder::new()
                .timeout(Some(per_attempt))
                .retry(0)
                .build();

            match ElectrumClient::from_config(url, config) {
                Ok(client) => match operation(&client) {
                    Ok(result) => {
                        eprintln!(
                            "[btc-net] single-call: OK from {} in {}ms",
                            url,
                            start.elapsed().as_millis()
                        );
                        return Ok(result);
                    }
                    Err(e) => {
                        eprintln!("[btc-net] single-call: node {} op failed: {}", url, e);
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    eprintln!("[btc-net] single-call: node {} connect failed: {}", url, e);
                    last_error = Some(NetworkErrors::RPCError(e.to_string()));
                }
            }
        }

        eprintln!(
            "[btc-net] single-call: all nodes failed after {}ms",
            start.elapsed().as_millis()
        );
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

                let confirmations = result.get("weight").and_then(|c| c.as_u64()).unwrap_or(0);

                let tx_ref = &mut txns[original_idx];
                tx_ref.update_btc_tx(transaction);
                tx_ref.status = if confirmations > 0 {
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
        let addr_count: usize = chains
            .values()
            .map(|c| c.external.len() + c.internal.len())
            .sum();

        eprintln!(
            "[btc-net] btc_update_balances: addr_types={} total_addrs={} nodes={} \
             no_balance={} no_history={}",
            chains.len(),
            addr_count,
            nodes.len(),
            no_recorded_balance,
            no_history
        );

        if no_recorded_balance && no_history {
            // Full scan: history across all addresses in parallel, then UTXOs for used ones.
            eprintln!("[btc-net] btc_update_balances: path=FULL_SCAN");
            let full = build_layout(chains, |entries| (0..entries.len()).collect());
            if !layout_is_empty(&full) {
                for (sub_layout, results) in
                    parallel_fetch_history(&nodes, chains, &full).await?
                {
                    apply_results(chains, &sub_layout, results, |entry, history| {
                        entry.history = history.into_iter().map(|h| h.tx_hash).collect();
                    })?;
                }
                prune_unused_btc_chains(chains);

                let used = build_layout(chains, used_indices);
                let used_count: usize = used.iter().map(|(_, e, i)| e.len() + i.len()).sum();
                eprintln!("[btc-net] btc_update_balances: full scan used_addrs={}", used_count);
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
            eprintln!("[btc-net] btc_update_balances: path=FRONTIER_SCAN");
            let frontier = build_layout(chains, gap_window_indices);
            let frontier_count: usize = frontier.iter().map(|(_, e, i)| e.len() + i.len()).sum();
            eprintln!(
                "[btc-net] btc_update_balances: frontier_addrs={}",
                frontier_count
            );
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
            let used_count: usize = used.iter().map(|(_, e, i)| e.len() + i.len()).sum();
            eprintln!("[btc-net] btc_update_balances: frontier used_addrs={}", used_count);
            if !layout_is_empty(&used) {
                for (sub_layout, results) in
                    parallel_fetch_unspent(&nodes, chains, &used).await?
                {
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

        eprintln!(
            "[btc-net] btc_update_balances: done total_satoshis={} ({})",
            total,
            selected_account
        );

        for token in tokens.iter_mut() {
            if token.native {
                token
                    .balances
                    .insert(selected_account.to_hash(), U256::from(total));
            }
        }

        Ok(())
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

    #[test]
    fn print_get_history_payloads() {
        use bitcoin::hashes::{sha256, Hash};
        use proto::btc_utils::{derive_btc_addresses_from_xpubs, BtcAccountXpubsInput, GAP_LIMIT};

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

        let mut all_scripthashes: Vec<String> = Vec::new();

        for (addr_type, chain) in &chains {
            for (label, vec) in [("ext", &chain.external), ("int", &chain.internal)] {
                for entry in vec.iter().take(2) {
                    let script = entry.address.to_bitcoin_addr().unwrap().script_pubkey();
                    let mut sh = sha256::Hash::hash(script.as_bytes()).to_byte_array();
                    sh.reverse();
                    let sh_hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
                    println!(
                        "{:?} {} {} -> sh={}",
                        addr_type, label, entry.address, sh_hex
                    );
                    all_scripthashes.push(sh_hex);
                }
            }
        }

        println!("\n--- single-call payload (paste into openssl s_client, append \\n) ---");
        println!(
            r#"{{"id":1,"method":"blockchain.scripthash.get_history","params":["{}"]}}"#,
            all_scripthashes[0]
        );

        println!("\n--- batch (3) payload ---");
        let batch_items: Vec<String> = all_scripthashes
            .iter()
            .take(3)
            .enumerate()
            .map(|(i, sh)| {
                format!(
                    r#"{{"id":{},"method":"blockchain.scripthash.get_history","params":["{}"]}}"#,
                    i + 1,
                    sh
                )
            })
            .collect();
        println!("[{}]", batch_items.join(","));
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

        for (addr_type, chain) in &chains {
            assert_eq!(
                chain.external.len(),
                original_lengths[addr_type],
                "{:?} external chain length changed",
                addr_type
            );
            assert_eq!(
                chain.internal.len(),
                original_lengths[addr_type],
                "{:?} internal chain length changed",
                addr_type
            );
        }

        // P2WPKH must always survive pruning (unconditionally retained).
        assert!(
            chains.contains_key(&bitcoin::AddressType::P2wpkh),
            "P2WPKH must survive pruning"
        );
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
}
