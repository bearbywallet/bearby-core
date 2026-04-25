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
use proto::btc_utils::{AddressChain, ByteCodec};
use proto::tx::{TransactionReceipt, TransactionRequest};
use std::collections::HashMap;
use token::ft::FToken;

const DEFAULT_FEE_RATE_BTC: f64 = 0.00001;
const SATOSHIS_PER_BTC: f64 = 100_000_000.0;
const BYTES_PER_KB: f64 = 1000.0;
const DEFAULT_TX_SIZE_BYTES: u64 = 250;
const HISTORY_BATCH_CHUNK: usize = 25;

fn calculate_tx_vsize(tx: &TransactionRequest) -> u64 {
    match tx {
        TransactionRequest::Bitcoin((btc_tx, metadata)) => {
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

fn btc_fee_rate_to_sat_per_byte(fee_btc: f64) -> u64 {
    if fee_btc < 0.0 {
        (DEFAULT_FEE_RATE_BTC * SATOSHIS_PER_BTC / BYTES_PER_KB) as u64
    } else {
        (fee_btc * SATOSHIS_PER_BTC / BYTES_PER_KB) as u64
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

    let slow_rate = min_fee_rate.max(1.0).ceil() as u64;
    let market_rate = (min_fee_rate * 1.10).ceil() as u64;
    let fast_rate = (min_fee_rate * 1.15).ceil() as u64;

    Some((slow_rate, market_rate, fast_rate))
}

impl NetworkProvider {
    fn with_electrum_client<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut(&ElectrumClient) -> Result<T>,
    {
        let mut last_error = None;
        let mut errors = String::with_capacity(200);

        for url in &self.config.rpc {
            let config = ConfigBuilder::new().timeout(Some(5)).build();

            match ElectrumClient::from_config(url, config) {
                Ok(client) => match operation(&client) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        errors.push_str(&format!("Operation failed on {}: {}. ", url, e));
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    errors.push_str(&format!("Failed to connect to {}: {}. ", url, e));
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
        accounts: &[&Address],
    ) -> Result<()>;
    async fn btc_list_unspent(
        &self,
        address: &Address,
    ) -> Result<Vec<electrum_client::ListUnspentRes>>;
    async fn batch_script_get_history(
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
            batch.estimate_fee(FAST_BLOCKS);
            batch.estimate_fee(MARKET_BLOCKS);
            batch.estimate_fee(SLOW_BLOCKS);

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
        use std::collections::HashMap;

        if txns.is_empty() {
            return Ok(());
        }

        self.with_electrum_client(|client| {
            let mut txid_to_index: HashMap<String, usize> = HashMap::new();
            let mut batch = Batch::default();

            for (idx, tx) in txns.iter().enumerate() {
                let txid_str = match tx
                    .get_btc()
                    .and_then(|b| {
                        b.get("txid")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    })
                    .or_else(|| tx.metadata.hash.clone())
                {
                    Some(s) => s,
                    None => continue,
                };

                batch.raw(
                    "blockchain.transaction.get".to_string(),
                    vec![Param::String(txid_str.clone()), Param::Bool(true)],
                );
                txid_to_index.insert(txid_str, idx);
            }

            if txid_to_index.is_empty() {
                return Ok(());
            }

            let results = client.batch_call(&batch).map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to batch get transactions: {}", e))
            })?;

            for (_txid_str, idx) in txid_to_index.iter() {
                let tx = &mut txns[*idx];

                if let Some(result) = results.get(*idx) {
                    let confirmations = result
                        .get("confirmations")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0);

                    let mut tx_data = result.clone();
                    if let Some(obj) = tx_data.as_object_mut() {
                        obj.remove("hex");
                    }

                    tx.set_btc(tx_data);

                    if confirmations >= 1 {
                        tx.status = TransactionStatus::Success;
                    } else {
                        tx.status = TransactionStatus::Pending;
                    }
                }
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
            if let TransactionReceipt::Bitcoin((tx, metadata)) = tx_receipt {
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
        accounts: &[&Address],
    ) -> Result<()> {
        if accounts.is_empty() || tokens.is_empty() {
            return Ok(());
        }

        let mut scripts = Vec::with_capacity(accounts.len());
        for addr in accounts {
            let btc_addr = addr
                .to_bitcoin_addr()
                .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;
            scripts.push(btc_addr.script_pubkey());
        }

        let script_refs: Vec<_> = scripts.iter().map(|s| s.as_ref()).collect();
        let balances = self.with_electrum_client(|client| {
            client
                .batch_script_get_balance(&script_refs)
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to get balances: {}", e)))
        })?;

        for token in tokens.iter_mut() {
            if token.native {
                for (account, balance) in accounts.iter().zip(balances.iter()) {
                    let confirmed = balance.confirmed;
                    let unconfirmed = if balance.unconfirmed < 0 {
                        0u64
                    } else {
                        balance.unconfirmed as u64
                    };
                    let total_balance = confirmed + unconfirmed;
                    token
                        .balances
                        .insert(account.to_hash(), U256::from(total_balance));
                }
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

        self.with_electrum_client(|client| {
            let unspents = client
                .script_list_unspent(script.as_ref())
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to list unspent: {}", e)))?;
            Ok(unspents)
        })
    }

    async fn batch_script_get_history(
        &self,
        chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()> {
        if chains.is_empty() {
            return Ok(());
        }

        let mut keys: Vec<bitcoin::AddressType> = chains.keys().copied().collect();
        keys.sort_by_key(|k| k.to_byte());

        let mut scripts: Vec<bitcoin::ScriptBuf> = Vec::new();
        let mut layout: Vec<(bitcoin::AddressType, usize)> = Vec::with_capacity(keys.len());

        for key in &keys {
            let chain = chains.get(key).expect("key from map");
            if chain.external.len() != chain.internal.len() {
                return Err(NetworkErrors::RPCError(format!(
                    "AddressChain length mismatch for {:?}: external={}, internal={}",
                    key,
                    chain.external.len(),
                    chain.internal.len()
                )));
            }
            let n = chain.external.len();
            for i in 0..n {
                scripts.push(chain.external[i].address.script_pubkey());
                scripts.push(chain.internal[i].address.script_pubkey());
            }
            layout.push((*key, n));
        }

        if scripts.is_empty() {
            return Ok(());
        }

        let script_refs: Vec<&bitcoin::Script> = scripts.iter().map(|s| s.as_ref()).collect();
        let mut results = self.with_electrum_client(|client| {
            let mut all: Vec<Vec<electrum_client::GetHistoryRes>> =
                Vec::with_capacity(script_refs.len());
            for chunk in script_refs.chunks(HISTORY_BATCH_CHUNK) {
                let chunk_results = client.batch_script_get_history(chunk).map_err(|e| {
                    NetworkErrors::RPCError(format!("Failed to batch script history: {}", e))
                })?;
                all.extend(chunk_results);
            }
            Ok(all)
        })?;

        let mut cursor = 0usize;
        for (addr_type, n) in layout {
            let chain = chains.get_mut(&addr_type).expect("layout key");
            let mut last_used: Option<usize> = None;

            for i in 0..n {
                let ext_history = std::mem::take(&mut results[cursor]);
                cursor += 1;
                let int_history = std::mem::take(&mut results[cursor]);
                cursor += 1;

                let ext_txids: Vec<bitcoin::Txid> =
                    ext_history.into_iter().map(|h| h.tx_hash).collect();
                let int_txids: Vec<bitcoin::Txid> =
                    int_history.into_iter().map(|h| h.tx_hash).collect();

                let both_empty = ext_txids.is_empty() && int_txids.is_empty();
                chain.external[i].history = ext_txids;
                chain.internal[i].history = int_txids;

                if !both_empty {
                    last_used = Some(i);
                }
            }

            let old_ext = std::mem::take(&mut chain.external);
            let old_int = std::mem::take(&mut chain.internal);

            if addr_type == bitcoin::AddressType::P2tr {
                if let Some(last) = last_used {
                    let mut new_ext = Vec::with_capacity(last + 2);
                    let mut new_int = Vec::with_capacity(last + 2);

                    for (i, (ext_entry, int_entry)) in
                        old_ext.into_iter().zip(old_int.into_iter()).enumerate()
                    {
                        if i <= last {
                            if !ext_entry.history.is_empty() {
                                new_ext.push(ext_entry);
                            }
                            if !int_entry.history.is_empty() {
                                new_int.push(int_entry);
                            }
                        } else if i == last + 1 {
                            new_ext.push(ext_entry);
                            new_int.push(int_entry);
                            break;
                        }
                    }

                    chain.external = new_ext;
                    chain.internal = new_int;
                } else {
                    let mut old_ext_iter = old_ext.into_iter();
                    let mut old_int_iter = old_int.into_iter();
                    if let (Some(ext), Some(int)) = (old_ext_iter.next(), old_int_iter.next()) {
                        chain.external = vec![ext];
                        chain.internal = vec![int];
                    }
                }
            } else {
                chain.external = old_ext
                    .into_iter()
                    .filter(|e| !e.history.is_empty())
                    .collect();
                chain.internal = old_int
                    .into_iter()
                    .filter(|e| !e.history.is_empty())
                    .collect();
            }
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
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let mut btc_token = gen_btc_token();

        let test_addr = "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z";
        let addr = Address::Secp256k1Bitcoin(test_addr.as_bytes().to_vec());
        let accounts = [&addr];

        let tokens_refs = vec![&mut btc_token];

        provider
            .btc_update_balances(tokens_refs, &accounts)
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
        let tx_request = TransactionRequest::Bitcoin((dummy_tx, tx_metadata));

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

    #[tokio::test]
    async fn test_btc_update_transactions_receipt() {
        use proto::tx::TransactionMetadata;
        use serde_json::json;

        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let tx_hash = "2c7e682a78010b47c812e4785c52831002b28486dc16998c77133510de9076a1";

        let mut test_tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                hash: Some(tx_hash.to_string()),
                ..Default::default()
            },
            evm: None,
            scilla: None,
            btc: Some(json!({"txid": tx_hash}).to_string()),
            tron: None,
            solana: None,
            signed_message: None,
            timestamp: 0,
        };
        assert!(test_tx.metadata.broadcast);

        let mut txns = vec![&mut test_tx];

        let result = provider.btc_update_transactions_receipt(&mut txns).await;

        if let Ok(_) = result {
            if let Some(btc_data) = test_tx.get_btc() {
                println!("{}", serde_json::to_string_pretty(&btc_data).unwrap());
            }
        }

        assert!(result.is_ok());
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
        use proto::btc_utils::{generate_btc_addresses, GAP_LIMIT};

        let seed = anvil_seed();
        let chains =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT).unwrap();

        let mut all_scripthashes: Vec<String> = Vec::new();

        for (addr_type, chain) in &chains {
            for (label, vec) in [("ext", &chain.external), ("int", &chain.internal)] {
                for entry in vec.iter().take(2) {
                    let script = entry.address.script_pubkey();
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
        use proto::btc_utils::{generate_btc_addresses, GAP_LIMIT};
        use test_data::gen_btc_regtest_conf;

        let provider = NetworkProvider::new(gen_btc_regtest_conf());
        let seed = anvil_seed();

        let mut chains =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT).unwrap();

        let original_lengths: HashMap<bitcoin::AddressType, usize> =
            chains.iter().map(|(k, c)| (*k, c.external.len())).collect();

        provider
            .batch_script_get_history(&mut chains)
            .await
            .unwrap();

        for (addr_type, chain) in &chains {
            assert!(
                chain.external.len() <= original_lengths[addr_type],
                "{:?} external chain unexpectedly grew",
                addr_type
            );
            assert!(
                chain.internal.len() <= original_lengths[addr_type],
                "{:?} internal chain unexpectedly grew",
                addr_type
            );
            for (i, entry) in chain.external.iter().enumerate() {
                if *addr_type == bitcoin::AddressType::P2tr
                    && entry.history.is_empty()
                    && i + 1 == chain.external.len()
                {
                    continue;
                }
                assert!(
                    !entry.history.is_empty(),
                    "{:?} kept external index {} should have history",
                    addr_type,
                    i,
                );
            }
            for (i, entry) in chain.internal.iter().enumerate() {
                if *addr_type == bitcoin::AddressType::P2tr
                    && entry.history.is_empty()
                    && i + 1 == chain.internal.len()
                {
                    continue;
                }
                assert!(
                    !entry.history.is_empty(),
                    "{:?} kept internal index {} should have history",
                    addr_type,
                    i,
                );
            }
        }
    }
}
