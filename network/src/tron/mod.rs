mod responses;

use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use prost::Message;
use proto::address::Address;
use proto::tron_generated::protocol;
use proto::tron_tx::TronTransaction;
use proto::tx::{TransactionReceipt, TransactionRequest};
use reqwest::Client;
use responses::*;
use serde_json::json;
use std::time::Duration;

const TRON_REQUEST_TIMEOUT_SECS: u64 = 8;
const TRON_ATTEMPT_TIMEOUT_SECS: u64 = 25;
const TRON_TOTAL_TIMEOUT_SECS: u64 = 60;
const TRON_MAX_RETRIES: usize = 3;
const TRON_BLOCK_TIME_SECS: u64 = 3;
const BLOCK_SAMPLE_SIZE: u64 = 10;
// Transaction size constants for bandwidth calculation.
// Matches snap-tron-wallet FeeCalculatorService.ts:43-55 and java-tron's
// bandwidth formula: raw_data_bytes + signature(65) + result_padding(64) +
// protobuf_overhead(5).
const SIGNATURE_SIZE: i64 = 65;
const MAX_RESULT_SIZE_IN_TX: i64 = 64;
const PROTOBUF_OVERHEAD: i64 = 5;
/// Total unsigned transaction overhead in bytes.
const UNSIGNED_TX_OVERHEAD: i64 = SIGNATURE_SIZE + MAX_RESULT_SIZE_IN_TX + PROTOBUF_OVERHEAD; // 134

// Fee constants (in SUN — 1 TRX = 1_000_000 SUN).
pub const FEE_LIMIT: i64 = 100_000_000; // 100 TRX — user-controlled cap (snap-tron-wallet default)
const ACCOUNT_ACTIVATION_FEE_SUN: i64 = 1_000_000; // 1 TRX
const MEMO_FEE_SUN: i64 = 1_000_000; // 1 TRX

// Default fallback values.
const DEFAULT_FALLBACK_ENERGY: i64 = 130_000;
const DEFAULT_ENERGY_FEE: i64 = 420; // SUN per energy unit (Tron mainnet)
const DEFAULT_TRANSACTION_FEE: i64 = 1000; // SUN per bandwidth byte

macro_rules! tron_retry {
    ($self:expr, $method:expr, |$client:ident| $body:expr) => {{
        let retry_start = std::time::Instant::now();
        let total_deadline = Duration::from_secs(TRON_TOTAL_TIMEOUT_SECS);
        let mut last_error = None;
        let endpoints = $self.tron_endpoints();
        for (_i, endpoint) in endpoints.iter().take(TRON_MAX_RETRIES).enumerate() {
            let elapsed = retry_start.elapsed();
            if elapsed >= total_deadline {
                break;
            }
            let remaining = total_deadline - elapsed;
            let per_attempt = Duration::from_secs(TRON_ATTEMPT_TIMEOUT_SECS).min(remaining);
            match tokio::time::timeout(per_attempt, async {
                let $client = TronHttpClient::new(endpoint)?;
                $body
            })
            .await
            {
                Ok(Ok(val)) => {
                    return Ok(val);
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                    last_error = Some(NetworkErrors::RPCError(format!(
                        "Timeout {}s: {}",
                        TRON_REQUEST_TIMEOUT_SECS, endpoint
                    )));
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No Tron nodes configured".into())))
    }};
}

struct TronHttpClient {
    client: Client,
    base_url: String,
}

impl TronHttpClient {
    fn new(base_url: &str) -> std::result::Result<Self, NetworkErrors> {
        let client = Client::builder()
            .timeout(Duration::from_secs(TRON_REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| NetworkErrors::RPCError(format!("HTTP client error: {}", e)))?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    async fn post<Req: serde::Serialize, Res: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Req,
    ) -> std::result::Result<Res, NetworkErrors> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| NetworkErrors::RPCError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| NetworkErrors::RPCError(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(NetworkErrors::RPCError(format!(
                "HTTP {}: {}",
                status, text
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| NetworkErrors::RPCError(format!("JSON parse error: {} - {}", e, text)))
    }

    async fn get_now_block(&self) -> std::result::Result<BlockResponse, NetworkErrors> {
        let body: serde_json::Value = json!({});
        self.post("/wallet/getnowblock", &body).await
    }

    async fn get_block_by_num(
        &self,
        num: i64,
    ) -> std::result::Result<BlockResponse, NetworkErrors> {
        let body = NumberMessage { num };
        self.post("/wallet/getblockbynum", &body).await
    }

    async fn get_chain_parameters(
        &self,
    ) -> std::result::Result<ChainParamsResponse, NetworkErrors> {
        let body: serde_json::Value = json!({});
        self.post("/wallet/getchainparameters", &body).await
    }

    async fn trigger_constant_contract(
        &self,
        owner_address: Vec<u8>,
        contract_address: Vec<u8>,
        data: Vec<u8>,
    ) -> std::result::Result<TriggerContractResponse, NetworkErrors> {
        let body = TriggerSmartContractRequest {
            owner_address: alloy::hex::encode(&owner_address),
            contract_address: alloy::hex::encode(&contract_address),
            data: alloy::hex::encode(&data),
            call_value: None,
        };
        self.post("/wallet/triggerconstantcontract", &body).await
    }

    async fn broadcast_transaction(
        &self,
        tx_json: &serde_json::Value,
    ) -> std::result::Result<BroadcastResponse, NetworkErrors> {
        self.post("/wallet/broadcasttransaction", tx_json).await
    }

    async fn get_account_net(
        &self,
        address: &Address,
    ) -> std::result::Result<AccountNetResponse, NetworkErrors> {
        let tron_addr = address.auto_format();
        let body = json!({
            "address": &tron_addr,
            "visible": true
        });
        self.post("/wallet/getaccountnet", &body).await
    }

    async fn get_account_resource(
        &self,
        address: &Address,
    ) -> std::result::Result<AccountResourceResponse, NetworkErrors> {
        let tron_addr = address.auto_format();
        let body = json!({
            "address": &tron_addr,
            "visible": true
        });
        self.post("/wallet/getaccountresource", &body).await
    }

    async fn get_contract(
        &self,
        address: &Address,
    ) -> std::result::Result<ContractResponse, NetworkErrors> {
        let tron_addr = address.auto_format();
        let body = json!({
            "value": &tron_addr,
            "visible": true
        });
        self.post("/wallet/getcontract", &body).await
    }

    async fn get_account(
        &self,
        address: &Address,
    ) -> std::result::Result<AccountResponse, NetworkErrors> {
        let tron_addr = address.auto_format();
        let body = json!({
            "address": &tron_addr,
            "visible": true
        });
        self.post("/wallet/getaccount", &body).await
    }
}

impl NetworkProvider {
    fn tron_endpoints(&self) -> Vec<String> {
        self.config
            .rpc
            .iter()
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .cloned()
            .collect()
    }
}

#[async_trait]
pub trait TronOperations {
    async fn tron_get_current_block_number(&self) -> Result<u64>;
    async fn tron_estimate_block_time(&self) -> Result<u64>;
    async fn tron_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams>;
    async fn tron_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn tron_fill_block_ref(&self, tx: &mut TronTransaction) -> Result<()>;
}

#[async_trait]
impl TronOperations for NetworkProvider {
    async fn tron_get_current_block_number(&self) -> Result<u64> {
        tron_retry!(self, "get_block_number", |client| {
            let block = client.get_now_block().await?;
            block
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.number as u64)
                .ok_or(NetworkErrors::ResponseParseError)
        })
    }

    async fn tron_estimate_block_time(&self) -> Result<u64> {
        tron_retry!(self, "estimate_block_time", |client| {
            let current = client.get_now_block().await?;

            let header = current
                .block_header
                .and_then(|h| h.raw_data)
                .ok_or(NetworkErrors::ResponseParseError)?;
            let current_num = header.number as u64;
            let current_ts = header.timestamp as u64;

            if current_num < BLOCK_SAMPLE_SIZE {
                return Ok(TRON_BLOCK_TIME_SECS);
            }

            let earlier_block = client
                .get_block_by_num((current_num - BLOCK_SAMPLE_SIZE) as i64)
                .await?;
            let earlier_ts = earlier_block
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.timestamp as u64)
                .ok_or(NetworkErrors::ResponseParseError)?;

            let time_diff_ms = current_ts.saturating_sub(earlier_ts);
            if time_diff_ms == 0 {
                return Ok(TRON_BLOCK_TIME_SECS);
            }

            Ok((time_diff_ms / (BLOCK_SAMPLE_SIZE * 1000)).max(1))
        })
    }

    async fn tron_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams> {
        tron_retry!(self, "estimate_params_batch", |client| {
            let chain_params = client.get_chain_parameters().await?;

            let energy_fee = chain_params
                .chain_parameter
                .iter()
                .find(|p| p.key == "getEnergyFee")
                .map(|p| p.value as u64)
                .unwrap_or(DEFAULT_ENERGY_FEE as u64);

            let transaction_fee = chain_params
                .chain_parameter
                .iter()
                .find(|p| p.key == "getTransactionFee")
                .map(|p| p.value as u64)
                .unwrap_or(DEFAULT_TRANSACTION_FEE as u64);

            let fee_estimate = match tx {
                TransactionRequest::Tron((tron_tx, _)) => {
                    let contract_type = tron_tx.contract_type().unwrap_or("");
                    match contract_type {
                        "TransferContract" => {
                            let account_net = client.get_account_net(sender).await?;

                            let encoded_size = tron_tx.encode().len() as i64;
                            let tx_size = encoded_size + UNSIGNED_TX_OVERHEAD;
                            let free_net_available =
                                account_net.free_net_limit - account_net.free_net_used;

                            let bandwidth_fee = if free_net_available >= tx_size {
                                0u64
                            } else {
                                let bandwidth_needed = tx_size - free_net_available.max(0);
                                bandwidth_needed as u64 * transaction_fee
                            };

                            // Account activation: 1 TRX per unactivated recipient
                            let activation_fee = {
                                let mut fee: u64 = 0;
                                for contract in tron_tx.raw().contract.iter() {
                                    // We're in the TransferContract match arm
                                    if let Ok(tc) = protocol::TransferContract::decode(
                                        contract.parameter.as_ref()
                                            .map(|p| p.value.as_slice())
                                            .unwrap_or(&[]),
                                    ) {
                                        if tc.amount > 0 {
                                            let recipient = Address::from_tron_bytes(
                                                &tc.to_address,
                                            );
                                            if let Ok(ref addr) = recipient {
                                                match client.get_account(addr).await {
                                                    Ok(resp) if resp.address.is_none() => {
                                                        fee += ACCOUNT_ACTIVATION_FEE_SUN as u64;
                                                    }
                                                    Err(_) => {
                                                        // Assume unactivated on error
                                                        fee += ACCOUNT_ACTIVATION_FEE_SUN as u64;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                                fee
                            };
                            let memo_fee = if tron_tx.raw().data.is_empty() {
                                0u64
                            } else {
                                MEMO_FEE_SUN as u64
                            };
                            bandwidth_fee + activation_fee + memo_fee
                        }
                        "TriggerSmartContract" => {
                            let contract_address = tron_tx.to_address()?;

                            let data = tron_tx
                                .raw()
                                .contract
                                .first()
                                .and_then(|c| c.parameter.as_ref())
                                .map(|p| {
                                    protocol::TriggerSmartContract::decode(&p.value[..])
                                        .map(|t| t.data)
                                        .unwrap_or_default()
                                })
                                .unwrap_or_default();

                            // Energy: simulate + energy sharing with contract deployer
                            let (sim, contract_info) = tokio::join!(
                                client.trigger_constant_contract(
                                    sender.to_tron_bytes(),
                                    contract_address.to_tron_bytes(),
                                    data.clone(),
                                ),
                                client.get_contract(&contract_address),
                            );

                            let energy_to_pay = match sim {
                                Ok(sim) => {
                                    let failed = sim.result.as_ref()
                                        .map(|r| r.code.is_some()).unwrap_or(false);
                                    if failed || sim.energy_used == 0 {
                                        DEFAULT_FALLBACK_ENERGY
                                    } else {
                                        let total_energy = sim.energy_used;
                                        let account_resource = client.get_account_resource(sender).await?;
                                        let free_energy = (account_resource.energy_limit
                                            - account_resource.energy_used).max(0);

                                        // Energy sharing: compute user's actual portion
                                        let user_energy = match &contract_info {
                                            Ok(info) => {
                                                let user_pct = info.consume_user_resource_percent.unwrap_or(100);
                                                let max_subsidy = info.origin_energy_limit.unwrap_or(0);

                                                if user_pct >= 100 || max_subsidy <= 0 {
                                                    total_energy
                                                } else {
                                                    let deployer_addr = info.origin_address.as_ref()
                                                        .and_then(|hex_str| {
                                                            let bytes = alloy::hex::decode(hex_str).ok()?;
                                                            Address::from_tron_bytes(&bytes).ok()
                                                        });
                                                    let deployer_available = match deployer_addr {
                                                        Some(ref addr) => match client.get_account_resource(addr).await {
                                                            Ok(ar) => (ar.energy_limit - ar.energy_used).max(0),
                                                            Err(_) => 0,
                                                        },
                                                        None => 0,
                                                    };

                                                    let user_theoretical = (total_energy * user_pct + 99) / 100;
                                                    let deployer_theoretical = total_energy - user_theoretical;
                                                    let deployer_actual = deployer_theoretical
                                                        .min(max_subsidy)
                                                        .min(deployer_available);

                                                    (total_energy - deployer_actual).max(0)
                                                }
                                            }
                                            Err(_) => total_energy,
                                        };

                                        (user_energy - free_energy).max(0)
                                    }
                                }
                                Err(_) => DEFAULT_FALLBACK_ENERGY,
                            };
                            let energy_cost = energy_to_pay as u64 * energy_fee;

                            // Bandwidth
                            let account_net = client.get_account_net(sender).await?;
                            let tx_size = tron_tx.encode().len() as i64 + UNSIGNED_TX_OVERHEAD;
                            let free_net = account_net.free_net_limit - account_net.free_net_used;
                            let bw_cost = if free_net >= tx_size { 0u64 }
                                else { (tx_size - free_net.max(0)) as u64 * transaction_fee };

                            // Memo
                            let memo = if tron_tx.raw().data.is_empty() { 0u64 } else { MEMO_FEE_SUN as u64 };

                            energy_cost + bw_cost + memo
                        }
                        _ => 0u64,
                    }
                }
                _ => 0u64,
            };

            let base = U256::from(fee_estimate);
            let slow = base;
            let market = base * U256::from(101) / U256::from(100);
            let fast = base * U256::from(102) / U256::from(100);

            Ok(RequiredTxParams {
                gas_price: U256::from(energy_fee),
                max_priority_fee: U256::ZERO,
                fee_history: GasFeeHistory::default(),
                tx_estimate_gas: base,
                blob_base_fee: U256::ZERO,
                nonce: 0,
                slow,
                market,
                fast,
                current: base,
            })
        })
    }

    async fn tron_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        for tx in &txns {
            if !tx.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }
        }

        tron_retry!(self, "broadcast_txns", |client| {
            for tx in txns.iter_mut() {
                let (tron_tx, metadata) = match tx {
                    TransactionReceipt::Tron((t, m)) => (t, m),
                    _ => {
                        return Err(NetworkErrors::RPCError(
                            "Expected Tron transaction".to_string(),
                        ))
                    }
                };

                let tx_id_hex = alloy::hex::encode(tron_tx.tx_id);
                let tx_json = tron_tx
                    .to_tron_web_json()
                    .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;

                let ret = client.broadcast_transaction(&tx_json).await?;

                let success = ret.result.unwrap_or(false);
                let error_msg = ret.error.clone().or_else(|| {
                    if ret.message.is_empty() {
                        None
                    } else {
                        Some(ret.message.clone())
                    }
                });

                if !success {
                    let msg = error_msg.unwrap_or_else(|| "Unknown error".to_string());
                    return Err(NetworkErrors::RPCError(format!(
                        "Broadcast failed: {}",
                        msg
                    )));
                }

                metadata.hash = Some(tx_id_hex);
            }

            Ok(txns.clone())
        })
    }

    async fn tron_fill_block_ref(&self, tx: &mut TronTransaction) -> Result<()> {
        tron_retry!(self, "fill_block_ref", |client| {
            let block = client.get_now_block().await?;

            if block.blockid.len() < 16 {
                return Err(NetworkErrors::ResponseParseError);
            }

            let ref_block_bytes = block.blockid[6..8].to_vec();
            let ref_block_hash = block.blockid[8..16].to_vec();

            let timestamp = block
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.timestamp)
                .ok_or(NetworkErrors::ResponseParseError)?;

            tx.set_block_ref(ref_block_bytes, ref_block_hash);
            tx.set_timestamp(timestamp);
            tx.set_expiration(timestamp + 300_000);

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::dyn_abi::{DynSolValue, JsonAbiExt};
    use alloy::json_abi::JsonAbi;
    use config::abi::ERC20_ABI;
    use std::time::Instant;
    use test_data::gen_tron_testnet_conf;

    #[tokio::test]
    async fn test_tron_connect_timeout_unreachable() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["https://192.0.2.1:443".to_string()];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() <= TRON_REQUEST_TIMEOUT_SECS + 2,
            "Request took {}s, expected <= {}s",
            elapsed.as_secs(),
            TRON_REQUEST_TIMEOUT_SECS + 2
        );
    }

    #[tokio::test]
    async fn test_tron_get_block_number() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let block_number = provider.tron_get_current_block_number().await.unwrap();
        assert!(block_number > 0);
    }

    #[tokio::test]
    async fn test_tron_estimate_block_time() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let block_time = provider.tron_estimate_block_time().await.unwrap();
        assert!((1..=10).contains(&block_time));
    }

    #[tokio::test]
    async fn test_tron_estimate_params_batch() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let sender = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let to = Address::from_tron_address(test_data::tron_addresses::ADDR_1).unwrap();

        let tron_tx = TronTransaction::builder()
            .transfer(&sender, &to, 1_000_000)
            .build()
            .unwrap();
        let tx = TransactionRequest::Tron((tron_tx, proto::tx::TransactionMetadata::default()));

        let params = provider
            .tron_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        println!("=== Tron Transfer Gas Estimation ===");
        println!("gas_price (energy_fee): {}", params.gas_price);
        println!(
            "tx_estimate_gas (bandwidth fee): {}",
            params.tx_estimate_gas
        );
        println!("current: {}", params.current);
        println!("====================================");

        assert!(params.gas_price > U256::ZERO);
    }

    #[tokio::test]
    async fn test_tron_estimate_params_trc20() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let sender = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let contract = Address::from_tron_address("TNuoKL1ni8aoshfFL1ASca1Gou9RXwAzfn").unwrap();

        let abi: JsonAbi = serde_json::from_str(ERC20_ABI).unwrap();
        let to = Address::from_tron_address(test_data::tron_addresses::ADDR_1).unwrap();
        let func = abi.function("transfer").and_then(|f| f.first()).unwrap();
        let data = func
            .abi_encode_input(&[
                DynSolValue::Address(to.to_alloy_addr()),
                DynSolValue::Uint(U256::from(1_000_000), 256),
            ])
            .unwrap();

        let tron_tx = TronTransaction::builder()
            .trigger_smart_contract(&sender, &contract, 0, data, 0, 0)
            .build()
            .unwrap();
        let tx = TransactionRequest::Tron((tron_tx, proto::tx::TransactionMetadata::default()));

        let params = provider
            .tron_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        println!("=== Tron TRC20 Gas Estimation ===");
        println!("gas_price (energy_fee): {}", params.gas_price);
        println!(
            "tx_estimate_gas (energy_used * energy_fee): {}",
            params.tx_estimate_gas
        );
        println!("slow: {}", params.slow);
        println!("market: {}", params.market);
        println!("fast: {}", params.fast);
        println!("current: {}", params.current);
        println!("=================================");

        assert!(params.gas_price > U256::ZERO);
        assert!(params.tx_estimate_gas > U256::ZERO);
        assert!(params.slow < params.market);
        assert!(params.market < params.fast);
        assert_eq!(params.slow, params.tx_estimate_gas);
    }
}
