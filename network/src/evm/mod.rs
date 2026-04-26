mod block_parse;
mod ft_parse;
mod gas_parse;
mod nonce_parser;
mod tx_parse;

pub use self::ft_parse::generate_erc20_transfer_data;
pub use self::gas_parse::{GasFeeHistory, RequiredTxParams};

use self::block_parse::{build_last_block_header_request, process_get_timestampt_block_response};
use self::ft_parse::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};
use self::gas_parse::{
    build_batch_gas_request, process_parse_fee_history_request, EIP1559, EIP4844,
};
use self::nonce_parser::process_nonce_response;
use self::tx_parse::{
    build_payload_tx_receipt, build_send_signed_tx_request, process_tx_receipt_response,
    process_tx_send_response,
};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::token::TokenError;
use errors::tx::TransactionErrors;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::common::JsonRPC;
use rpc::methods::EvmMethods;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::{json, Value};
use std::collections::HashMap;
use token::ft::FToken;

#[async_trait]
pub trait EvmOperations {
    async fn evm_get_current_block_number(&self) -> Result<u64>;
    async fn evm_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams>;
    async fn evm_estimate_block_time(&self, address: &Address) -> Result<u64>;
    async fn evm_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn evm_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn evm_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn evm_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken>;
}

#[async_trait]
impl EvmOperations for NetworkProvider {
    async fn evm_get_current_block_number(&self) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::BlockNumber);
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let block_number = response
            .result
            .as_ref()
            .and_then(|result| result.as_str())
            .and_then(|block_str| u64::from_str_radix(block_str.trim_start_matches("0x"), 16).ok())
            .ok_or(NetworkErrors::ResponseParseError)?;

        Ok(block_number)
    }

    async fn evm_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams> {
        let default_percentiles = [25.0, 50.0, 75.0];
        let percentiles_to_use = percentiles.unwrap_or(&default_percentiles);
        let requests = build_batch_gas_request(
            tx,
            block_count,
            percentiles_to_use,
            &self.config.features,
            sender,
        )?;

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let response = provider
            .req::<Vec<ResultRes<Value>>>(requests.into())
            .await
            .map_err(NetworkErrors::Request)?;

        if response.iter().all(|res| res.error.is_some()) {
            let all_errors = response
                .into_iter()
                .filter_map(|res| res.error.map(|e| e.to_string()))
                .collect::<Vec<String>>()
                .join(", ");
            return Err(NetworkErrors::RPCError(all_errors));
        }

        let nonce = response
            .first()
            .and_then(|res| process_nonce_response(res, sender).ok())
            .unwrap_or_default();

        let gas_price_response = response
            .get(1)
            .and_then(|res| res.result.as_ref())
            .and_then(|result| result.as_str())
            .and_then(Self::parse_str_to_u256)
            .unwrap_or_default();

        if let TransactionRequest::Zilliqa((zil_tx, _)) = tx {
            let gas_limit = U256::from(zil_tx.gas_limit);
            let slow = gas_price_response * gas_limit;
            let market = gas_price_response.saturating_mul(U256::from(2)) * gas_limit;
            let fast = gas_price_response.saturating_mul(U256::from(3)) * gas_limit;

            return Ok(RequiredTxParams {
                blob_base_fee: U256::ZERO,
                nonce,
                max_priority_fee: U256::ZERO,
                gas_price: gas_price_response,
                fee_history: Default::default(),
                tx_estimate_gas: U256::ZERO,
                slow,
                market,
                fast,
                current: market,
            });
        }

        let tx_estimate_gas_response = response.get(2);
        let tx_estimate_gas_response = tx_estimate_gas_response
            .and_then(|res| res.result.as_ref())
            .and_then(|result| result.as_str())
            .and_then(Self::parse_str_to_u256)
            .unwrap_or(U256::from(21000));

        let (max_priority_fee_per_gas_response, fee_history_response) =
            if self.config.features.contains(&EIP1559) {
                let max_priority_fee_per_gas_response = response
                    .get(3)
                    .and_then(|res| res.result.as_ref())
                    .and_then(|result| result.as_str())
                    .and_then(Self::parse_str_to_u256)
                    .unwrap_or_default();

                let fee_history_response = response
                    .get(4)
                    .and_then(|res| res.result.as_ref())
                    .and_then(|result| process_parse_fee_history_request(result).ok())
                    .unwrap_or_default();

                (max_priority_fee_per_gas_response, fee_history_response)
            } else {
                (U256::ZERO, Default::default())
            };

        let blob_base_fee = if self.config.features.contains(&EIP4844) {
            response
                .first()
                .and_then(|res| res.result.as_ref())
                .and_then(|result| result.as_str())
                .and_then(Self::parse_str_to_u256)
                .unwrap_or_default()
        } else {
            U256::ZERO
        };

        let (slow, market, fast) = if fee_history_response.base_fee > U256::ZERO {
            let priority_fee = if fee_history_response.priority_fee > U256::ZERO {
                fee_history_response.priority_fee
            } else {
                max_priority_fee_per_gas_response
            };

            Self::calculate_eip1559_fee_tiers(
                fee_history_response.base_fee,
                priority_fee,
                tx_estimate_gas_response,
            )
        } else {
            Self::calculate_legacy_fee_tiers(gas_price_response, tx_estimate_gas_response)
        };

        Ok(RequiredTxParams {
            blob_base_fee,
            nonce,
            max_priority_fee: max_priority_fee_per_gas_response,
            gas_price: gas_price_response,
            fee_history: fee_history_response,
            tx_estimate_gas: tx_estimate_gas_response,
            slow,
            market,
            fast,
            current: market,
        })
    }

    async fn evm_estimate_block_time(&self, address: &Address) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = build_last_block_header_request(address, None);
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let (last_blocknumber, last_timestamp) =
            { process_get_timestampt_block_response(&response, address) };
        let payload = build_last_block_header_request(address, Some(last_blocknumber - 1));
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let (_, early_timestamp) = { process_get_timestampt_block_response(&response, address) };

        Ok(last_timestamp - early_timestamp + 1)
    }

    async fn evm_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        let mut requests: Vec<Value> = Vec::with_capacity(txns.len());

        for tx in txns.iter() {
            requests.push(build_payload_tx_receipt(tx));
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(requests.into())
            .await
            .map_err(NetworkErrors::Request)?;

        for (index, res) in responses.into_iter().enumerate() {
            if let Some(tx) = txns.get_mut(index) {
                process_tx_receipt_response(res, tx)?;
            }
        }

        Ok(())
    }

    async fn evm_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        let total = txns.len();
        let mut all_requests = Vec::with_capacity(total);

        for tx in txns.iter() {
            if !tx.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }

            all_requests.push(build_send_signed_tx_request(tx));
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(all_requests.into())
            .await?;

        for (tx, response) in txns.iter_mut().zip(responses.iter()) {
            process_tx_send_response(response, tx)?;
        }

        Ok(txns)
    }

    async fn evm_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        let total_requests = tokens.iter().fold(0, |acc, _| acc + accounts.len());

        if total_requests == 0 {
            return Ok(());
        }

        let mut all_requests = Vec::with_capacity(total_requests);
        let mut request_mapping = Vec::with_capacity(total_requests);

        for (token_idx, token) in tokens.iter().enumerate() {
            let requests = build_token_requests(&token.addr, accounts, token.native)?;

            for (req, req_type) in requests {
                if let RequestType::Balance(account) = req_type {
                    request_mapping.push((token_idx, account));
                    all_requests.push(req);
                }
            }
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(all_requests.into())
            .await
            .map_err(NetworkErrors::Request)?;

        for ((token_idx, account), response) in request_mapping.iter().zip(responses.iter()) {
            match tokens[*token_idx].addr {
                Address::Secp256k1Sha256(_) => {
                    let balance =
                        process_zil_balance_response(response, account, tokens[*token_idx].native);
                    tokens[*token_idx]
                        .balances
                        .insert(account.to_hash(), U256::from(balance));
                }
                Address::Secp256k1Keccak256(_) | Address::Secp256k1Tron(_) => {
                    let balance = process_eth_balance_response(response)?;
                    tokens[*token_idx]
                        .balances
                        .insert(account.to_hash(), balance);
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn evm_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        let requests = build_token_requests(&contract, accounts, false)?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<Value>> = provider
            .req(
                requests
                    .iter()
                    .map(|(req, _)| req.clone())
                    .collect::<Vec<_>>()
                    .into(),
            )
            .await
            .map_err(NetworkErrors::Request)?;

        match contract {
            Address::Secp256k1Sha256(_) => {
                let (name, symbol, decimals) = process_zil_metadata_response(
                    responses[0]
                        .result
                        .as_ref()
                        .ok_or(TokenError::InvalidContractInit)?,
                )?;

                let mut balances: HashMap<usize, U256> = HashMap::new();

                for (i, (_, req_type)) in requests.iter().enumerate().skip(1) {
                    if let RequestType::Balance(account) = req_type {
                        let balance = process_zil_balance_response(&responses[i], account, false);
                        balances.insert(account.to_hash(), U256::from(balance));
                    }
                }

                Ok(FToken {
                    balances,
                    name,
                    symbol,
                    decimals,
                    addr: contract,
                    logo: None,
                    default: false,
                    native: false,
                    chain_hash: self.config.hash(),
                    rate: 0f64,
                })
            }
            Address::Secp256k1Keccak256(_) | Address::Secp256k1Tron(_) => {
                let mut metadata_iter = responses.iter();
                let name = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Name,
                )?;
                let symbol = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Symbol,
                )?;
                let decimals: u8 = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Decimals,
                )?
                .parse()
                .map_err(|_| TokenError::InvalidContractInit)?;

                let mut balances: HashMap<usize, U256> = HashMap::new();
                for ((_, req_type), response) in requests.iter().zip(responses.iter()).skip(3) {
                    if let RequestType::Balance(account) = req_type {
                        let balance = process_eth_balance_response(response)?;
                        balances.insert(account.to_hash(), balance);
                    }
                }

                Ok(FToken {
                    balances,
                    name,
                    symbol,
                    decimals,
                    addr: contract,
                    logo: None,
                    default: false,
                    native: false,
                    chain_hash: self.config.hash(),
                    rate: 0f64,
                })
            }
            _ => {
                return Err(NetworkErrors::EIPNotSupporting(0));
            }
        }
    }
}

impl NetworkProvider {
    fn calculate_eip1559_fee_tiers(
        base_fee: U256,
        priority_fee: U256,
        gas_limit: U256,
    ) -> (U256, U256, U256) {
        let effective_gas_price = base_fee.saturating_add(priority_fee);
        let slow_fee_per_gas =
            effective_gas_price.saturating_mul(U256::from(110)) / U256::from(100);
        let market_fee_per_gas =
            effective_gas_price.saturating_mul(U256::from(120)) / U256::from(100);
        let fast_fee_per_gas =
            effective_gas_price.saturating_mul(U256::from(230)) / U256::from(100);

        (
            Self::calculate_total_fee(slow_fee_per_gas, gas_limit),
            Self::calculate_total_fee(market_fee_per_gas, gas_limit),
            Self::calculate_total_fee(fast_fee_per_gas, gas_limit),
        )
    }

    fn calculate_legacy_fee_tiers(gas_price: U256, gas_limit: U256) -> (U256, U256, U256) {
        (
            Self::calculate_total_fee(gas_price, gas_limit),
            Self::calculate_total_fee(gas_price.saturating_mul(U256::from(2)), gas_limit),
            Self::calculate_total_fee(gas_price.saturating_mul(U256::from(3)), gas_limit),
        )
    }

    fn calculate_total_fee(fee_per_gas: U256, gas_limit: U256) -> U256 {
        fee_per_gas.saturating_mul(gas_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use test_data::gen_tron_testnet_conf;

    #[test]
    fn test_calculate_eip1559_fee_tiers() {
        let base_fee = U256::from(50353);
        let priority_fee = U256::from(1755128);
        let gas_limit = U256::from(21000);

        let (slow, market, fast) =
            NetworkProvider::calculate_eip1559_fee_tiers(base_fee, priority_fee, gas_limit);

        assert_eq!(U256::from(41706609000u128), slow);
        assert_eq!(U256::from(45498117000u128), market);
        assert_eq!(U256::from(87204726000u128), fast);
    }

    #[tokio::test]
    async fn test_tron_evm_update_transactions_receipt() {
        use history::status::TransactionStatus;
        use proto::tx::TransactionMetadata;
        use serde_json::json;

        let provider = NetworkProvider::new(gen_tron_testnet_conf());

        let tron_tx_json = json!({
            "signature": [
                "4735316cacefae2cfccd7d686ff25f8910ca7b05d11d2dd583c9b7c6af03427554f5a7017033bc0db9d5b654d0a9e864b4e30877c6a9b88798158c19e380f04201"
            ],
            "txID": "960188a94300ab78687bc8b9e42824c86d2c11a8ac7518022d868a96dd8c92a7",
            "raw_data": {
                "contract": [
                    {
                        "parameter": {
                            "value": {
                                "data": "a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                                "owner_address": "419705bf55c3dcc6d277ebb8fe2a68762268822ba2",
                                "contract_address": "418df49db5dbf07e498492d2dafcf7b305cdc72471"
                            },
                            "type_url": "type.googleapis.com/protocol.TriggerSmartContract"
                        },
                        "type": "TriggerSmartContract"
                    }
                ],
                "ref_block_bytes": "6b48",
                "ref_block_hash": "4448fdd628a1901b",
                "expiration": 1773553356000_i64,
                "fee_limit": 1340876,
                "timestamp": 1773553056000_i64
            },
            "raw_data_hex": "0a026b4822084448fdd628a1901b40e0999280cf335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15419705bf55c3dcc6d277ebb8fe2a68762268822ba21215418df49db5dbf07e498492d2dafcf7b305cdc724712244a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a76400007080f2ffffce339001cceb51"
        });

        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                hash: Some(
                    "960188a94300ab78687bc8b9e42824c86d2c11a8ac7518022d868a96dd8c92a7".to_string(),
                ),
                chain_hash: gen_tron_testnet_conf().hash(),
                ..Default::default()
            },
            evm: None,
            scilla: None,
            btc: None,
            tron: Some(tron_tx_json.to_string()),
            solana: None,
            signed_message: None,
            timestamp: 1773553056000,
        };
        assert!(tx.metadata.broadcast);

        let result = provider
            .evm_update_transactions_receipt(&mut [&mut tx])
            .await;

        assert!(result.is_ok());
        assert_eq!(tx.status, TransactionStatus::Success);
    }
}
