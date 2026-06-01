use alloy::primitives::U256;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use proto::{address::Address, tx::TransactionRequest};
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
};
use serde_json::{json, Value};

use super::nonce_parser::build_nonce_request;

#[derive(Debug, Default, Clone)]
pub struct GasFeeHistory {
    pub max_fee: U256,
    pub priority_fee: U256,
    pub base_fee: U256,
}

#[derive(Debug, Clone)]
pub struct RequiredTxParams {
    pub gas_price: U256,
    pub max_priority_fee: U256,
    pub fee_history: GasFeeHistory,
    pub tx_estimate_gas: U256,
    pub blob_base_fee: U256,
    pub nonce: u64,
    pub slow: U256,
    pub market: U256,
    pub fast: U256,
    pub current: U256,
}

pub const EIP1559: u16 = 1559;
pub const EIP4844: u16 = 4844;

pub fn build_fee_history_request(block_count: u64, percentiles: &[f64]) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([block_count, "latest", percentiles]),
        EvmMethods::FeeHistory,
    )
}

/// Single `eth_estimateGas` payload for an EVM `tx` (the `gas` field is stripped so the node
/// estimates freely). Shared by [`build_batch_gas_request`] and the standalone
/// `evm_estimate_gas`, so the tx-object shape lives in exactly one place.
pub fn build_estimate_gas_request(tx: &TransactionRequest) -> Result<Value, NetworkErrors> {
    let tx_object = match tx {
        TransactionRequest::Ethereum((eth_tx, _)) => {
            let mut val = serde_json::to_value(eth_tx)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;

            if let Some(obj) = val.as_object_mut() {
                obj.remove("gas");
            }

            val
        }
        _ => Err(TransactionErrors::InvalidTransaction)?,
    };

    Ok(RpcProvider::<ChainConfig>::build_payload(
        json!([tx_object]),
        EvmMethods::EstimateGas,
    ))
}

pub fn build_batch_gas_request(
    tx: &TransactionRequest,
    block_count: u64,
    percentiles: &[f64],
    features: &[u16],
    sender: &Address,
) -> Result<Vec<Value>, NetworkErrors> {
    let mut requests = Vec::with_capacity(4);

    requests.push(build_nonce_request(sender));

    match tx {
        TransactionRequest::Zilliqa(_) => {
            requests.push(RpcProvider::<ChainConfig>::build_payload(
                json!([]),
                ZilMethods::GetMinimumGasPrice,
            ));
            return Ok(requests);
        }
        TransactionRequest::Ethereum(_) => {
            requests.push(RpcProvider::<ChainConfig>::build_payload(
                json!([]),
                EvmMethods::GasPrice,
            ));
        }
        _ => Err(TransactionErrors::InvalidTransaction)?,
    }

    requests.push(build_estimate_gas_request(tx)?);

    if features.contains(&EIP1559) {
        requests.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::MaxPriorityFeePerGas,
        ));
        requests.push(build_fee_history_request(block_count, percentiles));
    }

    if features.contains(&EIP4844) {
        requests.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::BlobBaseFee,
        ));
    }

    Ok(requests)
}

pub fn process_parse_fee_history_request(value: &Value) -> Result<GasFeeHistory, NetworkErrors> {
    let fee_history = value;
    let base_fee = fee_history
        .get("baseFeePerGas")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|v| v.as_str())
        .ok_or(NetworkErrors::ResponseParseError)?;
    let base_fee = U256::from_str_radix(base_fee.trim_start_matches("0x"), 16)
        .map_err(|_| NetworkErrors::ResponseParseError)?;
    let rewards = fee_history
        .get("reward")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|v| v.as_str())
        .ok_or(NetworkErrors::ResponseParseError)?;
    let priority_fee = U256::from_str_radix(rewards.trim_start_matches("0x"), 16)
        .map_err(|_| NetworkErrors::ResponseParseError)?;
    let max_fee = base_fee
        .saturating_mul(U256::from(2))
        .saturating_add(priority_fee);

    Ok(GasFeeHistory {
        max_fee,
        priority_fee,
        base_fee,
    })
}
