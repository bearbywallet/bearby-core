use serde::{de::Deserializer, Deserialize, Serialize};

fn deserialize_hex_to_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    alloy::hex::decode(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub raw_data: Option<BlockHeaderRawData>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeaderRawData {
    pub number: i64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BlockResponse {
    #[serde(
        default,
        alias = "blockID",
        deserialize_with = "deserialize_hex_to_vec"
    )]
    pub blockid: Vec<u8>,
    pub block_header: Option<BlockHeader>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainParameter {
    pub key: String,
    #[serde(default)]
    pub value: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainParamsResponse {
    #[serde(alias = "chainParameter")]
    pub chain_parameter: Vec<ChainParameter>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TriggerResult {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TriggerContractResponse {
    #[serde(default)]
    pub result: Option<TriggerResult>,
    #[serde(default)]
    pub energy_used: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BroadcastResponse {
    #[serde(default)]
    pub result: Option<bool>,
    #[serde(default)]
    pub message: String,
    #[serde(default, alias = "Error")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumberMessage {
    pub num: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriggerSmartContractRequest {
    pub owner_address: String,
    pub contract_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_value: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountNetResponse {
    #[serde(default, rename = "freeNetUsed")]
    pub free_net_used: i64,
    #[serde(default, rename = "freeNetLimit")]
    pub free_net_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountResourceResponse {
    #[serde(default, rename = "EnergyUsed")]
    pub energy_used: i64,
    #[serde(default, rename = "EnergyLimit")]
    pub energy_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContractResponse {
    /// Address of the contract deployer (hex-encoded, e.g. "41...")
    #[serde(default, rename = "origin_address")]
    pub origin_address: Option<String>,
    /// Percentage of energy the user must pay (0-100, default 100 = user pays all)
    #[serde(default, rename = "consume_user_resource_percent")]
    pub consume_user_resource_percent: Option<i64>,
    /// Maximum energy units the deployer will subsidize per transaction
    #[serde(default, rename = "origin_energy_limit")]
    pub origin_energy_limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountResponse {
    /// Present if the account exists on-chain (activated).
    /// Absent/None for unactivated accounts (node returns {} with no address field).
    #[serde(default)]
    pub address: Option<String>,
}
