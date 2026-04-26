use crate::address::Address;
use crate::keypair::KeyPair;
use crate::tron_generated::protocol;
use config::address::ADDR_LEN;
use errors::tx::TransactionErrors;
use prost::Message;
use protocol::transaction::contract::ContractType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TronResource {
    Bandwidth,
    Energy,
}

impl TronResource {
    pub fn to_proto(self) -> i32 {
        match self {
            TronResource::Bandwidth => 0,
            TronResource::Energy => 1,
        }
    }

    pub fn from_proto(value: i32) -> Option<Self> {
        match value {
            0 => Some(TronResource::Bandwidth),
            1 => Some(TronResource::Energy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TronWebSignRequest {
    pub method: String,
    pub params: TronWebParams,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TronWebParams {
    pub transaction: TronWebTransaction,
    #[serde(rename = "useTronHeader")]
    pub use_tron_header: Option<bool>,
    pub input: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronWebTransaction {
    pub visible: Option<bool>,
    #[serde(rename = "txID")]
    pub tx_id: Option<String>,
    pub raw_data: TronWebRawData,
    #[serde(rename = "raw_data_hex")]
    pub raw_data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronWebRawData {
    pub contract: Vec<TronWebContract>,
    #[serde(default)]
    pub ref_block_bytes: String,
    #[serde(default)]
    pub ref_block_hash: String,
    pub expiration: i64,
    pub fee_limit: Option<i64>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronWebContract {
    #[serde(rename = "type")]
    pub contract_type: String,
    pub parameter: TronWebParameter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronWebParameter {
    pub type_url: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TronTransaction {
    raw: protocol::transaction::Raw,
}

impl Serialize for TronTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.raw.encode_to_vec();
        serializer.serialize_str(&hex::encode(encoded))
    }
}

impl<'de> Deserialize<'de> for TronTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        let raw = protocol::transaction::Raw::decode(&bytes[..])
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Self { raw })
    }
}

impl TronTransaction {
    pub fn from_tron_web(tx: &TronWebTransaction) -> Result<Self, TransactionErrors> {
        let hex_str = tx
            .raw_data_hex
            .strip_prefix("0x")
            .unwrap_or(&tx.raw_data_hex);
        let bytes =
            hex::decode(hex_str).map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        let raw = protocol::transaction::Raw::decode(&bytes[..])
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        Ok(Self { raw })
    }

    pub fn from_hex(hex: &str) -> Result<Self, TransactionErrors> {
        let hex_str = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes =
            hex::decode(hex_str).map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        let raw = protocol::transaction::Raw::decode(&bytes[..])
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        Ok(Self { raw })
    }

    pub fn from_raw(raw: protocol::transaction::Raw) -> Self {
        Self { raw }
    }

    pub fn builder() -> TronTransactionBuilder {
        TronTransactionBuilder::default()
    }

    pub fn raw(&self) -> &protocol::transaction::Raw {
        &self.raw
    }

    pub fn raw_mut(&mut self) -> &mut protocol::transaction::Raw {
        &mut self.raw
    }

    pub fn fee_limit(&self) -> i64 {
        self.raw.fee_limit
    }

    pub fn expiration(&self) -> i64 {
        self.raw.expiration
    }

    pub fn timestamp(&self) -> i64 {
        self.raw.timestamp
    }

    pub fn ref_block_bytes(&self) -> &[u8] {
        &self.raw.ref_block_bytes
    }

    pub fn ref_block_hash(&self) -> &[u8] {
        &self.raw.ref_block_hash
    }

    pub fn owner_address(&self) -> Result<Address, TransactionErrors> {
        let contract = self
            .raw
            .contract
            .first()
            .ok_or(TransactionErrors::InvalidContract)?;
        let param = contract
            .parameter
            .as_ref()
            .ok_or(TransactionErrors::InvalidContract)?;
        extract_owner_from_parameter(&param.value, &param.type_url)
    }

    pub fn to_address(&self) -> Result<Address, TransactionErrors> {
        let contract = self
            .raw
            .contract
            .first()
            .ok_or(TransactionErrors::InvalidContract)?;
        let param = contract
            .parameter
            .as_ref()
            .ok_or(TransactionErrors::InvalidContract)?;
        extract_to_address_from_parameter(&param.value, &param.type_url, &self.raw)
    }

    pub fn contract_type(&self) -> Option<&str> {
        self.raw.contract.first().and_then(|c| {
            c.parameter.as_ref().map(|p| {
                p.type_url
                    .strip_prefix("type.googleapis.com/protocol.")
                    .unwrap_or(&p.type_url)
            })
        })
    }

    pub fn is_transfer(&self) -> bool {
        self.contract_type() == Some("TransferContract")
    }

    pub fn transfer_amount(&self) -> Option<i64> {
        if !self.is_transfer() {
            return None;
        }
        let contract = self.raw.contract.first()?;
        let param = contract.parameter.as_ref()?;
        let transfer = protocol::TransferContract::decode(&param.value[..]).ok()?;
        Some(transfer.amount)
    }

    pub fn set_transfer_amount(&mut self, amount: i64) -> Result<(), TransactionErrors> {
        if !self.is_transfer() {
            return Err(TransactionErrors::InvalidContract);
        }
        let contract = self
            .raw
            .contract
            .first_mut()
            .ok_or(TransactionErrors::InvalidContract)?;
        let param = contract
            .parameter
            .as_mut()
            .ok_or(TransactionErrors::InvalidContract)?;

        let mut transfer = protocol::TransferContract::decode(&param.value[..])
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        transfer.amount = amount;
        param.value = transfer.encode_to_vec();
        Ok(())
    }

    pub fn set_fee_limit(&mut self, fee_limit: i64) -> &mut Self {
        self.raw.fee_limit = fee_limit;
        self
    }

    pub fn set_expiration(&mut self, expiration: i64) -> &mut Self {
        self.raw.expiration = expiration;
        self
    }

    pub fn set_timestamp(&mut self, timestamp: i64) -> &mut Self {
        self.raw.timestamp = timestamp;
        self
    }

    pub fn set_block_ref(
        &mut self,
        ref_block_bytes: Vec<u8>,
        ref_block_hash: Vec<u8>,
    ) -> &mut Self {
        self.raw.ref_block_bytes = ref_block_bytes;
        self.raw.ref_block_hash = ref_block_hash;
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        self.raw.encode_to_vec()
    }

    pub fn tx_id(&self) -> [u8; 32] {
        let bytes = self.encode();
        Sha256::digest(&bytes).into()
    }

    pub fn sign(&self, keypair: &KeyPair) -> Result<TronTransactionReceipt, TransactionErrors> {
        use k256::ecdsa::SigningKey;

        let raw_data_bytes = self.encode();
        let tx_id: [u8; 32] = Sha256::digest(&raw_data_bytes).into();

        let sk_bytes = keypair.get_sk_bytes();
        let signing_key =
            SigningKey::from_slice(&sk_bytes).map_err(|_| TransactionErrors::InvalidSecretKey)?;

        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_id)
            .map_err(|_| TransactionErrors::InvalidSignature)?;

        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery_id.to_byte());

        Ok(TronTransactionReceipt {
            raw_data_bytes,
            tx_id,
            signature,
            owner_address: self.owner_address()?,
        })
    }

    pub fn to_tron_web(&self) -> Result<TronWebTransaction, TransactionErrors> {
        let tx_id = hex::encode(self.tx_id());
        let raw_data_hex = hex::encode(self.encode());

        let contracts: Vec<TronWebContract> = self
            .raw
            .contract
            .iter()
            .map(|c| {
                let param = c
                    .parameter
                    .as_ref()
                    .ok_or(TransactionErrors::InvalidContract)?;
                let contract_type = param
                    .type_url
                    .strip_prefix("type.googleapis.com/protocol.")
                    .unwrap_or(&param.type_url)
                    .to_string();

                let value = contract_value_to_json(&param.value, &param.type_url)?;

                Ok(TronWebContract {
                    contract_type,
                    parameter: TronWebParameter {
                        type_url: param.type_url.clone(),
                        value,
                    },
                })
            })
            .collect::<Result<Vec<_>, TransactionErrors>>()?;

        Ok(TronWebTransaction {
            visible: Some(false),
            tx_id: Some(tx_id),
            raw_data: TronWebRawData {
                contract: contracts,
                ref_block_bytes: hex::encode(&self.raw.ref_block_bytes),
                ref_block_hash: hex::encode(&self.raw.ref_block_hash),
                expiration: self.raw.expiration,
                fee_limit: if self.raw.fee_limit > 0 {
                    Some(self.raw.fee_limit)
                } else {
                    None
                },
                timestamp: self.raw.timestamp,
            },
            raw_data_hex,
        })
    }
}

#[derive(Default)]
pub struct TronTransactionBuilder {
    ref_block_bytes: Vec<u8>,
    ref_block_hash: Vec<u8>,
    expiration: i64,
    timestamp: i64,
    fee_limit: i64,
    contract: Option<protocol::transaction::Contract>,
}

impl TronTransactionBuilder {
    pub fn ref_block(mut self, bytes: Vec<u8>, hash: Vec<u8>) -> Self {
        self.ref_block_bytes = bytes;
        self.ref_block_hash = hash;
        self
    }

    pub fn expiration(mut self, exp: i64) -> Self {
        self.expiration = exp;
        self
    }

    pub fn timestamp(mut self, ts: i64) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn fee_limit(mut self, fee: i64) -> Self {
        self.fee_limit = fee;
        self
    }

    pub fn transfer(self, owner: &Address, to: &Address, amount: i64) -> Self {
        let contract = protocol::TransferContract {
            owner_address: owner.to_tron_bytes(),
            to_address: to.to_tron_bytes(),
            amount,
        };
        self.with_contract(
            "type.googleapis.com/protocol.TransferContract",
            contract.encode_to_vec(),
            ContractType::TransferContract,
        )
    }

    pub fn trigger_smart_contract(
        self,
        owner: &Address,
        contract_addr: &Address,
        call_value: i64,
        data: Vec<u8>,
        call_token_value: i64,
        token_id: i64,
    ) -> Self {
        let contract = protocol::TriggerSmartContract {
            owner_address: owner.to_tron_bytes(),
            contract_address: contract_addr.to_tron_bytes(),
            call_value,
            data,
            call_token_value,
            token_id,
        };
        self.with_contract(
            "type.googleapis.com/protocol.TriggerSmartContract",
            contract.encode_to_vec(),
            ContractType::TriggerSmartContract,
        )
    }

    pub fn freeze_balance_v2(
        self,
        owner: &Address,
        frozen_balance: i64,
        resource: TronResource,
    ) -> Self {
        let contract = protocol::FreezeBalanceV2Contract {
            owner_address: owner.to_tron_bytes(),
            frozen_balance,
            resource: resource.to_proto(),
        };
        self.with_contract(
            "type.googleapis.com/protocol.FreezeBalanceV2Contract",
            contract.encode_to_vec(),
            ContractType::FreezeBalanceV2Contract,
        )
    }

    pub fn unfreeze_balance_v2(
        self,
        owner: &Address,
        unfreeze_balance: i64,
        resource: TronResource,
    ) -> Self {
        let contract = protocol::UnfreezeBalanceV2Contract {
            owner_address: owner.to_tron_bytes(),
            unfreeze_balance,
            resource: resource.to_proto(),
        };
        self.with_contract(
            "type.googleapis.com/protocol.UnfreezeBalanceV2Contract",
            contract.encode_to_vec(),
            ContractType::UnfreezeBalanceV2Contract,
        )
    }

    pub fn withdraw_expire_unfreeze(self, owner: &Address) -> Self {
        let contract = protocol::WithdrawExpireUnfreezeContract {
            owner_address: owner.to_tron_bytes(),
        };
        self.with_contract(
            "type.googleapis.com/protocol.WithdrawExpireUnfreezeContract",
            contract.encode_to_vec(),
            ContractType::WithdrawExpireUnfreezeContract,
        )
    }

    pub fn delegate_resource(
        self,
        owner: &Address,
        resource: TronResource,
        balance: i64,
        receiver: &Address,
        lock: bool,
        lock_period: i64,
    ) -> Self {
        let contract = protocol::DelegateResourceContract {
            owner_address: owner.to_tron_bytes(),
            resource: resource.to_proto(),
            balance,
            receiver_address: receiver.to_tron_bytes(),
            lock,
            lock_period,
        };
        self.with_contract(
            "type.googleapis.com/protocol.DelegateResourceContract",
            contract.encode_to_vec(),
            ContractType::DelegateResourceContract,
        )
    }

    pub fn undelegate_resource(
        self,
        owner: &Address,
        resource: TronResource,
        balance: i64,
        receiver: &Address,
    ) -> Self {
        let contract = protocol::UnDelegateResourceContract {
            owner_address: owner.to_tron_bytes(),
            resource: resource.to_proto(),
            balance,
            receiver_address: receiver.to_tron_bytes(),
        };
        self.with_contract(
            "type.googleapis.com/protocol.UnDelegateResourceContract",
            contract.encode_to_vec(),
            ContractType::UnDelegateResourceContract,
        )
    }

    pub fn cancel_all_unfreeze_v2(self, owner: &Address) -> Self {
        let contract = protocol::CancelAllUnfreezeV2Contract {
            owner_address: owner.to_tron_bytes(),
        };
        self.with_contract(
            "type.googleapis.com/protocol.CancelAllUnfreezeV2Contract",
            contract.encode_to_vec(),
            ContractType::CancelAllUnfreezeV2Contract,
        )
    }

    pub fn transfer_asset(
        self,
        owner: &Address,
        asset_name: Vec<u8>,
        to: &Address,
        amount: i64,
    ) -> Self {
        let contract = protocol::TransferAssetContract {
            asset_name,
            owner_address: owner.to_tron_bytes(),
            to_address: to.to_tron_bytes(),
            amount,
        };
        self.with_contract(
            "type.googleapis.com/protocol.TransferAssetContract",
            contract.encode_to_vec(),
            ContractType::TransferAssetContract,
        )
    }

    pub fn vote_witness(self, owner: &Address, votes: Vec<(Address, i64)>) -> Self {
        let vote_list = votes
            .iter()
            .map(|(addr, count)| protocol::vote_witness_contract::Vote {
                vote_address: addr.to_tron_bytes(),
                vote_count: *count,
            })
            .collect();
        let contract = protocol::VoteWitnessContract {
            owner_address: owner.to_tron_bytes(),
            votes: vote_list,
            support: false,
        };
        self.with_contract(
            "type.googleapis.com/protocol.VoteWitnessContract",
            contract.encode_to_vec(),
            ContractType::VoteWitnessContract,
        )
    }

    fn with_contract(
        mut self,
        type_url: &str,
        value: Vec<u8>,
        contract_type: ContractType,
    ) -> Self {
        self.contract = Some(protocol::transaction::Contract {
            r#type: contract_type as i32,
            parameter: Some(prost_types::Any {
                type_url: type_url.to_string(),
                value,
            }),
            provider: Vec::new(),
            contract_name: Vec::new(),
            permission_id: 0,
        });
        self
    }

    pub fn build(self) -> Result<TronTransaction, TransactionErrors> {
        let contract = self.contract.ok_or(TransactionErrors::InvalidContract)?;
        Ok(TronTransaction {
            raw: protocol::transaction::Raw {
                ref_block_bytes: self.ref_block_bytes,
                ref_block_num: 0,
                ref_block_hash: self.ref_block_hash,
                expiration: self.expiration,
                auths: Vec::new(),
                data: Vec::new(),
                contract: vec![contract],
                scripts: Vec::new(),
                timestamp: self.timestamp,
                fee_limit: self.fee_limit,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TronTransactionReceipt {
    #[serde(with = "hex::serde")]
    pub raw_data_bytes: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tx_id: [u8; 32],
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
    pub owner_address: Address,
}

impl TronTransactionReceipt {
    pub fn verify(&self) -> Result<bool, TransactionErrors> {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        let hash = Sha256::digest(&self.raw_data_bytes);
        let computed_id: [u8; 32] = hash.into();
        if computed_id != self.tx_id {
            return Ok(false);
        }

        if self.signature.len() != 65 {
            return Ok(false);
        }

        let sig = Signature::from_slice(&self.signature[..64])
            .map_err(|_| TransactionErrors::InvalidSignature)?;
        let recovery_id = RecoveryId::try_from(self.signature[64])
            .map_err(|_| TransactionErrors::InvalidSignature)?;

        let recovered_key = VerifyingKey::recover_from_prehash(&self.tx_id, &sig, recovery_id)
            .map_err(|_| TransactionErrors::InvalidSignature)?;

        let addr = alloy::primitives::Address::from_public_key(&recovered_key);
        let addr_bytes: [u8; ADDR_LEN] = addr.into();

        Ok(addr_bytes == *self.owner_address.as_ref())
    }

    pub fn tx_id_hex(&self) -> String {
        hex::encode(self.tx_id)
    }

    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    pub fn to_tron_web_json(&self) -> Result<serde_json::Value, TransactionErrors> {
        use serde_json::json;

        let raw = protocol::transaction::Raw::decode(&self.raw_data_bytes[..])
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;

        let contracts: Vec<serde_json::Value> = raw
            .contract
            .iter()
            .map(|c| {
                let param = c
                    .parameter
                    .as_ref()
                    .ok_or(TransactionErrors::InvalidContract)?;
                let contract_type = param
                    .type_url
                    .strip_prefix("type.googleapis.com/protocol.")
                    .unwrap_or(&param.type_url)
                    .to_string();

                let value = contract_value_to_json(&param.value, &param.type_url)?;

                Ok(json!({
                    "type": contract_type,
                    "parameter": {
                        "type_url": param.type_url,
                        "value": value
                    }
                }))
            })
            .collect::<Result<Vec<_>, TransactionErrors>>()?;

        let mut raw_data = serde_json::Map::new();
        raw_data.insert("contract".to_string(), json!(contracts));
        raw_data.insert(
            "ref_block_bytes".to_string(),
            json!(hex::encode(&raw.ref_block_bytes)),
        );
        raw_data.insert(
            "ref_block_hash".to_string(),
            json!(hex::encode(&raw.ref_block_hash)),
        );
        raw_data.insert("expiration".to_string(), json!(raw.expiration));
        if raw.fee_limit > 0 {
            raw_data.insert("fee_limit".to_string(), json!(raw.fee_limit));
        }
        raw_data.insert("timestamp".to_string(), json!(raw.timestamp));

        Ok(json!({
            "visible": false,
            "txID": hex::encode(self.tx_id),
            "raw_data_hex": hex::encode(&self.raw_data_bytes),
            "raw_data": raw_data,
            "signature": [hex::encode(&self.signature)]
        }))
    }
}

fn contract_value_to_json(
    value: &[u8],
    type_url: &str,
) -> Result<serde_json::Value, TransactionErrors> {
    use serde_json::json;

    fn tron_bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    match type_url {
        "type.googleapis.com/protocol.TransferContract" => {
            let c = protocol::TransferContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "to_address": tron_bytes_to_hex(&c.to_address),
                "amount": c.amount
            }))
        }
        "type.googleapis.com/protocol.TriggerSmartContract" => {
            let c = protocol::TriggerSmartContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            let mut map = serde_json::Map::new();
            if !c.owner_address.is_empty() {
                map.insert(
                    "owner_address".to_string(),
                    json!(tron_bytes_to_hex(&c.owner_address)),
                );
            }
            if !c.contract_address.is_empty() {
                map.insert(
                    "contract_address".to_string(),
                    json!(tron_bytes_to_hex(&c.contract_address)),
                );
            }
            if c.call_value > 0 {
                map.insert("call_value".to_string(), json!(c.call_value));
            }
            if !c.data.is_empty() {
                map.insert("data".to_string(), json!(tron_bytes_to_hex(&c.data)));
            }
            if c.call_token_value > 0 {
                map.insert("call_token_value".to_string(), json!(c.call_token_value));
            }
            if c.token_id > 0 {
                map.insert("token_id".to_string(), json!(c.token_id));
            }
            Ok(serde_json::Value::Object(map))
        }
        "type.googleapis.com/protocol.FreezeBalanceV2Contract" => {
            let c = protocol::FreezeBalanceV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "frozen_balance": c.frozen_balance,
                "resource": c.resource
            }))
        }
        "type.googleapis.com/protocol.UnfreezeBalanceV2Contract" => {
            let c = protocol::UnfreezeBalanceV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "unfreeze_balance": c.unfreeze_balance,
                "resource": c.resource
            }))
        }
        "type.googleapis.com/protocol.WithdrawExpireUnfreezeContract" => {
            let c = protocol::WithdrawExpireUnfreezeContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address)
            }))
        }
        "type.googleapis.com/protocol.DelegateResourceContract" => {
            let c = protocol::DelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "resource": c.resource,
                "balance": c.balance,
                "receiver_address": tron_bytes_to_hex(&c.receiver_address),
                "lock": c.lock,
                "lock_period": c.lock_period
            }))
        }
        "type.googleapis.com/protocol.UnDelegateResourceContract" => {
            let c = protocol::UnDelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "resource": c.resource,
                "balance": c.balance,
                "receiver_address": tron_bytes_to_hex(&c.receiver_address)
            }))
        }
        "type.googleapis.com/protocol.CancelAllUnfreezeV2Contract" => {
            let c = protocol::CancelAllUnfreezeV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address)
            }))
        }
        "type.googleapis.com/protocol.TransferAssetContract" => {
            let c = protocol::TransferAssetContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "asset_name": tron_bytes_to_hex(&c.asset_name),
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "to_address": tron_bytes_to_hex(&c.to_address),
                "amount": c.amount
            }))
        }
        "type.googleapis.com/protocol.VoteWitnessContract" => {
            let c = protocol::VoteWitnessContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            let votes: Vec<serde_json::Value> = c
                .votes
                .iter()
                .map(|v| {
                    json!({
                        "vote_address": tron_bytes_to_hex(&v.vote_address),
                        "vote_count": v.vote_count
                    })
                })
                .collect();
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "votes": votes,
                "support": c.support
            }))
        }
        "type.googleapis.com/protocol.AccountCreateContract" => {
            let c = protocol::AccountCreateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "account_address": tron_bytes_to_hex(&c.account_address)
            }))
        }
        "type.googleapis.com/protocol.AccountUpdateContract" => {
            let c = protocol::AccountUpdateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address),
                "account_name": tron_bytes_to_hex(&c.account_name)
            }))
        }
        "type.googleapis.com/protocol.AccountPermissionUpdateContract" => {
            let c = protocol::AccountPermissionUpdateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Ok(json!({
                "owner_address": tron_bytes_to_hex(&c.owner_address)
            }))
        }
        _ => Err(TransactionErrors::InvalidContract),
    }
}

fn extract_owner_from_parameter(
    value: &[u8],
    type_url: &str,
) -> Result<Address, TransactionErrors> {
    match type_url {
        "type.googleapis.com/protocol.TransferContract" => {
            let c = protocol::TransferContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.TriggerSmartContract" => {
            let c = protocol::TriggerSmartContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.FreezeBalanceV2Contract" => {
            let c = protocol::FreezeBalanceV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.UnfreezeBalanceV2Contract" => {
            let c = protocol::UnfreezeBalanceV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.WithdrawExpireUnfreezeContract" => {
            let c = protocol::WithdrawExpireUnfreezeContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.DelegateResourceContract" => {
            let c = protocol::DelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.UnDelegateResourceContract" => {
            let c = protocol::UnDelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.CancelAllUnfreezeV2Contract" => {
            let c = protocol::CancelAllUnfreezeV2Contract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.TransferAssetContract" => {
            let c = protocol::TransferAssetContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.VoteWitnessContract" => {
            let c = protocol::VoteWitnessContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.AccountCreateContract" => {
            let c = protocol::AccountCreateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.AccountUpdateContract" => {
            let c = protocol::AccountUpdateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.AccountPermissionUpdateContract" => {
            let c = protocol::AccountPermissionUpdateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.owner_address).map_err(TransactionErrors::AddressError)
        }
        _ => Err(TransactionErrors::InvalidContract),
    }
}

fn extract_to_address_from_parameter(
    value: &[u8],
    type_url: &str,
    raw: &protocol::transaction::Raw,
) -> Result<Address, TransactionErrors> {
    match type_url {
        "type.googleapis.com/protocol.TransferContract" => {
            let c = protocol::TransferContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.to_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.TriggerSmartContract" => {
            let c = protocol::TriggerSmartContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.contract_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.DelegateResourceContract" => {
            let c = protocol::DelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.receiver_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.UnDelegateResourceContract" => {
            let c = protocol::UnDelegateResourceContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.receiver_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.TransferAssetContract" => {
            let c = protocol::TransferAssetContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.to_address).map_err(TransactionErrors::AddressError)
        }
        "type.googleapis.com/protocol.AccountCreateContract" => {
            let c = protocol::AccountCreateContract::decode(value)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
            Address::from_tron_bytes(&c.account_address).map_err(TransactionErrors::AddressError)
        }
        _ => {
            let contract = raw
                .contract
                .first()
                .ok_or(TransactionErrors::InvalidContract)?;
            let param = contract
                .parameter
                .as_ref()
                .ok_or(TransactionErrors::InvalidContract)?;
            extract_owner_from_parameter(&param.value, &param.type_url)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn test_transfer_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x01], vec![0xab; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner, &to, 1_000_000)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_trigger_smart_contract_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let contract_addr = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("a9059cbb").unwrap());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(contract_addr.as_ref());
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x01);

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x02], vec![0xcd; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .fee_limit(100_000_000)
            .trigger_smart_contract(&owner, &contract_addr, 0, data, 0, 0)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x03], vec![0xef; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner, &to, 2_000_000)
            .build()
            .unwrap();

        let hex = hex::encode(tx.encode());
        let decoded = TronTransaction::from_hex(&hex).unwrap();

        assert_eq!(decoded.fee_limit(), tx.fee_limit());
        assert_eq!(decoded.expiration(), tx.expiration());
        assert_eq!(decoded.timestamp(), tx.timestamp());
        assert_eq!(decoded.owner_address().unwrap(), owner);
    }

    #[test]
    fn test_modify_fee_limit() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let mut tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x04], vec![0x11; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner, &to, 1_000_000)
            .build()
            .unwrap();

        assert_eq!(tx.fee_limit(), 0);

        tx.set_fee_limit(500_000_000);
        assert_eq!(tx.fee_limit(), 500_000_000);

        let receipt = tx.sign(&keypair).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_tron_web_json_parsing() {
        let json = r#"{
            "visible": false,
            "txID": "536a4c369fb07663a21a826cc1f4bd35ff2d83b3042fa242b240217f44912cd0",
            "raw_data": {
                "contract": [{
                    "parameter": {
                        "value": {
                            "data": "095ea7b3000000000000000000000000be365314f2e77fd1257d60c346bb32dbda369403ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "owner_address": "41cad64aace72b5465e7c4f6f27c8683b977341e8c",
                            "contract_address": "41751f6515e355dc49474a8565a1234bf3424b9fe4"
                        },
                        "type_url": "type.googleapis.com/protocol.TriggerSmartContract"
                    },
                    "type": "TriggerSmartContract"
                }],
                "ref_block_bytes": "a653",
                "ref_block_hash": "96e2b982db3d40d8",
                "expiration": 1773409017000,
                "fee_limit": 1000000000,
                "timestamp": 1773408959995
            },
            "raw_data_hex": "0a02a653220896e2b982db3d40d840a8b9a8bbce335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541cad64aace72b5465e7c4f6f27c8683b977341e8c121541751f6515e355dc49474a8565a1234bf3424b9fe42244095ea7b3000000000000000000000000be365314f2e77fd1257d60c346bb32dbda369403ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff70fbfba4bbce3390018094ebdc03"
        }"#;

        let web_tx: TronWebTransaction = serde_json::from_str(json).unwrap();
        let tx = TronTransaction::from_tron_web(&web_tx).unwrap();

        assert_eq!(tx.expiration(), 1773409017000);
        assert_eq!(tx.fee_limit(), 1000000000);
        assert_eq!(tx.timestamp(), 1773408959995);
        assert_eq!(tx.contract_type(), Some("TriggerSmartContract"));
    }

    #[test]
    fn test_tron_sign_request_full_flow() {
        let json = r#"{
            "method": "tron_sign",
            "params": {
                "transaction": {
                    "visible": false,
                    "txID": "536a4c369fb07663a21a826cc1f4bd35ff2d83b3042fa242b240217f44912cd0",
                    "raw_data": {
                        "contract": [{
                            "parameter": {
                                "value": {
                                    "data": "095ea7b3000000000000000000000000be365314f2e77fd1257d60c346bb32dbda369403ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                                    "owner_address": "41cad64aace72b5465e7c4f6f27c8683b977341e8c",
                                    "contract_address": "41751f6515e355dc49474a8565a1234bf3424b9fe4"
                                },
                                "type_url": "type.googleapis.com/protocol.TriggerSmartContract"
                            },
                            "type": "TriggerSmartContract"
                        }],
                        "ref_block_bytes": "a653",
                        "ref_block_hash": "96e2b982db3d40d8",
                        "expiration": 1773409017000,
                        "fee_limit": 1000000000,
                        "timestamp": 1773408959995
                    },
                    "raw_data_hex": "0a02a653220896e2b982db3d40d840a8b9a8bbce335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541cad64aace72b5465e7c4f6f27c8683b977341e8c121541751f6515e355dc49474a8565a1234bf3424b9fe42244095ea7b3000000000000000000000000be365314f2e77fd1257d60c346bb32dbda369403ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff70fbfba4bbce3390018094ebdc03"
                },
                "useTronHeader": true,
                "input": {
                    "data": "095ea7b3000000000000000000000000be365314f2e77fd1257d60c346bb32dbda369403ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "owner_address": "41cad64aace72b5465e7c4f6f27c8683b977341e8c",
                    "contract_address": "41751f6515e355dc49474a8565a1234bf3424b9fe4"
                }
            }
        }"#;

        let sign_request: TronWebSignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(sign_request.method, "tron_sign");

        let original_tx_json = serde_json::to_value(&sign_request.params.transaction).unwrap();

        let tx = TronTransaction::from_tron_web(&sign_request.params.transaction).unwrap();

        let tx_web = tx.to_tron_web().unwrap();
        let converted_tx_json = serde_json::to_value(&tx_web).unwrap();

        assert_eq!(
            original_tx_json, converted_tx_json,
            "JSON should match after round-trip conversion"
        );

        assert_eq!(tx.contract_type(), Some("TriggerSmartContract"));
        assert_eq!(tx.fee_limit(), 1000000000);

        let original_tx_id = tx.tx_id();
        let original_tx_id_hex = hex::encode(original_tx_id);
        assert_eq!(
            original_tx_id_hex,
            "536a4c369fb07663a21a826cc1f4bd35ff2d83b3042fa242b240217f44912cd0"
        );

        let owner = tx.owner_address().unwrap();
        assert_eq!(owner.auto_format(), "TUTiD4GUapWtyQeV1NZbCxpqCQJ9L5veGh");

        let contract_addr = tx.to_address().unwrap();
        assert_eq!(
            contract_addr.auto_format(),
            "TLeVfrdym8RoJreJ23dAGyfJDygRtiWKBZ"
        );
    }

    #[test]
    fn test_freeze_balance_v2() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x05], vec![0x55; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .freeze_balance_v2(&owner, 10_000_000, TronResource::Energy)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_delegate_resource() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let receiver = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x06], vec![0x66; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .delegate_resource(
                &owner,
                TronResource::Bandwidth,
                5_000_000,
                &receiver,
                false,
                0,
            )
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_wrong_keypair_fails_verification() {
        let keypair1 = KeyPair::gen_tron().unwrap();
        let keypair2 = KeyPair::gen_tron().unwrap();
        let owner1 = keypair1.get_addr().unwrap();
        let to = keypair2.get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x07], vec![0x77; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner1, &to, 100_000)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair2).unwrap();
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn test_receipt_to_tron_web_json() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x01], vec![0xab; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner, &to, 1_000_000)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        let json = receipt.to_tron_web_json().unwrap();

        assert_eq!(json["visible"], false);
        assert_eq!(json["txID"], hex::encode(receipt.tx_id));
        assert!(json["raw_data"].is_object());
        assert!(json["raw_data"]["contract"].is_array());
        assert_eq!(
            json["raw_data"]["expiration"].as_i64().unwrap(),
            1700000000000
        );
        assert_eq!(
            json["raw_data"]["timestamp"].as_i64().unwrap(),
            1699999990000
        );
        assert_eq!(json["raw_data_hex"], hex::encode(&receipt.raw_data_bytes));
        assert!(json["signature"].is_array());
        assert_eq!(json["signature"][0], hex::encode(&receipt.signature));
    }

    #[test]
    fn test_receipt_to_tron_web_json_trigger_contract() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let contract_addr = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("a9059cbb").unwrap());

        let tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x02], vec![0xcd; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .fee_limit(100_000_000)
            .trigger_smart_contract(&owner, &contract_addr, 0, data, 0, 0)
            .build()
            .unwrap();

        let receipt = tx.sign(&keypair).unwrap();
        let json = receipt.to_tron_web_json().unwrap();

        assert_eq!(json["visible"], false);
        assert_eq!(json["txID"], hex::encode(receipt.tx_id));
        assert!(json["raw_data"]["contract"].is_array());
        assert_eq!(
            json["raw_data"]["contract"][0]["type"],
            "TriggerSmartContract"
        );
        assert_eq!(json["raw_data"]["fee_limit"].as_i64().unwrap(), 100_000_000);
        assert!(json["signature"].is_array());
    }

    #[tokio::test]
    async fn test_transaction_request_sign_to_json() {
        use crate::tx::{TransactionMetadata, TransactionReceipt, TransactionRequest};
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let tron_tx = TronTransaction::builder()
            .ref_block(vec![0x00, 0x01], vec![0xab; 8])
            .expiration(1700000000000)
            .timestamp(1699999990000)
            .transfer(&owner, &to, 1_000_000)
            .build()
            .unwrap();

        let tx_req = TransactionRequest::Tron((tron_tx, TransactionMetadata::default()));
        let receipt = tx_req.sign(&keypair).await.unwrap();

        if let TransactionReceipt::Tron((tron_receipt, _meta)) = receipt {
            let json = tron_receipt.to_tron_web_json().unwrap();

            assert_eq!(json["visible"], false);
            assert!(json["txID"].is_string());
            assert!(json["raw_data"].is_object());
            assert!(json["raw_data"]["contract"].is_array());
            assert!(json["raw_data_hex"].is_string());
            assert!(json["signature"].is_array());
            assert_eq!(json["signature"].as_array().unwrap().len(), 1);
        } else {
            panic!("Expected Tron transaction receipt");
        }
    }
}
