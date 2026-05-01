use std::time::{SystemTime, UNIX_EPOCH};

use crate::status::TransactionStatus;
use alloy::{
    consensus::{transaction::SignerRecoverable, Transaction, TxType},
    primitives::TxKind,
};
use errors::tx::TransactionErrors;
use proto::{
    address::Address,
    btc_tx::BitcoinMetadata,
    pubkey::PubKey,
    tx::{TransactionMetadata, TransactionReceipt},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HistoricalTransaction {
    pub status: TransactionStatus,
    pub metadata: TransactionMetadata,
    pub evm: Option<String>,
    pub scilla: Option<String>,
    pub btc: Option<(bitcoin::Transaction, BitcoinMetadata)>,
    pub tron: Option<String>,
    pub solana: Option<String>,
    pub signed_message: Option<String>,
    pub timestamp: u64,
}

impl HistoricalTransaction {
    pub fn get_evm(&self) -> Option<Value> {
        self.evm.as_ref().and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn get_scilla(&self) -> Option<Value> {
        self.scilla
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn set_evm(&mut self, value: Value) {
        self.evm = serde_json::to_string(&value).ok();
    }

    pub fn set_scilla(&mut self, value: Value) {
        self.scilla = serde_json::to_string(&value).ok();
    }

    pub fn get_btc(&self) -> Option<&(bitcoin::Transaction, BitcoinMetadata)> {
        self.btc.as_ref()
    }

    pub fn set_btc(&mut self, value: (bitcoin::Transaction, BitcoinMetadata)) {
        self.btc = Some(value);
    }

    pub fn update_btc_tx(&mut self, tx: bitcoin::Transaction) {
        if let Some((_, meta)) = self.btc.take() {
            self.btc = Some((tx, meta));
        }
    }

    pub fn get_tron(&self) -> Option<Value> {
        self.tron
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn set_tron(&mut self, value: Value) {
        self.tron = serde_json::to_string(&value).ok();
    }

    pub fn get_solana(&self) -> Option<Value> {
        self.solana
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn set_solana(&mut self, value: Value) {
        self.solana = serde_json::to_string(&value).ok();
    }

    pub fn get_signed_message(&self) -> Option<Value> {
        self.signed_message
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn set_signed_message(&mut self, value: Value) {
        self.signed_message = serde_json::to_string(&value).ok();
    }

    pub fn from_signed_message(
        message: &str,
        signature: &str,
        pub_key: &str,
        signer_address: &str,
        title: Option<String>,
        icon: Option<String>,
        chain_hash: u64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let signed_msg = json!({
            "type": "personal_sign",
            "message": message,
            "signature": signature,
            "pubKey": pub_key,
            "signer": signer_address,
        });

        Self {
            status: TransactionStatus::Success,
            metadata: TransactionMetadata {
                chain_hash,
                title,
                icon,
                ..Default::default()
            },
            evm: None,
            scilla: None,
            btc: None,
            tron: None,
            solana: None,
            signed_message: serde_json::to_string(&signed_msg).ok(),
            timestamp,
        }
    }

    pub fn from_signed_typed_data(
        typed_data_json: &str,
        signature: &str,
        pub_key: &str,
        signer_address: &str,
        title: Option<String>,
        icon: Option<String>,
        chain_hash: u64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let typed_data: Value = serde_json::from_str(typed_data_json).unwrap_or(Value::Null);

        let signed_msg = json!({
            "type": "eth_signTypedData_v4",
            "typedData": typed_data,
            "signature": signature,
            "pubKey": pub_key,
            "signer": signer_address,
        });

        Self {
            status: TransactionStatus::Success,
            metadata: TransactionMetadata {
                chain_hash,
                title,
                icon,
                ..Default::default()
            },
            evm: None,
            scilla: None,
            btc: None,
            tron: None,
            solana: None,
            signed_message: serde_json::to_string(&signed_msg).ok(),
            timestamp,
        }
    }

    pub fn from_transaction_receipt(
        receipt: TransactionReceipt,
    ) -> Result<Self, TransactionErrors> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match receipt {
            TransactionReceipt::Zilliqa((zil_receipt, metadata)) => {
                let sender_pub_key = alloy::hex::encode(zil_receipt.pub_key);
                let sender_addr = PubKey::Secp256k1Sha256(zil_receipt.pub_key)
                    .get_addr()?
                    .get_zil_bech32()?;
                let chain_id = proto::zq1_proto::chainid_from_version(zil_receipt.version);

                let scilla = json!({
                    "hash": metadata.hash.clone().unwrap_or_default(),
                    "version": zil_receipt.version.to_string(),
                    "nonce": zil_receipt.nonce.to_string(),
                    "toAddr": Address::Secp256k1Sha256(zil_receipt.to_addr)
                        .get_zil_check_sum_addr()
                        .unwrap_or_default(),
                    "senderAddr": sender_addr,
                    "senderPubKey": sender_pub_key,
                    "amount": u128::from_be_bytes(zil_receipt.amount).to_string(),
                    "gasPrice": u128::from_be_bytes(zil_receipt.gas_price).to_string(),
                    "gasLimit": zil_receipt.gas_limit.to_string(),
                    "code": String::from_utf8(zil_receipt.code).unwrap_or_default(),
                    "data": String::from_utf8(zil_receipt.data).unwrap_or_default(),
                    "signature": alloy::hex::encode(zil_receipt.signature),
                    "priority": zil_receipt.priority,
                    "chainId": chain_id,
                    "receipt": null,
                });

                Ok(Self {
                    status: TransactionStatus::Pending,
                    metadata,
                    evm: None,
                    scilla: serde_json::to_string(&scilla).ok(),
                    btc: None,
                    tron: None,
                    solana: None,
                    signed_message: None,
                    timestamp,
                })
            }
            TransactionReceipt::Ethereum((tx, metadata)) => {
                let from = tx.recover_signer().unwrap_or_default();
                let to = match tx.kind() {
                    TxKind::Call(addr) => Some(addr.to_string()),
                    TxKind::Create => None,
                };
                let tx_type = match tx.tx_type() {
                    TxType::Legacy => "legacy",
                    TxType::Eip2930 => "eip2930",
                    TxType::Eip1559 => "eip1559",
                    TxType::Eip4844 => "eip4844",
                    TxType::Eip7702 => "eip7702",
                };

                let mut evm = json!({
                    "transactionHash": metadata.hash.clone().unwrap_or_default(),
                    "from": from.to_string(),
                    "to": to,
                    "type": tx_type,
                    "value": tx.value().to_string(),
                    "nonce": tx.nonce().to_string(),
                    "chainId": tx.chain_id().map(|id| id.to_string()),
                });

                if let Some(gas_limit) = Some(tx.gas_limit()) {
                    evm["gasLimit"] = json!(gas_limit.to_string());
                }
                if let Some(gas_price) = tx.gas_price() {
                    evm["gasPrice"] = json!(gas_price.to_string());
                }
                if let Some(max_fee) = Some(tx.max_fee_per_gas()) {
                    evm["maxFeePerGas"] = json!(max_fee.to_string());
                }
                if let Some(priority_fee) = tx.max_priority_fee_per_gas() {
                    evm["maxPriorityFeePerGas"] = json!(priority_fee.to_string());
                }

                let input = tx.input();
                if !input.is_empty() {
                    evm["data"] = json!(alloy::hex::encode_prefixed(input));
                }

                Ok(Self {
                    status: TransactionStatus::Pending,
                    metadata,
                    evm: serde_json::to_string(&evm).ok(),
                    scilla: None,
                    btc: None,
                    tron: None,
                    solana: None,
                    signed_message: None,
                    timestamp,
                })
            }
            TransactionReceipt::Bitcoin((tx, metadata, btc_meta)) => Ok(Self {
                status: TransactionStatus::Pending,
                metadata,
                evm: None,
                scilla: None,
                btc: Some((tx, btc_meta)),
                tron: None,
                solana: None,
                signed_message: None,
                timestamp,
            }),
            TransactionReceipt::Tron((tron_tx, metadata)) => {
                let tron = tron_tx.to_tron_web_json()?;

                Ok(Self {
                    status: TransactionStatus::Pending,
                    metadata,
                    evm: None,
                    scilla: None,
                    btc: None,
                    tron: serde_json::to_string(&tron).ok(),
                    solana: None,
                    signed_message: None,
                    timestamp,
                })
            }
            TransactionReceipt::Solana((solana_receipt, metadata)) => Ok(Self {
                status: TransactionStatus::Pending,
                metadata,
                evm: None,
                scilla: None,
                btc: None,
                tron: None,
                solana: serde_json::to_string(&json!({
                    "transactionHash": solana_receipt.tx_id(),
                }))
                .ok(),
                signed_message: None,
                timestamp,
            }),
        }
    }

    pub fn update_from_evm_receipt(&mut self, receipt: Value) {
        let success = receipt
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s == "0x1")
            .unwrap_or(false);

        if let Some(mut evm) = self.get_evm() {
            if let Some(obj) = evm.as_object_mut() {
                if let Some(receipt_obj) = receipt.as_object() {
                    for (key, value) in receipt_obj {
                        obj.insert(key.clone(), value.clone());
                    }
                }
            }
            self.set_evm(evm);
        } else {
            self.set_evm(receipt);
        }

        self.status = if success {
            TransactionStatus::Success
        } else {
            TransactionStatus::Failed
        };
    }

    pub fn update_from_scilla_result(&mut self, result: Value) {
        if let Some(mut scilla) = self.get_scilla() {
            if let Some(obj) = scilla.as_object_mut() {
                if let Some(result_obj) = result.as_object() {
                    for (key, value) in result_obj {
                        obj.insert(key.clone(), value.clone());
                    }
                }
            }
            self.set_scilla(scilla.clone());
            self.update_scilla_status(&scilla);
        } else {
            self.set_scilla(result.clone());
            self.update_scilla_status(&result);
        }
    }

    fn update_scilla_status(&mut self, scilla: &Value) {
        if let Some(status) = scilla.get("status").and_then(|s| s.as_u64()) {
            match status {
                3 => self.status = TransactionStatus::Success,
                0 | 1 | 2 | 4 | 5 | 6 => self.status = TransactionStatus::Pending,
                _ => self.status = TransactionStatus::Failed,
            }
            return;
        }

        if let Some(receipt) = scilla.get("receipt").filter(|r| !r.is_null()) {
            let success = receipt
                .get("success")
                .and_then(|s| s.as_bool())
                .unwrap_or(false);
            self.status = if success {
                TransactionStatus::Success
            } else {
                TransactionStatus::Failed
            };
        }
    }
}

impl TryFrom<TransactionReceipt> for HistoricalTransaction {
    type Error = TransactionErrors;

    fn try_from(receipt: TransactionReceipt) -> Result<Self, Self::Error> {
        Self::from_transaction_receipt(receipt)
    }
}
