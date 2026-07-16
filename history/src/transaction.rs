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
    solana_tx::SolanaHistoryTransaction,
    tron_tx::TronTransactionReceipt,
    tx::{TransactionMetadata, TransactionReceipt},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Dual-read helper: new typed receipt or legacy TronWeb JSON string.
mod optional_tron_history {
    use super::TronTransactionReceipt;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        value: &Option<TronTransactionReceipt>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<TronTransactionReceipt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Receipt(TronTransactionReceipt),
            LegacyJson(String),
        }

        match Option::<Helper>::deserialize(deserializer)? {
            None => Ok(None),
            Some(Helper::Receipt(receipt)) => Ok(Some(receipt)),
            Some(Helper::LegacyJson(json_str)) => {
                TronTransactionReceipt::try_from_tron_web_json_str(&json_str)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}

/// Dual-read helper: new typed Solana history or legacy JSON string blob.
mod optional_solana_history {
    use super::SolanaHistoryTransaction;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        value: &Option<SolanaHistoryTransaction>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<SolanaHistoryTransaction>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Typed(SolanaHistoryTransaction),
            LegacyJson(String),
        }

        match Option::<Helper>::deserialize(deserializer)? {
            None => Ok(None),
            Some(Helper::Typed(tx)) => Ok(Some(tx)),
            Some(Helper::LegacyJson(json_str)) => {
                SolanaHistoryTransaction::try_from_legacy_json_str(&json_str)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HistoricalTransaction {
    pub status: TransactionStatus,
    pub metadata: TransactionMetadata,
    pub evm: Option<String>,
    pub scilla: Option<String>,
    pub btc: Option<(bitcoin::Transaction, BitcoinMetadata)>,
    #[serde(with = "optional_tron_history")]
    pub tron: Option<TronTransactionReceipt>,
    #[serde(with = "optional_solana_history")]
    pub solana: Option<SolanaHistoryTransaction>,
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

    pub fn get_tron(&self) -> Option<&TronTransactionReceipt> {
        self.tron.as_ref()
    }

    pub fn set_tron(&mut self, receipt: TronTransactionReceipt) {
        self.tron = Some(receipt);
    }

    /// Update status from an eth-compatible getTransactionReceipt payload.
    /// Does not write into `evm` — Tron history stays under `tron` only.
    pub fn update_from_tron_receipt_status(&mut self, receipt: &Value) {
        let success = receipt
            .get("status")
            .and_then(Value::as_str)
            .map(|s| s == "0x1" || s == "1")
            .unwrap_or(false);

        self.status = if success {
            TransactionStatus::Success
        } else {
            TransactionStatus::Failed
        };
    }

    pub fn get_solana(&self) -> Option<&SolanaHistoryTransaction> {
        self.solana.as_ref()
    }

    pub fn set_solana(&mut self, value: SolanaHistoryTransaction) {
        self.solana = Some(value);
    }

    /// Apply `getTransaction` confirmation fields onto the typed Solana history row.
    pub fn update_from_solana_confirmation(
        &mut self,
        success: bool,
        fee: Option<u64>,
        slot: Option<u64>,
    ) {
        self.status = if success {
            TransactionStatus::Success
        } else {
            TransactionStatus::Failed
        };
        if let Some(entry) = self.solana.as_mut() {
            if fee.is_some() {
                entry.fee = fee;
            }
            if slot.is_some() {
                entry.slot = slot;
            }
        }
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
            TransactionReceipt::Tron((tron_tx, metadata)) => Ok(Self {
                status: TransactionStatus::Pending,
                metadata,
                evm: None,
                scilla: None,
                btc: None,
                tron: Some(tron_tx),
                solana: None,
                signed_message: None,
                timestamp,
            }),
            TransactionReceipt::Solana((solana_receipt, metadata)) => Ok(Self {
                status: TransactionStatus::Pending,
                metadata,
                evm: None,
                scilla: None,
                btc: None,
                tron: None,
                solana: Some(SolanaHistoryTransaction::from(solana_receipt)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use proto::tron_tx::TronTransactionReceipt;

    #[test]
    fn tron_legacy_json_string_deserializes() {
        let receipt = TronTransactionReceipt::try_from_tron_web_json_str(
            r#"{"visible":false,"txID":"960188a94300ab78687bc8b9e42824c86d2c11a8ac7518022d868a96dd8c92a7","raw_data":{"contract":[{"parameter":{"value":{"data":"a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a7640000","owner_address":"419705bf55c3dcc6d277ebb8fe2a68762268822ba2","contract_address":"418df49db5dbf07e498492d2dafcf7b305cdc72471"},"type_url":"type.googleapis.com/protocol.TriggerSmartContract"},"type":"TriggerSmartContract"}],"ref_block_bytes":"6b48","ref_block_hash":"4448fdd628a1901b","expiration":1773553356000,"fee_limit":1340876,"timestamp":1773553056000},"raw_data_hex":"0a026b4822084448fdd628a1901b40e0999280cf335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15419705bf55c3dcc6d277ebb8fe2a68762268822ba21215418df49db5dbf07e498492d2dafcf7b305cdc724712244a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a76400007080f2ffffce339001cceb51","signature":["4735316cacefae2cfccd7d686ff25f8910ca7b05d11d2dd583c9b7c6af03427554f5a7017033bc0db9d5b654d0a9e864b4e30877c6a9b88798158c19e380f04201"]}"#,
        );
        assert!(receipt.is_ok(), "legacy helper: {receipt:?}");
        let receipt = receipt.unwrap();
        assert_eq!(
            alloy::hex::encode(receipt.tx_id),
            "960188a94300ab78687bc8b9e42824c86d2c11a8ac7518022d868a96dd8c92a7"
        );

        let hist = HistoricalTransaction {
            tron: Some(receipt),
            timestamp: 1,
            ..Default::default()
        };
        let json = serde_json::to_string(&hist).expect("serialize");
        let restored: HistoricalTransaction =
            serde_json::from_str(&json).expect("deserialize typed");
        assert!(restored.tron.is_some());
        assert!(restored.evm.is_none());

        // Dual-read: field stored as a raw TronWeb JSON string (legacy rows).
        let legacy_hist = format!(
            r#"{{"status":"Pending","metadata":{{}},"tron":{},"timestamp":1}}"#,
            serde_json::to_string(
                r#"{"visible":false,"txID":"960188a94300ab78687bc8b9e42824c86d2c11a8ac7518022d868a96dd8c92a7","raw_data":{"contract":[{"parameter":{"value":{"data":"a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a7640000","owner_address":"419705bf55c3dcc6d277ebb8fe2a68762268822ba2","contract_address":"418df49db5dbf07e498492d2dafcf7b305cdc72471"},"type_url":"type.googleapis.com/protocol.TriggerSmartContract"},"type":"TriggerSmartContract"}],"ref_block_bytes":"6b48","ref_block_hash":"4448fdd628a1901b","expiration":1773553356000,"fee_limit":1340876,"timestamp":1773553056000},"raw_data_hex":"0a026b4822084448fdd628a1901b40e0999280cf335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15419705bf55c3dcc6d277ebb8fe2a68762268822ba21215418df49db5dbf07e498492d2dafcf7b305cdc724712244a9059cbb000000000000000000000000e2e1a54926527fbb4e4420de4c6bab82beaee24d0000000000000000000000000000000000000000000000000de0b6b3a76400007080f2ffffce339001cceb51","signature":["4735316cacefae2cfccd7d686ff25f8910ca7b05d11d2dd583c9b7c6af03427554f5a7017033bc0db9d5b654d0a9e864b4e30877c6a9b88798158c19e380f04201"]}"#
            )
            .unwrap()
        );
        let from_legacy: HistoricalTransaction =
            serde_json::from_str(&legacy_hist).expect("deserialize legacy string form");
        assert!(from_legacy.tron.is_some());
    }

    #[test]
    fn tron_status_update_does_not_set_evm() {
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            tron: Some(TronTransactionReceipt {
                raw_data_bytes: vec![0x0a],
                tx_id: [0u8; 32],
                signature: Vec::new(),
                owner_address: Address::Secp256k1Tron([0u8; 20]),
            }),
            ..Default::default()
        };
        tx.update_from_tron_receipt_status(&json!({"status": "0x1"}));
        assert_eq!(tx.status, TransactionStatus::Success);
        assert!(tx.evm.is_none());
        assert!(tx.tron.is_some());
    }

    #[test]
    fn solana_legacy_json_string_deserializes() {
        use proto::solana_tx::SolanaHistoryTransaction;

        let sig = [3u8; 64];
        let hash = SolanaHistoryTransaction {
            signature: sig.to_vec(),
            ..Default::default()
        }
        .tx_id();
        let legacy_blob = format!(
            r#"{{"transactionHash":"{}","fee":"5000","slot":"99"}}"#,
            hash
        );
        let legacy_hist = format!(
            r#"{{"status":"Pending","metadata":{{}},"solana":{},"timestamp":1}}"#,
            serde_json::to_string(&legacy_blob).expect("wrap legacy string")
        );
        let from_legacy: HistoricalTransaction =
            serde_json::from_str(&legacy_hist).expect("deserialize legacy solana string form");
        let solana = from_legacy.get_solana().expect("solana present");
        assert_eq!(solana.signature, sig.to_vec());
        assert_eq!(solana.fee, Some(5000));
        assert_eq!(solana.slot, Some(99));
        assert!(solana.message.is_empty());
    }

    #[test]
    fn solana_typed_roundtrip_and_confirmation_update() {
        use proto::solana_tx::SolanaHistoryTransaction;

        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            solana: Some(SolanaHistoryTransaction {
                message: vec![0xde, 0xad],
                signature: vec![0xbe; 64],
                fee: None,
                slot: None,
            }),
            timestamp: 1,
            ..Default::default()
        };

        let json = serde_json::to_string(&tx).expect("serialize");
        let restored: HistoricalTransaction =
            serde_json::from_str(&json).expect("deserialize typed solana");
        assert!(restored.solana.is_some());
        assert_eq!(
            restored.get_solana().map(|s| s.message.as_slice()),
            Some([0xde, 0xad].as_slice())
        );

        tx.update_from_solana_confirmation(true, Some(5000), Some(123));
        assert_eq!(tx.status, TransactionStatus::Success);
        let solana = tx.get_solana().expect("solana present");
        assert_eq!(solana.fee, Some(5000));
        assert_eq!(solana.slot, Some(123));
        assert_eq!(solana.message, vec![0xde, 0xad]);
    }
}
