use crate::{keypair::KeyPair, signature::Signature};
use errors::keypair::KeyPairError;
use errors::tx::TransactionErrors;
use serde::{Deserialize, Serialize};
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{legacy::Message, v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_system_interface::instruction::transfer as system_transfer;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_token::instruction::transfer as token_transfer;

type Result<T> = std::result::Result<T, KeyPairError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SolanaTransaction {
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SolanaTransactionReceipt {
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
}

/// Typed Solana row stored under `HistoricalTransaction.solana`.
/// New writes always set `message` + `signature`.
/// Legacy JSON rows may only have a base58 hash (signature recovered when possible).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SolanaHistoryTransaction {
    /// Bincode-encoded Solana message (legacy rows: empty).
    #[serde(with = "hex::serde", default)]
    pub message: Vec<u8>,
    /// 64-byte Ed25519 signature (legacy: decoded from `transactionHash` when possible).
    #[serde(with = "hex::serde", default)]
    pub signature: Vec<u8>,
    /// Confirmation fee in lamports (from `getTransaction.meta.fee`).
    #[serde(default)]
    pub fee: Option<u64>,
    /// Confirmation slot (from `getTransaction.slot`).
    #[serde(default)]
    pub slot: Option<u64>,
}

impl From<SolanaTransactionReceipt> for SolanaHistoryTransaction {
    fn from(receipt: SolanaTransactionReceipt) -> Self {
        Self {
            message: receipt.message,
            signature: receipt.signature,
            fee: None,
            slot: None,
        }
    }
}

impl SolanaHistoryTransaction {
    #[inline]
    pub fn tx_id(&self) -> String {
        bs58::encode(&self.signature).into_string()
    }

    #[inline]
    pub fn signature_ref(&self) -> &[u8] {
        self.signature.as_slice()
    }

    /// Rebuild from legacy history string:
    /// `{"transactionHash":"<b58>","fee":"5000","slot":"123"}` (fee/slot string or number).
    pub fn try_from_legacy_json_str(json_str: &str) -> std::result::Result<Self, TransactionErrors> {
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;
        Self::try_from_legacy_value(&value)
    }

    pub fn try_from_legacy_value(
        value: &serde_json::Value,
    ) -> std::result::Result<Self, TransactionErrors> {
        let hash = value
            .get("transactionHash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let signature = if hash.is_empty() {
            Vec::with_capacity(0)
        } else {
            bs58::decode(hash)
                .into_vec()
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?
        };

        Ok(Self {
            message: Vec::with_capacity(0),
            signature,
            fee: parse_u64_field(value, "fee"),
            slot: parse_u64_field(value, "slot"),
        })
    }
}

fn parse_u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    let field = value.get(key)?;
    match field {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

impl SolanaTransaction {
    pub fn sign(&self, keypair: &KeyPair) -> Result<SolanaTransactionReceipt> {
        let sig = keypair.sign_message(&self.message)?;

        let sig_bytes = match sig {
            Signature::Ed25519Solana(bytes) => bytes.to_vec(),
            _ => return Err(KeyPairError::InvalidEd25519Solana),
        };

        let receipt = SolanaTransactionReceipt {
            message: self.message.clone(),
            signature: sig_bytes,
        };

        Ok(receipt)
    }
}

impl SolanaTransactionReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.signature.len() + self.message.len());
        result.push(0x01);
        result.extend_from_slice(&self.signature);
        result.extend_from_slice(&self.message);
        result
    }

    pub fn tx_id(&self) -> String {
        bs58::encode(&self.signature).into_string()
    }

    pub fn verify(&self, keypair: &KeyPair) -> Result<bool> {
        let pk = keypair.get_pubkey()?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| KeyPairError::InvalidEd25519Solana)?;
        let sig = Signature::Ed25519Solana(sig_bytes);
        sig.verify(&self.message, &pk)
            .map_err(KeyPairError::InvalidSignature)
    }
}

pub fn build_sol_transfer_message(
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    blockhash: &[u8; 32],
) -> std::result::Result<Vec<u8>, String> {
    let hash = Hash::from(*blockhash);
    let ix = system_transfer(from, to, lamports);
    let msg = Message::new_with_blockhash(&[ix], Some(from), &hash);
    bincode::serialize(&msg).map_err(|e| e.to_string())
}

pub fn adjust_sol_native_transfer_lamports(
    message_bytes: &[u8],
    balance: u64,
    fee: u64,
) -> Option<Vec<u8>> {
    use solana_system_interface::instruction::SystemInstruction;

    let msg: Message = bincode::deserialize(message_bytes).ok()?;
    let ix = match msg.instructions.as_slice() {
        [ix] => ix,
        _ => return None,
    };
    let program_key = msg.account_keys.get(usize::from(ix.program_id_index))?;

    if *program_key != Pubkey::default() {
        return None;
    }

    let sys_ix: SystemInstruction = bincode::deserialize(&ix.data).ok()?;
    let lamports = match sys_ix {
        SystemInstruction::Transfer { lamports } => lamports,
        _ => return None,
    };

    if lamports != balance {
        return None;
    }

    let new_lamports = lamports.saturating_sub(fee);

    if new_lamports == 0 || new_lamports >= lamports {
        return None;
    }

    let from = ix
        .accounts
        .first()
        .and_then(|index| msg.account_keys.get(usize::from(*index)))?;
    let to = ix
        .accounts
        .get(1)
        .and_then(|index| msg.account_keys.get(usize::from(*index)))?;
    let blockhash: [u8; 32] = msg.recent_blockhash.to_bytes();

    build_sol_transfer_message(from, to, new_lamports, &blockhash).ok()
}

pub fn build_message_from_instructions(
    instructions: &[Instruction],
    payer: &Pubkey,
    blockhash: &[u8; 32],
) -> std::result::Result<Vec<u8>, String> {
    let hash = Hash::from(*blockhash);
    let msg = Message::new_with_blockhash(instructions, Some(payer), &hash);
    bincode::serialize(&msg).map_err(|e| e.to_string())
}

pub fn build_versioned_message_from_instructions(
    instructions: &[Instruction],
    payer: &Pubkey,
    blockhash: &[u8; 32],
    lookup_tables: &[AddressLookupTableAccount],
) -> std::result::Result<Vec<u8>, String> {
    if lookup_tables.is_empty() {
        return build_message_from_instructions(instructions, payer, blockhash);
    }

    let hash = Hash::from(*blockhash);
    let message = v0::Message::try_compile(payer, instructions, lookup_tables, hash)
        .map_err(|error| error.to_string())?;

    bincode::serialize(&VersionedMessage::V0(message)).map_err(|error| error.to_string())
}

/// Strict parse: the entire byte slice must be exactly one Solana message
/// (legacy or versioned v0 — `VersionedMessage`'s deserializer handles both).
fn is_bare_message(bytes: &[u8]) -> bool {
    use bincode::Options;
    bincode::options()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize::<VersionedMessage>(bytes)
        .is_ok()
}

#[inline]
fn invalid_payload() -> String {
    String::from("invalid solana transaction payload")
}

/// Solana shortvec (compact-u16): 1–3 bytes, canonical form only.
///
/// Mirrors `solana_short_vec::decode_shortu16_len` / `visit_byte`:
/// - rejects multi-byte aliases of a shorter encoding (`0x80 0x00`, …)
/// - rejects continuation on the 3rd byte
/// - rejects values that overflow `u16` (3rd-byte data bits above the low 2)
///
/// Returns `(value, bytes_consumed)`.
fn decode_compact_u16(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut val: u32 = 0;
    for nth_byte in 0..3 {
        let elem = *bytes.get(nth_byte)?;
        // Non-canonical multi-byte alias of a smaller encoding.
        if elem == 0 && nth_byte != 0 {
            return None;
        }
        let elem_val = u32::from(elem & 0x7f);
        let done = elem & 0x80 == 0;
        // 3rd byte must terminate (continuation bit clear).
        if nth_byte == 2 && !done {
            return None;
        }
        // nth_byte ∈ {0,1,2} ⇒ shift ∈ {0,7,14}; elem_val ≤ 0x7f ⇒ product fits u32.
        let shift = (nth_byte as u32) * 7;
        val |= elem_val << shift;
        // Overflow past u16 (covers 3rd-byte high data bits, e.g. `0x80 0x80 0x04`).
        if val > u32::from(u16::MAX) {
            return None;
        }
        if done {
            return Some((val as usize, nth_byte + 1));
        }
    }
    None
}

/// Accepts either bare Solana message bytes (what internal builders produce)
/// or a full serialized transaction (what WalletConnect dapps send:
/// shortvec sig-count + N×64-byte signatures + message) and returns the bare
/// message bytes in both cases.
pub fn normalize_solana_message(bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if is_bare_message(bytes) {
        return Ok(bytes.to_vec());
    }

    let (sig_count, prefix_len) = decode_compact_u16(bytes).ok_or_else(invalid_payload)?;
    let sig_bytes = sig_count.checked_mul(64).ok_or_else(invalid_payload)?;
    let message_offset = prefix_len
        .checked_add(sig_bytes)
        .ok_or_else(invalid_payload)?;
    let message = bytes
        .get(message_offset..)
        .filter(|rest| !rest.is_empty() && is_bare_message(rest))
        .ok_or_else(invalid_payload)?;

    Ok(message.to_vec())
}

pub fn build_spl_transfer_message(
    owner: &Pubkey,
    mint: &Pubkey,
    to_wallet: &Pubkey,
    amount: u64,
    blockhash: &[u8; 32],
    token_program: &Pubkey,
) -> std::result::Result<Vec<u8>, String> {
    let source_ata = get_associated_token_address_with_program_id(owner, mint, token_program);
    let dest_ata = get_associated_token_address_with_program_id(to_wallet, mint, token_program);
    let hash = Hash::from(*blockhash);
    let create_dest_ata_ix =
        create_associated_token_account_idempotent(owner, to_wallet, mint, token_program);
    let transfer_ix = token_transfer(token_program, &source_ata, &dest_ata, owner, &[], amount)
        .map_err(|e| e.to_string())?;
    let msg = Message::new_with_blockhash(&[create_dest_ata_ix, transfer_ix], Some(owner), &hash);

    bincode::serialize(&msg).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;
    use solana_message::legacy::Message as SolanaMessage;

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    const DEVNET_USDC_RICH_ATA: &str = "6r6KJLTwFLnJ2czodnEQeiWfAEDw2nkCDsu4AwptU3fm";

    #[test]
    fn test_solana_tx_sign_and_encode() {
        let keypair = KeyPair::gen_solana().unwrap();
        let message = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tx = SolanaTransaction {
            message: message.clone(),
        };

        let receipt = tx.sign(&keypair).unwrap();

        assert_eq!(receipt.message, message);
        assert_eq!(receipt.signature.len(), 64);

        let encoded = receipt.encode();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..65], receipt.signature.as_slice());
        assert_eq!(&encoded[65..], message.as_slice());
    }

    #[test]
    fn test_solana_tx_id() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction {
            message: vec![0u8; 32],
        };
        let receipt = tx.sign(&keypair).unwrap();

        let tx_id = receipt.tx_id();
        assert!(!tx_id.is_empty());
        let decoded = bs58::decode(&tx_id).into_vec().unwrap();
        assert_eq!(decoded, receipt.signature);
    }

    #[test]
    fn test_solana_tx_verify() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction {
            message: b"test solana transaction".to_vec(),
        };
        let receipt = tx.sign(&keypair).unwrap();

        assert!(receipt.verify(&keypair).unwrap());
    }

    #[test]
    fn test_solana_tx_verify_wrong_keypair() {
        let keypair1 = KeyPair::gen_solana().unwrap();
        let keypair2 = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction {
            message: b"test message".to_vec(),
        };
        let receipt = tx.sign(&keypair1).unwrap();

        assert!(!receipt.verify(&keypair2).unwrap());
    }

    #[test]
    fn test_solana_tx_serde_roundtrip() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction {
            message: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let receipt = tx.sign(&keypair).unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let recovered: SolanaTransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, recovered);
    }

    #[test]
    fn test_adjust_sol_native_transfer_lamports() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let balance: u64 = 80_574_080;
        let fee: u64 = 5_000;
        let msg = build_sol_transfer_message(&from, &to, balance, &[0u8; 32]).unwrap();

        let adjusted = adjust_sol_native_transfer_lamports(&msg, balance, fee).unwrap();
        let decoded: SolanaMessage = bincode::deserialize(&adjusted).unwrap();
        let new_lamports =
            u64::from_le_bytes(decoded.instructions[0].data[4..12].try_into().unwrap());
        assert_eq!(new_lamports, balance - fee);

        let partial_msg = build_sol_transfer_message(&from, &to, 1_000_000, &[0u8; 32]).unwrap();
        assert!(adjust_sol_native_transfer_lamports(&partial_msg, balance, fee).is_none());
    }

    #[test]
    fn test_build_sol_transfer_message_roundtrip() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_sol_transfer_message(&from, &to, 1_000_000, &[0u8; 32]).unwrap();
        assert!(!msg.is_empty());
        let decoded: SolanaMessage = bincode::deserialize(&msg).unwrap();
        assert_eq!(decoded.account_keys.len(), 3);
    }

    #[test]
    fn test_build_spl_transfer_message_roundtrip() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg =
            build_spl_transfer_message(&owner, &mint, &to, 1_000, &[0u8; 32], &spl_token::id())
                .unwrap();
        assert!(!msg.is_empty());
        let decoded: SolanaMessage = bincode::deserialize(&msg).unwrap();
        assert_eq!(decoded.instructions.len(), 2);
    }

    #[test]
    fn test_known_ata_derivation() {
        let owner: Pubkey = DEVNET_RICH_ADDRESS.parse().unwrap();
        let mint: Pubkey = DEVNET_USDC_MINT.parse().unwrap();
        let ata = get_associated_token_address_with_program_id(&owner, &mint, &spl_token::id());
        assert_eq!(ata.to_string(), DEVNET_USDC_RICH_ATA);
    }

    #[test]
    fn test_solana_history_from_receipt() {
        let keypair = KeyPair::gen_solana().unwrap();
        let message = vec![0xabu8, 0xcd, 0xef];
        let receipt = SolanaTransaction {
            message: message.clone(),
        }
        .sign(&keypair)
        .unwrap();

        let history = SolanaHistoryTransaction::from(receipt.clone());
        assert_eq!(history.message, message);
        assert_eq!(history.signature, receipt.signature);
        assert!(history.fee.is_none());
        assert!(history.slot.is_none());
        assert_eq!(history.tx_id(), receipt.tx_id());
    }

    #[test]
    fn test_solana_history_legacy_json_string() {
        let sig = [7u8; 64];
        let hash = bs58::encode(&sig).into_string();
        let json = format!(
            r#"{{"transactionHash":"{}","fee":"5000","slot":"12345"}}"#,
            hash
        );

        let history = SolanaHistoryTransaction::try_from_legacy_json_str(&json).unwrap();
        assert_eq!(history.signature, sig.to_vec());
        assert!(history.message.is_empty());
        assert_eq!(history.fee, Some(5000));
        assert_eq!(history.slot, Some(12345));
        assert_eq!(history.tx_id(), hash);
    }

    #[test]
    fn test_solana_history_legacy_numeric_fee_slot() {
        let sig = [9u8; 64];
        let hash = bs58::encode(&sig).into_string();
        let value = serde_json::json!({
            "transactionHash": hash,
            "fee": 4200u64,
            "slot": 99u64,
        });

        let history = SolanaHistoryTransaction::try_from_legacy_value(&value).unwrap();
        assert_eq!(history.fee, Some(4200));
        assert_eq!(history.slot, Some(99));
    }

    #[test]
    fn test_solana_history_typed_serde_roundtrip() {
        let history = SolanaHistoryTransaction {
            message: vec![1, 2, 3],
            signature: vec![4; 64],
            fee: Some(5000),
            slot: Some(42),
        };
        let json = serde_json::to_string(&history).unwrap();
        let recovered: SolanaHistoryTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(history, recovered);
    }

    #[test]
    fn test_normalize_bare_legacy_message_passthrough() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_sol_transfer_message(&from, &to, 1_000, &[7u8; 32]).unwrap();
        assert_eq!(normalize_solana_message(&msg).unwrap(), msg);
    }

    #[test]
    fn test_normalize_bare_versioned_message_passthrough() {
        let payer = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let extra = Pubkey::new_unique();
        let ix = system_transfer(&payer, &extra, 500);
        let tables = vec![AddressLookupTableAccount {
            key: table_key,
            addresses: vec![extra],
        }];
        let msg =
            build_versioned_message_from_instructions(&[ix], &payer, &[9u8; 32], &tables).unwrap();
        assert_eq!(msg[0] & 0x80, 0x80, "expected v0 prefix");
        assert_eq!(normalize_solana_message(&msg).unwrap(), msg);
    }

    #[test]
    fn test_normalize_full_legacy_transaction_strips_signatures() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_sol_transfer_message(&from, &to, 1_000, &[7u8; 32]).unwrap();

        // Wire tx: shortvec(1) + one 64-byte placeholder signature + message.
        let mut wire = Vec::with_capacity(1 + 64 + msg.len());
        wire.push(0x01);
        wire.extend_from_slice(&[0u8; 64]);
        wire.extend_from_slice(&msg);

        assert_eq!(normalize_solana_message(&wire).unwrap(), msg);
    }

    #[test]
    fn test_normalize_full_versioned_transaction_strips_signatures() {
        let payer = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let extra = Pubkey::new_unique();
        let ix = system_transfer(&payer, &extra, 500);
        let tables = vec![AddressLookupTableAccount {
            key: table_key,
            addresses: vec![extra],
        }];
        let msg =
            build_versioned_message_from_instructions(&[ix], &payer, &[9u8; 32], &tables).unwrap();

        let mut wire = Vec::with_capacity(1 + 64 + msg.len());
        wire.push(0x01);
        wire.extend_from_slice(&[1u8; 64]);
        wire.extend_from_slice(&msg);

        assert_eq!(normalize_solana_message(&wire).unwrap(), msg);
    }

    #[test]
    fn test_normalize_rejects_garbage() {
        assert!(normalize_solana_message(&[]).is_err());
        assert!(normalize_solana_message(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(normalize_solana_message(&[0x01; 40]).is_err());
    }

    #[test]
    fn test_decode_compact_u16_canonical() {
        assert_eq!(decode_compact_u16(&[0x00]), Some((0, 1)));
        assert_eq!(decode_compact_u16(&[0x01]), Some((1, 1)));
        assert_eq!(decode_compact_u16(&[0x7f]), Some((0x7f, 1)));
        assert_eq!(decode_compact_u16(&[0x80, 0x01]), Some((0x80, 2)));
        assert_eq!(decode_compact_u16(&[0xff, 0x7f]), Some((0x3fff, 2)));
        assert_eq!(decode_compact_u16(&[0x80, 0x80, 0x01]), Some((0x4000, 3)));
        assert_eq!(decode_compact_u16(&[0xff, 0xff, 0x03]), Some((0xffff, 3)));
    }

    #[test]
    fn test_decode_compact_u16_rejects_noncanonical() {
        // Multi-byte aliases of a shorter encoding.
        assert!(decode_compact_u16(&[0x80, 0x00]).is_none());
        assert!(decode_compact_u16(&[0x80, 0x80, 0x00]).is_none());
        assert!(decode_compact_u16(&[0xff, 0x00]).is_none());
        // Continuation on 3rd byte.
        assert!(decode_compact_u16(&[0x80, 0x80, 0x80]).is_none());
        // Overflow past u16 (3rd-byte high data bits).
        assert!(decode_compact_u16(&[0x80, 0x80, 0x04]).is_none());
        // Truncated multi-byte form.
        assert!(decode_compact_u16(&[]).is_none());
        assert!(decode_compact_u16(&[0x80]).is_none());
    }

    #[test]
    fn test_normalize_rejects_noncanonical_shortvec_prefix() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_sol_transfer_message(&from, &to, 1_000, &[7u8; 32]).unwrap();

        // 3-byte alias of sig_count=1 — shortvec rejects; must not strip as if count=1.
        let mut wire = Vec::with_capacity(3 + 64 + msg.len());
        wire.extend_from_slice(&[0x81, 0x80, 0x00]);
        wire.extend_from_slice(&[0u8; 64]);
        wire.extend_from_slice(&msg);
        assert!(normalize_solana_message(&wire).is_err());
    }
}
