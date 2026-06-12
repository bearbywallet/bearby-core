use crate::{keypair::KeyPair, signature::Signature};
use errors::keypair::KeyPairError;
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
}
