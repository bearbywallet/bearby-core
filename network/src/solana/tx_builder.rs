use bincode;
use solana_hash::Hash;
use solana_message::legacy::Message;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction::transfer as system_transfer;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_token::instruction::transfer as token_transfer;

pub fn build_sol_transfer_message(
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, String> {
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

    if msg.instructions.len() != 1 {
        return None;
    }

    let ix = &msg.instructions[0];
    let program_key = msg.account_keys.get(ix.program_id_index as usize)?;

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

    let from = msg.account_keys.get(*ix.accounts.first()? as usize)?;
    let to = msg.account_keys.get(*ix.accounts.get(1)? as usize)?;
    let blockhash: [u8; 32] = msg.recent_blockhash.to_bytes();

    build_sol_transfer_message(from, to, new_lamports, &blockhash).ok()
}

pub fn build_spl_transfer_message(
    owner: &Pubkey,
    mint: &Pubkey,
    to_wallet: &Pubkey,
    amount: u64,
    blockhash: &[u8; 32],
    token_program: &Pubkey,
) -> Result<Vec<u8>, String> {
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
    use solana_message::legacy::Message as SolanaMessage;

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    const DEVNET_USDC_RICH_ATA: &str = "6r6KJLTwFLnJ2czodnEQeiWfAEDw2nkCDsu4AwptU3fm";

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
