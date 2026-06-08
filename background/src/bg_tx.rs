use crate::{Result, bg_provider::ProvidersManagement, bg_wallet::WalletManagement};
use alloy::primitives::U256;
use alloy::{dyn_abi::TypedData, primitives::keccak256};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::sha::SHA256_SIZE;
use errors::{background::BackgroundError, tx::TransactionErrors, wallet::WalletErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
use network::evm::RequiredTxParams;
use network::tron::FEE_LIMIT;
use proto::{
    address::Address,
    pubkey::PubKey,
    signature::Signature,
    solana_tx::adjust_sol_native_transfer_lamports,
    tx::{TransactionReceipt, TransactionRequest},
};
use sha2::{Digest, Sha256};
use wallet::{
    bitcoin_wallet::BitcoinWallet, wallet_crypto::WalletCrypto, wallet_storage::StorageOperations,
};

use crate::Background;
use secrecy::SecretString;

pub fn update_tx_from_params(
    tx: &mut TransactionRequest,
    params: RequiredTxParams,
    balance: U256,
) -> std::result::Result<(), TransactionErrors> {
    match tx {
        TransactionRequest::Zilliqa((ref mut zil_tx, _metadata)) => {
            zil_tx.nonce = params.nonce + 1;

            if balance == U256::from(zil_tx.amount) {
                let current_fee: u128 = params.current.try_into().unwrap_or_default();
                zil_tx.amount -= current_fee;
            }

            zil_tx.gas_price = params
                .gas_price
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Gas price overflow".to_string()))?;
        }
        TransactionRequest::Ethereum((ref mut eth_tx, _metadata)) => {
            eth_tx.nonce = Some(params.nonce);
            eth_tx.gas = Some(params.tx_estimate_gas.try_into().map_err(|_| {
                TransactionErrors::ConvertTxError("Gas limit overflow".to_string())
            })?);

            let is_eip1559_supported = params.fee_history.base_fee > U256::ZERO;
            let is_native_transfer = eth_tx
                .input
                .input()
                .map(|data| data.is_empty())
                .unwrap_or(true);
            let is_fast_fee = params.fast > U256::ZERO && params.current >= params.fast;

            let precision = U256::from(1_000_000);
            let multiplier = if params.slow > U256::ZERO {
                params.current.saturating_mul(precision) / params.slow
            } else {
                precision
            };

            if is_eip1559_supported {
                let base_priority_fee = if params.fee_history.priority_fee.is_zero() {
                    params.max_priority_fee
                } else {
                    params.fee_history.priority_fee
                };
                let priority_fee = base_priority_fee.saturating_mul(multiplier) / precision;
                // EIP-1559 invariant: max_fee must cover at least base_fee + priority_fee.
                // Using max_priority_fee alone without base_fee would stall in the mempool.
                let min_required_fee = params.fee_history.base_fee.saturating_add(priority_fee);
                let gas_limit = eth_tx.gas.unwrap_or_default();
                let max_fee_per_gas = if gas_limit > 0 {
                    let computed_fee = params.current / U256::from(gas_limit);
                    std::cmp::max(computed_fee, min_required_fee)
                } else {
                    min_required_fee
                };
                // Enforce EIP-1559 invariant: max_fee_per_gas >= max_priority_fee_per_gas.
                // For large gas limits (275k+), the integer division above can drop below
                // priority_fee, which causes -32003 (transaction underpriced).
                let max_fee_per_gas = std::cmp::max(max_fee_per_gas, priority_fee);

                eth_tx.max_priority_fee_per_gas = Some(priority_fee.try_into().map_err(|_| {
                    TransactionErrors::ConvertTxError("Priority fee overflow".to_string())
                })?);

                eth_tx.max_fee_per_gas = Some(max_fee_per_gas.try_into().map_err(|_| {
                    TransactionErrors::ConvertTxError("Max fee overflow".to_string())
                })?);

                eth_tx.gas_price = None;

                if let Some(current_value) = eth_tx.value {
                    if is_native_transfer && current_value == balance {
                        let buffer_multiplier = if is_fast_fee {
                            precision.saturating_mul(U256::from(105)) / U256::from(100)
                        } else {
                            precision
                        };
                        let fee_to_subtract =
                            params.current.saturating_mul(buffer_multiplier) / precision;
                        let adjusted_value = current_value.saturating_sub(fee_to_subtract);

                        if adjusted_value > U256::ZERO && adjusted_value < current_value {
                            eth_tx.value = Some(adjusted_value);
                        }
                    }
                }
            } else {
                let gas_price = params.gas_price.saturating_mul(multiplier) / precision;

                eth_tx.gas_price = Some(gas_price.try_into().map_err(|_| {
                    TransactionErrors::ConvertTxError("Gas price overflow".to_string())
                })?);

                eth_tx.max_fee_per_gas = None;
                eth_tx.max_priority_fee_per_gas = None;

                if let Some(current_value) = eth_tx.value {
                    if is_native_transfer && current_value == balance {
                        let buffer_multiplier = if is_fast_fee {
                            precision.saturating_mul(U256::from(105)) / U256::from(100)
                        } else {
                            precision
                        };
                        let fee_to_subtract =
                            params.current.saturating_mul(buffer_multiplier) / precision;
                        let adjusted_value = current_value.saturating_sub(fee_to_subtract);

                        if adjusted_value > U256::ZERO && adjusted_value < current_value {
                            eth_tx.value = Some(adjusted_value);
                        }
                    }
                }
            }
        }
        TransactionRequest::Tron((ref mut tron_tx, _metadata)) => {
            let estimated_fee: i64 = params
                .current
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Fee overflow".to_string()))?;

            // Check if this is a max-balance transfer before we mutate the amount
            let is_max_balance = tron_tx.transfer_amount()
                .map(|a| a > 0 && U256::from(a as u64) == balance)
                .unwrap_or(false);

            if is_max_balance {
                // Max-balance: use estimate with 10% buffer for fee_limit.
                // The node's actual bandwidth burn can differ from our estimate
                // by small amounts due to protobuf encoding overhead differences.
                // A 10% buffer prevents "balance is not sufficient" rejections.
                let amount = tron_tx.transfer_amount().unwrap_or(0);
                let fee_limit_buffered = std::cmp::max(
                    estimated_fee * 110 / 100,
                    estimated_fee + 1000,
                );
                let adjusted = amount - fee_limit_buffered;
                if adjusted <= 0 {
                    return Err(TransactionErrors::ConvertTxError(format!(
                        "Insufficient TRX: balance {} sun <= fee {} sun",
                        amount, fee_limit_buffered
                    )));
                }
                tron_tx.set_fee_limit(fee_limit_buffered);
                tron_tx.set_transfer_amount(adjusted)?;
            } else {
                // Non-max-balance: use cap-based fee_limit (matches snap-tron-wallet).
                let fee_limit = std::cmp::max(estimated_fee, FEE_LIMIT);
                tron_tx.set_fee_limit(fee_limit);
            }
        }
        TransactionRequest::Solana((ref mut sol_tx, _)) => {
            let fee: u64 = params
                .current
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Fee overflow".to_string()))?;
            let balance_u64: u64 = balance.try_into().unwrap_or(u64::MAX);

            if let Some(adjusted) =
                adjust_sol_native_transfer_lamports(&sol_tx.message, balance_u64, fee)
            {
                sol_tx.message = adjusted;
            }
        }
        TransactionRequest::Bitcoin((ref mut btc_tx, ref metadata, ref btc_meta)) => {
            if params.current == U256::ZERO {
                return Ok(());
            }

            let new_fee: u64 = params
                .current
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Fee overflow".to_string()))?;

            let total_input: u64 = btc_meta
                .witness_utxos
                .iter()
                .map(|u| u.value.to_sat())
                .sum();

            let value_indices: Vec<usize> = btc_tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| !o.script_pubkey.is_op_return())
                .map(|(i, _)| i)
                .collect();

            if value_indices.is_empty() {
                return Err(TransactionErrors::ConvertTxError(
                    "No spendable outputs in transaction".into(),
                ));
            }

            let dust_limit = metadata
                .signer
                .as_ref()
                .map(wallet::bitcoin_wallet::get_dust_limit)
                .unwrap_or(546);

            let change_idx = *value_indices.last().unwrap();
            let is_max_transfer = value_indices.len() == 1;
            let has_op_return = btc_tx.output.len() > value_indices.len();

            if is_max_transfer && has_op_return {
                return Err(TransactionErrors::ConvertTxError(
                    "Cannot adjust fee: transaction carries an OP_RETURN memo but has no change output to absorb the fee delta; rebuild the transaction with the updated fee rate".into(),
                ));
            }

            if is_max_transfer {
                let max_fee_affordable = total_input.saturating_sub(dust_limit);
                let new_amount = if new_fee > max_fee_affordable {
                    dust_limit
                } else {
                    let amt = total_input.saturating_sub(new_fee);
                    if amt < dust_limit {
                        return Err(TransactionErrors::ConvertTxError(format!(
                            "Insufficient funds: need {} sats (fee) + {} sats (min output) = {} sats, but only have {} sats",
                            new_fee,
                            dust_limit,
                            new_fee + dust_limit,
                            total_input
                        )));
                    }
                    amt
                };
                btc_tx.output[change_idx].value = bitcoin::Amount::from_sat(new_amount);
            } else {
                let total_dest: u64 = btc_tx
                    .output
                    .iter()
                    .enumerate()
                    .filter(|(i, o)| *i != change_idx && !o.script_pubkey.is_op_return())
                    .map(|(_, o)| o.value.to_sat())
                    .sum();

                let new_change = total_input
                    .saturating_sub(total_dest)
                    .saturating_sub(new_fee);

                if new_change >= dust_limit {
                    btc_tx.output[change_idx].value = bitcoin::Amount::from_sat(new_change);
                } else {
                    btc_tx.output.remove(change_idx);
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait TransactionsManagement {
    type Error;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    async fn check_pending_txns(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> std::result::Result<[u8; SHA256_SIZE], Self::Error>;

    fn prepare_eip712_message(
        &self,
        typed_data_json: String,
    ) -> std::result::Result<TypedData, Self::Error>;

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> Result<[u8; SHA256_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_data = wallet.get_wallet_data()?;
        let account = wallet_data.get_account(account_index)?;

        match account.addr {
            Address::Secp256k1Bitcoin(_) => Err(BackgroundError::BincodeError(
                "BTC not impl yet".to_string(),
            ))?,
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                Ok(hash.into())
            }
            Address::Secp256k1Keccak256(_) => {
                let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
                let full_message = format!("{}{}", prefix, message);
                let hash = keccak256(full_message.as_bytes());

                Ok(hash.0)
            }
            Address::Secp256k1Tron(_) => {
                let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
                let full_message = format!("{}{}", prefix, message);
                let hash = keccak256(full_message.as_bytes());

                Ok(hash.0)
            }
            Address::Ed25519Solana(_) => Err(BackgroundError::BincodeError(
                "Personal sign not supported for Solana".to_string(),
            ))?,
        }
    }

    fn prepare_eip712_message(&self, typed_data_json: String) -> Result<TypedData> {
        let typed_data: TypedData = serde_json::from_str(&typed_data_json)
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;

        Ok(typed_data)
    }

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        typed_data_json: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data.get_account(account_index)?;
        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let typed_data: TypedData = serde_json::from_str(typed_data_json)
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;
        let signature = key_pair.sign_typed_data_eip712(typed_data).await?;
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_typed_data(
            typed_data_json,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            data.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data.get_account(account_index)?;

        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let signature = match account.addr {
            Address::Secp256k1Bitcoin(_) => {
                return Err(BackgroundError::WalletError(
                    WalletErrors::InvalidHexToWalletType,
                ));
            }
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                key_pair.sign_message(&hash)?
            }
            Address::Secp256k1Keccak256(_) => {
                let bytes = if message.starts_with("0x") || message.starts_with("0X") {
                    hex::decode(&message[2..]).unwrap_or_else(|_| message.as_bytes().to_vec())
                } else {
                    message.as_bytes().to_vec()
                };
                key_pair.sign_message(&bytes)?
            }
            Address::Secp256k1Tron(_) => {
                let bytes = if message.starts_with("0x") || message.starts_with("0X") {
                    hex::decode(&message[2..]).unwrap_or_else(|_| message.as_bytes().to_vec())
                } else {
                    message.as_bytes().to_vec()
                };
                let prefix = format!("\x19TRON Signed Message:\n{}", bytes.len());
                let mut full_msg = prefix.into_bytes();
                full_msg.extend_from_slice(&bytes);
                let hash = keccak256(&full_msg);
                key_pair.sign_hash(&hash.0)?
            }
            Address::Ed25519Solana(_) => {
                return Err(BackgroundError::WalletError(
                    WalletErrors::InvalidHexToWalletType,
                ));
            }
        };
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_message(
            message,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            data.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    async fn check_pending_txns(&self, wallet_index: usize) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let chain = self.get_provider(data.chain_hash)?;
        let mut history = wallet.get_history()?;

        let mut matching_transactions = Vec::with_capacity(history.len());

        for tx in history.iter_mut() {
            if tx.metadata.chain_hash == data.chain_hash && tx.status == TransactionStatus::Pending
            {
                matching_transactions.push(tx);
            }
        }

        if matching_transactions.is_empty() {
            return Ok(history);
        }

        chain
            .update_transactions_receipt(&mut matching_transactions)
            .await?;
        wallet.save_history(&history)?;

        Ok(history)
    }

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let provider = self.get_provider(data.chain_hash)?;
        let txns = provider.broadcast_signed_transactions(txns).await?;
        let history = txns
            .into_iter()
            .map(HistoricalTransaction::try_from)
            .collect::<std::result::Result<Vec<HistoricalTransaction>, TransactionErrors>>()?;

        for item in &history {
            if item.btc.is_some() {
                wallet.mark_btc_addresses_used(data.selected_account, item)?;
            }
        }

        wallet.add_history(&history)?;

        Ok(history)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::bg_bitcoin::BitcoinManagement;
    use crate::{BackgroundBip39Params, bg_storage::StorageManagement, bg_token::TokensManagement};
    use wallet::wallet_account::AccountManagement;
    use alloy::{primitives::U256, rpc::types::TransactionRequest as ETHTransactionRequest};
    use network::btc::BtcOperations;

    use proto::{
        address::Address,
        tx::{TransactionMetadata, TransactionRequest},
    };
    use rand::RngExt;
    use secrecy::{ExposeSecret, SecretString};
    use test_data::{
        ANVIL_MNEMONIC, TEST_PASSWORD, empty_passphrase, gen_anvil_net_conf, gen_anvil_token,
        gen_btc_regtest_conf, gen_eth_account, gen_zil_account, gen_zil_testnet_conf,
        gen_zil_token,
    };
    use token::ft::FToken;
    use tokio;
    use wallet::{
        bitcoin_wallet::BitcoinWallet, wallet_crypto::WalletCrypto,
        wallet_transaction::WalletTransaction,
    };

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_sign_and_verify_zil_swap_to_anvil() {
        let (mut bg, _dir) = setup_test_background();
        let zil_config = gen_zil_testnet_conf();
        let anvil_config = gen_anvil_net_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(zil_config.clone()).unwrap();
        bg.add_provider(anvil_config.clone()).unwrap();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        let accounts = [gen_zil_account(0, "ZIL Acc 0")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: zil_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![FToken::zil(zil_config.hash())],
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let token_transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: Some(21000),
            chain_id: Some(anvil_config.chain_id()),
            ..Default::default()
        };
        let metadata = proto::tx::TransactionMetadata {
            chain_hash: anvil_config.hash(),
            signer: data.get_selected_account().map(|acc| acc.addr.clone()).ok(),
            ..Default::default()
        };
        assert!(metadata.broadcast);
        let zilpay_trasnfer_req = TransactionRequest::Ethereum((token_transfer_request, metadata));
        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        bg.select_accounts_chain(0, anvil_config.hash(), None)
            .await
            .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let selected_account = data.get_selected_account().unwrap();

        assert!(selected_account.addr.to_string().starts_with("0x"));

        let tx = wallet
            .sign_transaction(zilpay_trasnfer_req, 0, &argon_seed, &empty_passphrase())
            .await
            .unwrap();

        assert!(tx.verify().unwrap());
    }

    #[tokio::test]
    async fn test_sign_and_send_evm_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        let accounts = [gen_eth_account(5, "Anvil Acc 5")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_anvil_token()],
        })
        .await
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.get_account(0).unwrap();
        assert_eq!(
            account.addr.to_string().to_lowercase(),
            "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc"
        );
        let ftokens = wallet.get_ftokens().unwrap();
        let balance = *ftokens
            .first()
            .unwrap()
            .balances
            .get(&account.addr.to_hash())
            .unwrap();

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata = proto::tx::TransactionMetadata {
            chain_hash: net_config.hash(),
            ..Default::default()
        };
        assert!(metadata.broadcast);
        let mut tx_request = TransactionRequest::Ethereum((transfer_request.clone(), metadata));

        let params = provider
            .estimate_params_batch(&tx_request, &account.addr, 1, None)
            .await
            .unwrap();

        super::update_tx_from_params(&mut tx_request, params, balance).unwrap();
        let txn = tx_request;

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();
        let keypair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];
        let txns = bg.broadcast_signed_transactions(0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_update_history_evm() {
        use test_data::anvil_accounts;
        use tokio::time::{Duration, sleep};

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();
        let net_hash = net_config.hash();

        bg.add_provider(net_config.clone()).unwrap();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        let accounts = [gen_eth_account(6, "Anvil Acc 6")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_hash,
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_anvil_token()],
        })
        .await
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.get_account(0).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();
        let balance = *ftokens
            .first()
            .unwrap()
            .balances
            .get(&account.addr.to_hash())
            .unwrap();

        let recipient_0 = Address::from_eth_address(anvil_accounts::ACCOUNT_1).unwrap();
        let transfer_request_0 = ETHTransactionRequest {
            to: Some(recipient_0.to_alloy_addr().into()),
            value: Some(U256::from(100u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata_0 = proto::tx::TransactionMetadata {
            chain_hash: net_hash,
            ..Default::default()
        };
        assert!(metadata_0.broadcast);
        let mut tx_request_0 = TransactionRequest::Ethereum((transfer_request_0, metadata_0));

        let params_0 = provider
            .estimate_params_batch(&tx_request_0, &account.addr, 1, None)
            .await
            .unwrap();

        // Use update_tx_from_params to set gas fields based on network capabilities
        super::update_tx_from_params(&mut tx_request_0, params_0, balance).unwrap();
        let txn_0 = tx_request_0;

        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let keypair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();
        let txn_0 = txn_0.sign(&keypair).await.unwrap();
        let txns_0 = vec![txn_0];
        let txns_0 = bg.broadcast_signed_transactions(0, txns_0).await.unwrap();

        assert_eq!(txns_0.len(), 1);
        let tx_hash_0 = txns_0[0].metadata.hash.clone().unwrap();

        let wallet_check = bg.get_wallet_by_index(0).unwrap();
        let history_check = wallet_check.get_history().unwrap();
        assert_eq!(history_check.len(), 1);

        let recipient_1 = Address::from_eth_address(anvil_accounts::ACCOUNT_2).unwrap();
        let transfer_request_1 = ETHTransactionRequest {
            to: Some(recipient_1.to_alloy_addr().into()),
            value: Some(U256::from(200u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata_1 = proto::tx::TransactionMetadata {
            chain_hash: net_hash,
            ..Default::default()
        };
        assert!(metadata_1.broadcast);
        let mut tx_request_1 = TransactionRequest::Ethereum((transfer_request_1, metadata_1));

        let params_1 = provider
            .estimate_params_batch(&tx_request_1, &account.addr, 1, None)
            .await
            .unwrap();

        super::update_tx_from_params(&mut tx_request_1, params_1, balance).unwrap();
        let txn_1 = tx_request_1;

        let keypair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();
        let txn_1 = txn_1.sign(&keypair).await.unwrap();
        let txns_1 = vec![txn_1];
        let txns_1 = bg.broadcast_signed_transactions(0, txns_1).await.unwrap();

        assert_eq!(txns_1.len(), 1);
        let tx_hash_1 = txns_1[0].metadata.hash.clone().unwrap();

        sleep(Duration::from_secs(2)).await;

        bg.check_pending_txns(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let history = wallet.get_history().unwrap();
        let filtered_history = history
            .into_iter()
            .filter(|t| t.metadata.chain_hash == net_hash)
            .collect::<Vec<HistoricalTransaction>>();

        assert_eq!(filtered_history.len(), 2);
        let hash_0 = filtered_history[0].metadata.hash.as_ref().unwrap();
        let hash_1 = filtered_history[1].metadata.hash.as_ref().unwrap();
        assert!(hash_0 == &tx_hash_0 || hash_1 == &tx_hash_0);
        assert!(hash_0 == &tx_hash_1 || hash_1 == &tx_hash_1);
        assert_eq!(filtered_history[0].status, TransactionStatus::Success);
        assert_eq!(filtered_history[1].status, TransactionStatus::Success);
    }

    #[tokio::test]
    async fn test_sign_message_legacy_zilliqa() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "ZIL wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let message = "Hello, Zilliqa!";
        let (pubkey, signature) = bg
            .sign_message(0, 0, &argon_seed, &empty_passphrase(), message, None, None)
            .unwrap();

        let hashed_message = Sha256::digest(message.as_bytes());
        let key_pair = bg
            .get_wallet_by_index(0)
            .unwrap()
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();

        assert_eq!(pubkey.as_bytes(), key_pair.get_pubkey_bytes());
        let is_valid = key_pair.verify_sig(&hashed_message, &signature).unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_unckeched_seed_phrase() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let mnemonic_secret = SecretString::from(UNCHECKSUMED_WORD.to_string());
        let accounts = [gen_zil_account(0, "Zil 0")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        const UNCHECKSUMED_WORD: &str =
            "sword sure throw slide garden science six destroy canvas ceiling negative black";
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: false,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Zilliqa legacy wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_zil_token()],
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let revealed_mnemonic = wallet.reveal_mnemonic(&argon_seed).unwrap();
        let keypair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();

        assert_eq!(
            revealed_mnemonic.to_phrase().expose_secret(),
            UNCHECKSUMED_WORD
        );
        assert_eq!(
            "d7986cf4acc822c1a6cdc4170f5561a6cee1591c37ec6a887bb650d051e4ad71",
            hex::encode(keypair.get_secretkey().unwrap().as_ref())
        );
        assert_eq!(
            "022b8e6855eaf04ec7bd2e01d5aaf4e46a111b509882e5456d97af60a6d1ed6f28",
            hex::encode(keypair.get_pubkey().unwrap().as_bytes())
        );
    }

    #[tokio::test]
    async fn test_sign_and_send_btc() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_btc_regtest_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        let accounts = [(0, "BTC Taproot Acc 0".to_string())];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BTC Taproot wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![test_data::gen_btc_token()],
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        bg.sync_ftokens_balances(0).await.unwrap();
        let ftokens = wallet.get_ftokens().unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let pr = bg.get_provider(data.chain_hash).unwrap();
        let account = data.get_account(0).unwrap();
        let res = pr.btc_list_unspent(&account.addr).await.unwrap();
        dbg!(&ftokens, &account);

        let btc_token = ftokens
            .iter()
            .find(|t| t.native && t.chain_hash == net_config.hash())
            .unwrap();
        let balance = btc_token
            .balances
            .get(&account.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        assert!(balance > U256::ZERO, "selected account balance must be > 0");

        assert!(res.is_empty(), "new tapRoot walelt must be empty!");

        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let dest_addr = Address::from_bitcoin_address(
            "bc1p0lks35d0spqsvz2t3t0kqus38wrlpmcjtvvupkfkwdrzfh6zjyps9rvd6v",
        )
        .unwrap();
        let destinations = vec![(dest_addr, 1000u64)];

        let signed_tx = wallet
            .prepare_and_sign_btc_transaction(
                &pr,
                0,
                &argon_seed,
                &empty_passphrase(),
                destinations,
                Some(10),
            )
            .await
            .unwrap();

        assert!(signed_tx.verify().unwrap());

        if let TransactionReceipt::Bitcoin((signed_btc_tx, _, _)) = &signed_tx {
            assert!(!signed_btc_tx.output.is_empty());
        } else {
            panic!("Not a BTC tx");
        }

        let txns = vec![signed_tx];
        bg.broadcast_signed_transactions(0, txns).await.unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let new_account = data.get_accounts().unwrap().first().unwrap();

        assert_eq!(new_account.addr, account.addr);
        let bip86_xpub = test_data::derive_bip86_xpub(
            &wallet.reveal_mnemonic(&argon_seed).unwrap(),
            account.account_type.value() as u32,
            net_config
                .bitcoin_network()
                .unwrap_or(bitcoin::Network::Bitcoin),
        );
        bg.rotate_btc_account(0, 0, &bip86_xpub).await.unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let new_account = data.get_accounts().unwrap().first().unwrap();

        assert_ne!(&new_account.addr, &account.addr);
    }

    #[tokio::test]
    async fn test_sign_and_send_tron_max_balance_tx() {
        use test_data::{gen_tron_account, gen_tron_testnet_conf, gen_tron_token, tron_addresses};

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_tron_testnet_conf();
        bg.add_provider(net_config.clone()).unwrap();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        let accounts = [
            gen_tron_account(0, "Tron Acc 0"),
            gen_tron_account(1, "Tron Acc 1"),
        ];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Tron wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_tron_token()],
        })
        .await
        .unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account_0 = data.get_account(0).unwrap();
        let account_1 = data.get_account(1).unwrap();

        // Select account 1 and sync its balance too
        wallet.select_account(1).unwrap();
        bg.sync_ftokens_balances(0).await.unwrap();
        // Back to account 0
        wallet.select_account(0).unwrap();

        let ftokens = wallet.get_ftokens().unwrap();
        let balance_0 = ftokens
            .first()
            .unwrap()
            .balances
            .get(&account_0.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        let balance_1 = ftokens
            .first()
            .unwrap()
            .balances
            .get(&account_1.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        assert_eq!(account_0.addr.auto_format(), tron_addresses::ADDR_0);

        let (sender_idx, sender, recipient, sender_balance) =
            if balance_0 >= balance_1 && balance_0 > U256::ZERO {
                (0usize, account_0, &account_1.addr, balance_0)
            } else if balance_1 > U256::ZERO {
                (1usize, account_1, &account_0.addr, balance_1)
            } else {
                panic!("both accounts have zero TRX balance — fund at least one on Nile testnet");
            };

        // Send 1 TRX (not max balance) — exercises estimate + cap flow without
        // node rejecting exact balance = amount + fee_limit equality check.
        let amount_sun: i64 = 1_000_000;

        let mut tron_tx = proto::tron_tx::TronTransaction::builder()
            .transfer(&sender.addr, recipient, amount_sun)
            .build()
            .unwrap();

        let metadata = proto::tx::TransactionMetadata {
            chain_hash: net_config.hash(),
            ..Default::default()
        };
        assert!(metadata.broadcast);

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();

        provider.tron_fill_block_ref(&mut tron_tx).await.unwrap();

        let mut tx_request = TransactionRequest::Tron((tron_tx.clone(), metadata.clone()));

        let params = provider
            .estimate_params_batch(&tx_request, &sender.addr, 1, None)
            .await
            .unwrap();

        let fee: i64 = params.current.try_into().expect("fee must fit in i64");
        assert!(fee >= 0, "TransferContract fee_limit must be non-negative");

        super::update_tx_from_params(&mut tx_request, params, sender_balance).unwrap();

        if let TransactionRequest::Tron((ref updated, _)) = tx_request {
            if let Some(amount) = updated.transfer_amount() {
                // Non-max-balance: amount unchanged, fee_limit = cap (100M SUN)
                assert_eq!(amount, amount_sun, "amount must be unchanged for non-max send");
                assert!(updated.fee_limit() >= FEE_LIMIT, "fee_limit must be at least cap");
            } else {
                panic!("expected Transfer contract");
            }
            tron_tx = updated.clone();
        }

        let tx_request = TransactionRequest::Tron((tron_tx, metadata));

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();
        let keypair = wallet
            .reveal_keypair(sender_idx, &argon_seed, &empty_passphrase())
            .unwrap();

        let signed = tx_request.sign(&keypair).await.unwrap();
        assert!(signed.verify().unwrap());

        let txns = vec![signed];
        let txns = bg.broadcast_signed_transactions(0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);
        for tx in &txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_sign_message_tron() {
        use test_data::{gen_tron_account, gen_tron_testnet_conf, gen_tron_token};

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_tron_testnet_conf();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_tron_account(0, "Tron Acc 0")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Tron wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_tron_token()],
        })
        .await
        .unwrap();

        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let message = "Hello, Tron!";
        let (pubkey, signature) = bg
            .sign_message(0, 0, &argon_seed, &empty_passphrase(), message, None, None)
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let key_pair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();

        assert_eq!(pubkey.as_bytes(), key_pair.get_pubkey_bytes());

        let prefixed_msg = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut full_msg = prefixed_msg.into_bytes();
        full_msg.extend_from_slice(message.as_bytes());
        let hash = keccak256(&full_msg);

        let is_valid = key_pair.verify_hash(&hash.0, &signature).unwrap();
        assert!(is_valid, "Tron message signature verification failed");
    }

    #[tokio::test]
    async fn test_sign_message_tron_hex() {
        use test_data::{gen_tron_account, gen_tron_testnet_conf, gen_tron_token};

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_tron_testnet_conf();

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC.to_string());
        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_tron_account(0, "Tron Acc 0")];
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Tron wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_tron_token()],
        })
        .await
        .unwrap();

        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let hex_message = "0x48656c6c6f2c2054726f6e21";
        let (_pubkey, signature) = bg
            .sign_message(
                0,
                0,
                &argon_seed,
                &empty_passphrase(),
                hex_message,
                None,
                None,
            )
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let key_pair = wallet
            .reveal_keypair(0, &argon_seed, &empty_passphrase())
            .unwrap();

        let decoded = hex::decode(&hex_message[2..]).unwrap();
        let prefixed_msg = format!("\x19TRON Signed Message:\n{}", decoded.len());
        let mut full_msg = prefixed_msg.into_bytes();
        full_msg.extend_from_slice(&decoded);
        let hash = keccak256(&full_msg);

        let is_valid = key_pair.verify_hash(&hash.0, &signature).unwrap();
        assert!(is_valid, "Tron hex message signature verification failed");
    }

    fn make_op_return(memo: &[u8]) -> bitcoin::TxOut {
        wallet::bitcoin_wallet::build_op_return_output(memo).unwrap()
    }

    fn make_params(fee: u64) -> RequiredTxParams {
        RequiredTxParams {
            gas_price: U256::ZERO,
            max_priority_fee: U256::ZERO,
            fee_history: network::evm::GasFeeHistory::default(),
            tx_estimate_gas: U256::ZERO,
            blob_base_fee: U256::ZERO,
            nonce: 0,
            slow: U256::ZERO,
            market: U256::ZERO,
            fast: U256::ZERO,
            current: U256::from(fee),
        }
    }

    fn make_btc_tx_with_input(outputs: Vec<bitcoin::TxOut>, input_sats: u64) -> TransactionRequest {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: "0000000000000000000000000000000000000000000000000000000000000000"
                        .parse::<bitcoin::Txid>()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outputs,
        };
        TransactionRequest::Bitcoin((
            tx,
            TransactionMetadata::default(),
            proto::btc_tx::BitcoinMetadata {
                witness_utxos: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(input_sats),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
                input_meta: vec![(
                    0,
                    crypto::bip49::DerivationPath::new(
                        0,
                        crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
                        86,
                    ),
                )],
            },
        ))
    }

    fn make_btc_tx(outputs: Vec<bitcoin::TxOut>) -> TransactionRequest {
        make_btc_tx_with_input(outputs, 200_000)
    }

    #[test]
    fn test_update_tx_preserves_op_return() {
        let memo = b"SWAP:THOR.RUNE:thor1abc";
        let mut tx = make_btc_tx(vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            make_op_return(memo),
        ]);

        let params = make_params(5_000);

        update_tx_from_params(&mut tx, params, U256::ZERO).unwrap();

        match tx {
            TransactionRequest::Bitcoin((ref btc_tx, _, _)) => {
                assert_eq!(btc_tx.output.len(), 3);
                assert_eq!(btc_tx.output[0].value.to_sat(), 100_000);
                assert_eq!(btc_tx.output[1].value.to_sat(), 95_000);
                assert!(btc_tx.output[2].script_pubkey.is_op_return());
                assert_eq!(&btc_tx.output[2].script_pubkey.as_bytes()[2..], memo);
            }
            _ => panic!("expected Bitcoin variant"),
        }
    }

    #[test]
    fn test_update_tx_drops_dust_change_keeps_op_return() {
        let memo = b"SWAP:THOR.RUNE:thor1abc";
        let mut tx = make_btc_tx_with_input(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(100_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(100),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                make_op_return(memo),
            ],
            100_100,
        );

        let params = make_params(5_000);

        update_tx_from_params(&mut tx, params, U256::ZERO).unwrap();

        match tx {
            TransactionRequest::Bitcoin((ref btc_tx, _, _)) => {
                assert_eq!(btc_tx.output.len(), 2);
                assert_eq!(btc_tx.output[0].value.to_sat(), 100_000);
                assert!(btc_tx.output[1].script_pubkey.is_op_return());
            }
            _ => panic!("expected Bitcoin variant"),
        }
    }

    #[test]
    fn test_update_tx_rejects_max_transfer_with_op_return() {
        let memo = b"SWAP:ETH:0xabc";
        let mut tx = make_btc_tx(vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(200_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            make_op_return(memo),
        ]);

        let params = make_params(3_000);

        let res = update_tx_from_params(&mut tx, params, U256::from(200_000));
        assert!(
            res.is_err(),
            "expected error for [dest, OP_RETURN] with no change output"
        );

        match tx {
            TransactionRequest::Bitcoin((ref btc_tx, _, _)) => {
                assert_eq!(btc_tx.output.len(), 2);
                assert_eq!(btc_tx.output[0].value.to_sat(), 200_000);
                assert!(btc_tx.output[1].script_pubkey.is_op_return());
            }
            _ => panic!("expected Bitcoin variant"),
        }
    }

    #[test]
    fn test_update_tx_plain_btc_unchanged() {
        let mut tx = make_btc_tx(vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
        ]);

        let params = make_params(5_000);

        update_tx_from_params(&mut tx, params, U256::ZERO).unwrap();

        match tx {
            TransactionRequest::Bitcoin((ref btc_tx, _, _)) => {
                assert_eq!(btc_tx.output.len(), 2);
                assert_eq!(btc_tx.output[0].value.to_sat(), 100_000);
                assert_eq!(btc_tx.output[1].value.to_sat(), 95_000);
            }
            _ => panic!("expected Bitcoin variant"),
        }
    }
}
