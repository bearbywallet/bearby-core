use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use alloy::primitives::U256;
use alloy::{dyn_abi::TypedData, primitives::keccak256};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::sha::SHA256_SIZE;
use errors::{background::BackgroundError, tx::TransactionErrors, wallet::WalletErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
use network::{evm::RequiredTxParams, solana::tx_builder::adjust_sol_native_transfer_lamports};
use proto::{
    address::Address,
    pubkey::PubKey,
    signature::Signature,
    tx::{TransactionReceipt, TransactionRequest},
};
use sha2::{Digest, Sha256};
use wallet::{
    bitcoin_wallet::BitcoinWallet, wallet_crypto::WalletCrypto, wallet_storage::StorageOperations,
};

use crate::Background;

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
                let max_fee_per_gas = if eth_tx.gas.unwrap_or_default() > 0 {
                    params.current / U256::from(eth_tx.gas.unwrap_or_default())
                } else {
                    params.fee_history.base_fee.saturating_add(priority_fee)
                };

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
            let fee: i64 = params
                .current
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Fee overflow".to_string()))?;
            let existing_fee = tron_tx.fee_limit();
            tron_tx.set_fee_limit(if existing_fee > 0 {
                existing_fee.max(fee)
            } else {
                fee
            });

            if let Some(amount) = tron_tx.transfer_amount() {
                if amount > 0 && U256::from(amount as u64) == balance {
                    let adjusted = amount - fee;
                    if adjusted <= 0 {
                        return Err(TransactionErrors::ConvertTxError(format!(
                            "Insufficient TRX: balance {} sun <= fee {} sun",
                            amount, fee
                        )));
                    }
                    tron_tx.set_transfer_amount(adjusted)?;
                }
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
        TransactionRequest::Bitcoin((ref mut btc_tx, ref metadata)) => {
            if params.current == U256::ZERO {
                return Ok(());
            }

            let new_fee: u64 = params
                .current
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Fee overflow".to_string()))?;

            let total_input: u64 = metadata
                .btc_witness_utxos
                .as_ref()
                .ok_or(TransactionErrors::ConvertTxError(
                    "Missing witness UTXOs".to_string(),
                ))?
                .iter()
                .map(|u| u.value.to_sat())
                .sum();

            let output_count = btc_tx.output.len();
            if output_count == 0 {
                Err(TransactionErrors::ConvertTxError(
                    "No outputs in transaction".to_string(),
                ))?
            }

            let is_max_transfer = output_count == 1;

            if is_max_transfer {
                let dust_limit = metadata
                    .signer
                    .as_ref()
                    .map(wallet::bitcoin_wallet::get_dust_limit)
                    .unwrap_or(546);

                let max_fee_affordable = total_input.saturating_sub(dust_limit);

                if new_fee > max_fee_affordable {
                    let new_amount = dust_limit;
                    btc_tx.output[0].value = bitcoin::Amount::from_sat(new_amount);

                    if output_count > 1 {
                        btc_tx.output.pop();
                    }
                } else {
                    let new_amount = total_input.saturating_sub(new_fee);

                    if new_amount < dust_limit {
                        let min_required = new_fee + dust_limit;
                        Err(TransactionErrors::ConvertTxError(format!(
                            "Insufficient funds: need {} sats (fee) + {} sats (min output) = {} sats, but only have {} sats",
                            new_fee, dust_limit, min_required, total_input
                        )))?
                    }

                    btc_tx.output[0].value = bitcoin::Amount::from_sat(new_amount);

                    if output_count > 1 {
                        btc_tx.output.pop();
                    }
                }
            } else {
                let mut total_output: u64 = 0;
                for i in 0..output_count.saturating_sub(1) {
                    total_output += btc_tx.output[i].value.to_sat();
                }

                let new_change = total_input
                    .saturating_sub(total_output)
                    .saturating_sub(new_fee);

                let dust_limit = metadata
                    .signer
                    .as_ref()
                    .map(wallet::bitcoin_wallet::get_dust_limit)
                    .unwrap_or(546);

                if new_change >= dust_limit {
                    btc_tx.output[output_count - 1].value = bitcoin::Amount::from_sat(new_change);
                } else if output_count > 1 {
                    btc_tx.output.pop();
                } else {
                    Err(TransactionErrors::ConvertTxError(
                        "Insufficient funds for fee".to_string(),
                    ))?
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
        passphrase: Option<&str>,
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
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    async fn prepare_and_sign_btc_transaction(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;
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
        passphrase: Option<&str>,
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
        passphrase: Option<&str>,
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

        wallet.add_history(&history)?;

        Ok(history)
    }

    async fn prepare_and_sign_btc_transaction(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> Result<TransactionReceipt> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let provider = self.get_provider(data.chain_hash)?;

        Ok(wallet
            .prepare_and_sign_btc_transaction(
                &provider,
                account_index,
                seed_bytes,
                passphrase,
                destinations,
                fee_rate_sat_per_vbyte,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::{bg_storage::StorageManagement, bg_token::TokensManagement, BackgroundBip39Params};
    use alloy::{primitives::U256, rpc::types::TransactionRequest as ETHTransactionRequest};
    use network::btc::BtcOperations;

    use proto::{address::Address, tx::TransactionRequest};
    use rand::RngExt;
    use secrecy::{ExposeSecret, SecretString};
    use test_data::{
        empty_passphrase, gen_anvil_net_conf, gen_anvil_token, gen_btc_regtest_conf,
        gen_eth_account, gen_zil_account, gen_zil_testnet_conf, gen_zil_token, ANVIL_MNEMONIC,
        TEST_PASSWORD,
    };
    use token::ft::FToken;
    use tokio;
    use wallet::{wallet_crypto::WalletCrypto, wallet_transaction::WalletTransaction};

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
            .sign_transaction(zilpay_trasnfer_req, 0, &argon_seed, None)
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
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
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
        use tokio::time::{sleep, Duration};

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
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
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

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
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
            .sign_message(0, 0, &argon_seed, None, message, None, None)
            .unwrap();

        let hashed_message = Sha256::digest(message.as_bytes());
        let key_pair = bg
            .get_wallet_by_index(0)
            .unwrap()
            .reveal_keypair(0, &argon_seed, None)
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
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        assert_eq!(
            revealed_mnemonic.to_phrase().expose_secret(),
            UNCHECKSUMED_WORD
        );
        assert_eq!(
            "d7986cf4acc822c1a6cdc4170f5561a6cee1591c37ec6a887bb650d051e4ad71",
            hex::encode(&keypair.get_secretkey().unwrap().as_ref())
        );
        assert_eq!(
            "022b8e6855eaf04ec7bd2e01d5aaf4e46a111b509882e5456d97af60a6d1ed6f28",
            hex::encode(&keypair.get_pubkey().unwrap().as_bytes())
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
        dbg!(&ftokens);

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

        let signed_tx = bg
            .prepare_and_sign_btc_transaction(0, 0, &argon_seed, None, destinations, Some(10))
            .await
            .unwrap();

        assert!(signed_tx.verify().unwrap());

        if let TransactionReceipt::Bitcoin((signed_btc_tx, _)) = &signed_tx {
            assert!(signed_btc_tx.output.len() >= 1);
        } else {
            panic!("Not a BTC tx");
        }

        let txns = vec![signed_tx];
        bg.broadcast_signed_transactions(0, txns).await.unwrap();
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

        let amount_sun: i64 = sender_balance.try_into().expect("balance must fit in i64");

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
        dbg!(sender_balance, amount_sun, fee);
        assert!(fee >= 0, "TransferContract fee_limit must be non-negative");

        super::update_tx_from_params(&mut tx_request, params, sender_balance).unwrap();

        if let TransactionRequest::Tron((ref updated, _)) = tx_request {
            if let Some(amount) = updated.transfer_amount() {
                if fee > 0 {
                    assert_eq!(
                        amount,
                        amount_sun - fee,
                        "amount must be reduced by fee for max balance transfer"
                    );
                } else {
                    assert_eq!(
                        amount, amount_sun,
                        "amount must stay unchanged for zero fee_limit"
                    );
                }
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
            .reveal_keypair(sender_idx, &argon_seed, None)
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
            .sign_message(0, 0, &argon_seed, None, message, None, None)
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let key_pair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

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
            .sign_message(0, 0, &argon_seed, None, hex_message, None, None)
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let key_pair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        let decoded = hex::decode(&hex_message[2..]).unwrap();
        let prefixed_msg = format!("\x19TRON Signed Message:\n{}", decoded.len());
        let mut full_msg = prefixed_msg.into_bytes();
        full_msg.extend_from_slice(&decoded);
        let hash = keccak256(&full_msg);

        let is_valid = key_pair.verify_hash(&hash.0, &signature).unwrap();
        assert!(is_valid, "Tron hex message signature verification failed");
    }
}
