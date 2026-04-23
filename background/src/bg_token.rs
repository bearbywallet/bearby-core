use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use alloy::{primitives::U256, rpc::types::TransactionInput};
use async_trait::async_trait;
use config::sha::SHA256_SIZE;
use crypto::slip44::{SOLANA, TRON};
use errors::background::BackgroundError;
use network::{
    evm::generate_erc20_transfer_data,
    solana::tx_builder::{build_sol_transfer_message, build_spl_transfer_message},
    solana::SolanaOperations,
};
use proto::{
    address::Address,
    solana_tx::SolanaTransaction,
    tron_tx::TronTransaction,
    tx::{ETHTransactionRequest, TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use serde_json::json;
use token::ft::FToken;
use wallet::{account::AccountV2, wallet_storage::StorageOperations};

#[async_trait]
pub trait TokensManagement {
    type Error;

    async fn fetch_ftoken_meta(
        &self,
        wallet_index: usize,
        contract: Address,
    ) -> std::result::Result<FToken, Self::Error>;

    async fn sync_ftokens_balances(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    async fn build_token_transfer(
        &self,
        token: &FToken,
        from: &AccountV2,
        to: Address,
        amount: U256,
    ) -> std::result::Result<TransactionRequest, Self::Error>;
}

#[async_trait]
impl TokensManagement for Background {
    type Error = BackgroundError;

    async fn build_token_transfer(
        &self,
        token: &FToken,
        sender: &AccountV2,
        to: Address,
        amount: U256,
    ) -> Result<TransactionRequest> {
        let provider = self.get_provider(token.chain_hash)?;
        let evm_chain_id = provider.config.chain_id();
        let erc20_payment = || ETHTransactionRequest {
            to: Some(to.to_alloy_addr().into()),
            value: Some(amount),
            nonce: Some(0),
            gas: Some(21000),
            from: Some(sender.addr.to_alloy_addr()),
            chain_id: Some(evm_chain_id),
            ..Default::default()
        };
        let erc20_transfer = || -> Result<ETHTransactionRequest> {
            let transfer_data = generate_erc20_transfer_data(&to, amount)?;
            let token_transfer_request = ETHTransactionRequest {
                from: Some(sender.addr.to_alloy_addr()),
                to: Some(token.addr.to_alloy_addr().into()),
                value: Some(U256::ZERO),
                nonce: Some(0),
                gas: None,
                chain_id: Some(evm_chain_id),
                input: TransactionInput::new(transfer_data.into()),
                ..Default::default()
            };

            Ok(token_transfer_request)
        };
        let metadata = TransactionMetadata {
            chain_hash: token.chain_hash,
            hash: None,
            info: None,
            icon: None,
            title: None,
            signer: Some(sender.addr.clone()),
            token_info: Some((amount, token.decimals, token.symbol.clone())),
            btc_witness_utxos: None,
            broadcast: true,
        };
        let addr = if token.native {
            &sender.addr
        } else {
            &token.addr
        };

        match addr {
            Address::Secp256k1Bitcoin(_) => {
                if !token.native {
                    return Err(BackgroundError::TokenError(
                        errors::token::TokenError::ABIError(
                            "BTC tokens not supported yet".to_string(),
                        ),
                    ));
                }

                let amount_sat = amount.to::<u64>();
                let provider = self.get_provider(token.chain_hash)?;

                let (tx, witness_utxos) = crate::bg_tx::build_unsigned_btc_transaction(
                    &provider,
                    &sender.addr,
                    vec![(to, amount_sat)],
                    None,
                )
                .await?;

                let metadata = TransactionMetadata {
                    chain_hash: token.chain_hash,
                    hash: None,
                    info: None,
                    icon: None,
                    title: None,
                    signer: Some(sender.addr.clone()),
                    token_info: Some((amount, token.decimals, token.symbol.clone())),
                    btc_witness_utxos: Some(witness_utxos),
                    broadcast: true,
                };

                let txn = TransactionRequest::Bitcoin((tx, metadata));

                Ok(txn)
            }
            Address::Secp256k1Keccak256(_) => {
                let transfer_request = if token.native {
                    erc20_payment()
                } else {
                    erc20_transfer()?
                };

                let txn = TransactionRequest::Ethereum((transfer_request, metadata));

                Ok(txn)
            }
            Address::Secp256k1Sha256(_) => {
                let transfer_request = if token.native {
                    ZILTransactionRequest {
                        nonce: 0,
                        chain_id: provider.config.chain_ids[1] as u16,
                        gas_price: 2_000_000_000,
                        gas_limit: 50,
                        to_addr: to,
                        amount: amount.to::<u128>(),
                        code: Vec::with_capacity(0),
                        data: Vec::with_capacity(0),
                    }
                } else {
                    let base_16_to = to.get_zil_check_sum_addr()?.to_lowercase();
                    let payload = json!({
                        "_tag": "Transfer",
                        "params": [
                            { "vname": "to", "type": "ByStr20", "value": base_16_to },
                            { "vname": "amount", "type": "Uint128", "value": amount.to_string() }
                        ]
                    })
                    .to_string();
                    ZILTransactionRequest {
                        nonce: 0,
                        chain_id: provider.config.chain_ids[1] as u16,
                        gas_price: 2_000_000_000,
                        gas_limit: 5000,
                        to_addr: token.addr.clone(),
                        amount: 0,
                        code: Vec::with_capacity(0),
                        data: payload.as_bytes().to_vec(),
                    }
                };
                let txn = TransactionRequest::Zilliqa((transfer_request, metadata));

                Ok(txn)
            }
            Address::Secp256k1Tron(_) => {
                let tron_tx = if token.native {
                    TronTransaction::builder()
                        .transfer(&sender.addr, &to, amount.to::<i64>())
                        .build()
                        .map_err(|e| {
                            BackgroundError::TransactionErrors(
                                errors::tx::TransactionErrors::ConvertTxError(e.to_string()),
                            )
                        })?
                } else {
                    let transfer_data = network::evm::generate_erc20_transfer_data(&to, amount)?;
                    TronTransaction::builder()
                        .trigger_smart_contract(
                            &sender.addr,
                            &token.addr,
                            0,
                            transfer_data.to_vec(),
                            0,
                            0,
                        )
                        .build()
                        .map_err(|e| {
                            BackgroundError::TransactionErrors(
                                errors::tx::TransactionErrors::ConvertTxError(e.to_string()),
                            )
                        })?
                };
                let txn = TransactionRequest::Tron((tron_tx, metadata));

                Ok(txn)
            }
            Address::Ed25519Solana(mint_pk) => {
                let from_pk = &sender.addr.to_solana_addr()?;
                let Address::Ed25519Solana(to_pk) = to else {
                    return Err(BackgroundError::TokenError(
                        errors::token::TokenError::ABIError(
                            "recipient must be a Solana address".to_string(),
                        ),
                    ));
                };

                let blockhash_str = provider
                    .solana_get_latest_blockhash()
                    .await
                    .map_err(BackgroundError::NetworkErrors)?;

                let blockhash: [u8; SHA256_SIZE] = bs58::decode(&blockhash_str)
                    .into_vec()
                    .map_err(|e| {
                        BackgroundError::TokenError(errors::token::TokenError::ABIError(
                            e.to_string(),
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        BackgroundError::TokenError(errors::token::TokenError::ABIError(
                            "blockhash must be 32 bytes".to_string(),
                        ))
                    })?;

                if token.native {
                    let from_b58 = from_pk.to_string();
                    let (data_len, owner) = provider
                        .solana_check_account_health(&from_b58)
                        .await
                        .map_err(BackgroundError::NetworkErrors)?;
                    let expected_owner = token.addr.auto_format();
                    if owner != expected_owner || data_len > 0 {
                        return Err(BackgroundError::TokenError(
                            errors::token::TokenError::ABIError(format!(
                                "Account {from_b58} cannot send native SOL: has {data_len} bytes of on-chain data (owner: {owner}). Use a different account."
                            )),
                        ));
                    }
                }

                let message = if token.native {
                    build_sol_transfer_message(from_pk, &to_pk, amount.to::<u64>(), &blockhash)
                        .map_err(|e| {
                            BackgroundError::TokenError(errors::token::TokenError::ABIError(e))
                        })?
                } else {
                    let mint_b58 = mint_pk.to_string();
                    let (_space, token_program_str) = provider
                        .solana_check_account_health(&mint_b58)
                        .await
                        .map_err(BackgroundError::NetworkErrors)?;
                    let token_program: solana_pubkey::Pubkey = token_program_str.parse().map_err(
                        |e: solana_pubkey::ParsePubkeyError| {
                            BackgroundError::TokenError(errors::token::TokenError::ABIError(
                                e.to_string(),
                            ))
                        },
                    )?;
                    build_spl_transfer_message(
                        from_pk,
                        mint_pk,
                        &to_pk,
                        amount.to::<u64>(),
                        &blockhash,
                        &token_program,
                    )
                    .map_err(|e| {
                        BackgroundError::TokenError(errors::token::TokenError::ABIError(e))
                    })?
                };

                Ok(TransactionRequest::Solana((
                    SolanaTransaction { message },
                    metadata,
                )))
            }
        }
    }

    async fn fetch_ftoken_meta(&self, wallet_index: usize, contract: Address) -> Result<FToken> {
        let w = self.get_wallet_by_index(wallet_index)?;
        let data = w.get_wallet_data()?;
        let current_accounts = data.get_accounts()?;
        let accounts = current_accounts
            .iter()
            .map(|a| &a.addr)
            .collect::<Vec<&Address>>();
        let provider = self.get_provider(data.chain_hash)?;
        let mut token_meta = provider.ftoken_meta(contract, &accounts).await?;

        if provider.config.slip_44 == TRON {
            token_meta.logo = Some(format!(
                "https://static.tronscan.org/production/upload/logo/new/{}.png",
                token_meta.addr.auto_format(),
            ));
        } else if provider.config.slip_44 == SOLANA {
            //
        } else if let Some(t) = w.get_ftokens()?.into_iter().next() {
            token_meta.logo = t.logo;
        }

        Ok(token_meta)
    }

    async fn sync_ftokens_balances(&self, wallet_index: usize) -> Result<()> {
        let w = self
            .wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let mut ftokens = w.get_ftokens()?;
        let data = w.get_wallet_data()?;

        if ftokens.is_empty() {
            return Ok(());
        }

        let selected_account = data.get_selected_account()?;
        let addresses = vec![&selected_account.addr];
        let provider = self.get_provider(data.chain_hash)?;
        let matching_tokens: Vec<&mut FToken> = ftokens
            .iter_mut()
            .filter(|token| token.chain_hash == data.chain_hash)
            .collect();

        provider
            .update_balances(matching_tokens, &addresses)
            .await?;

        w.save_ftokens(&ftokens)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_tokens {
    use super::*;
    use crate::bg_tx::update_tx_from_params;
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use crate::{bg_tx::TransactionsManagement, bg_wallet::WalletManagement};
    use wallet::wallet_account::AccountManagement;

    use config::address::ADDR_LEN;
    use crypto::bip49::{DerivationPath, DerivationTypeCodec};
    use crypto::slip44;

    use history::status::TransactionStatus;
    use network::btc::BtcOperations;
    use rand::RngExt;
    use rpc::network_config::{ChainConfig, Explorer};
    use secrecy::SecretString;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;
    use test_data::{
        anvil_accounts, empty_passphrase, gen_anvil_net_conf, gen_anvil_token,
        gen_btc_regtest_conf, gen_sol_devnet_conf, gen_sol_token, ANVIL_MNEMONIC,
    };
    use test_data::{
        gen_eth_account, gen_tron_account, gen_tron_testnet_conf, gen_tron_token, gen_zil_account,
        gen_zil_testnet_conf, tron_addresses, TEST_PASSWORD,
    };
    use tokio;
    use wallet::wallet_token::TokenManagement;
    use wallet::wallet_transaction::WalletTransaction;

    const USDT_TOKEN: &str = "0x55d398326f99059fF775485246999027B3197955";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_bsc_mainnet_conf() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Binance Smart Chain".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155, 1559],
            slip_44: slip44::ETHEREUM,
            ens: None,
            explorers: vec![Explorer {
                name: "BscScan".to_string(),
                url: "https://bscscan.com".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_mainnet_token(chain_hash: u64) -> FToken {
        FToken {
            rate: 0f64,
            chain_hash,
            default: true,
            name: "Binance Smart Chain".to_string(),
            symbol: "BSC".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_ftoken_meta() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [gen_eth_account(0, "Bsc account 1")];
        let net_config = gen_bsc_mainnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![gen_bsc_mainnet_token(net_config.hash())],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
        {
            let d = bg.wallets.first().unwrap().get_wallet_data().unwrap();
            assert_eq!(d.get_accounts().unwrap().len(), 1);
        }

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        assert_eq!(&meta.name, "Tether USD");
        assert_eq!(&meta.symbol, "USDT");
        assert_eq!(meta.decimals, 18u8);
        assert_eq!(meta.chain_hash, net_config.hash());
        assert!(!meta.default);
        assert!(!meta.native);

        let account_key = {
            let data = bg.wallets[0].get_wallet_data().unwrap();
            data.get_accounts().unwrap()[0].addr.to_hash()
        };
        assert!(meta.balances.contains_key(&account_key));
        assert_eq!(meta.balances.get(&account_key).unwrap().to::<usize>(), 0);

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();

        let tokens = bg.wallets.first().unwrap().get_ftokens().unwrap();

        assert!(tokens[0].native);
        assert!(tokens[0].default);
        assert_eq!(tokens[0].chain_hash, net_config.hash());
    }

    #[tokio::test]
    async fn test_sync_ft_balances() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [
            gen_eth_account(0, "account 0"),
            gen_eth_account(1, "account 1"),
            gen_eth_account(2, "account 2"),
            gen_eth_account(3, "account 3"),
            gen_eth_account(4, "account 4"),
            gen_eth_account(5, "account 5"),
            gen_eth_account(6, "account 6"),
        ];
        let net_config = gen_bsc_mainnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![gen_bsc_mainnet_token(net_config.hash())],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
        {
            let d = bg.wallets.first().unwrap().get_wallet_data().unwrap();
            assert_eq!(d.get_accounts().unwrap().len(), 7);
        }

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();

        {
            let wallet = bg.wallets.first_mut().unwrap();
            let mut ftokens = wallet.get_ftokens().unwrap();
            for token in ftokens.iter_mut() {
                token.balances.clear();
            }
            wallet.save_ftokens(&ftokens).unwrap();
        }

        bg.sync_ftokens_balances(0).await.unwrap();

        let ftokens = bg.wallets[0].get_ftokens().unwrap();

        dbg!(&ftokens);

        let selected_key = {
            let data = bg.wallets[0].get_wallet_data().unwrap();
            data.get_selected_account().unwrap().addr.to_hash()
        };

        for token in &ftokens {
            assert!(
                token.balances.contains_key(&selected_key),
                "token {} missing balance for selected account (key {})",
                token.symbol,
                selected_key
            );
        }
    }

    #[tokio::test]
    async fn test_build_token_transfer_zil() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [gen_zil_account(0, "Zil account 1")];
        let net_config = gen_zil_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();

        let zlp_token = FToken::zlp(net_config.hash());

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![zlp_token.clone()],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let recipient = "0xEC6bB19886c9D5f5125DfC739362Bf54AA23d51F";
        let to_addr = Address::from_zil_base16(recipient).unwrap();
        let amount = U256::from(1_000_000_000_000_u64);

        let wallet = bg.wallets.first().unwrap();
        let account = wallet
            .get_wallet_data()
            .unwrap()
            .get_account(0)
            .unwrap()
            .clone();

        let txn_req = bg
            .build_token_transfer(&zlp_token, &account, to_addr.clone(), amount)
            .await
            .unwrap();

        match txn_req {
            TransactionRequest::Zilliqa((req, _meta)) => {
                assert_eq!(req.to_addr, zlp_token.addr);
                assert_eq!(req.amount, 0);
                assert_eq!(req.gas_limit, 5000);

                let base_16_to = to_addr
                    .get_zil_check_sum_addr()
                    .unwrap_or_default()
                    .to_lowercase();
                let payload = json!({
                    "_tag": "Transfer",
                    "params": [
                        { "vname": "to", "type": "ByStr20", "value": base_16_to },
                        { "vname": "amount", "type": "Uint128", "value": amount.to_string() }
                    ]
                })
                .to_string();

                assert_eq!(req.data, payload.as_bytes().to_vec());
            }
            _ => panic!("Expected Zilliqa transaction request"),
        }
    }

    #[tokio::test]
    async fn test_build_token_transfer_btc_max_amount() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_btc_regtest_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [
            (2, "BTC TapRoot Acc 2".to_string()),
            (3, "BTC TapRoot Acc 3".to_string()),
        ];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BTC Max wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![test_data::gen_btc_token()],
            bip: DerivationPath::BIP84_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        let accs = data.get_accounts().unwrap();
        assert_eq!(accs.len(), 2, "Should have 2 accounts");

        let account = &accs[0];
        let account_1 = &accs[1];

        let addr_str = account.addr.auto_format();
        let addr_str_1 = account_1.addr.auto_format();

        assert!(
            addr_str.starts_with("bcrt1"),
            "Should be SegWit address starting with bc1q, got: {}",
            addr_str
        );
        assert_eq!(
            addr_str, "bcrt1qt3az9lwpqfvr466mezsewuzdc4d379ldygnnez",
            "Account 2 should match expected SegWit address"
        );
        assert_eq!(
            addr_str_1, "bcrt1qcqp7wgm6ke7zvwqnyy5a52ratfuhufw02cr92j",
            "Account 3 should match expected SegWit address"
        );

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();
        let btc_token = ftokens.first().unwrap();

        assert!(btc_token.native, "BTC token should be native");
        assert_eq!(btc_token.symbol, "BTC", "Token symbol should be BTC");

        let balance_0 = btc_token
            .balances
            .get(&account.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        let balance_1 = btc_token
            .balances
            .get(&account_1.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);

        let provider = bg.get_provider(net_config.hash()).unwrap();

        let (from_account, from_index, to_account) = if balance_0 > U256::ZERO {
            let unspents = provider.btc_list_unspent(&account.addr).await.unwrap();
            if !unspents.is_empty() {
                (account, 0usize, account_1)
            } else if balance_1 > U256::ZERO {
                let unspents_1 = provider.btc_list_unspent(&account_1.addr).await.unwrap();
                if !unspents_1.is_empty() {
                    (account_1, 1usize, account)
                } else {
                    println!("No UTXOs available for either account, skipping test");
                    return;
                }
            } else {
                println!("No balance available in either account, skipping test");
                return;
            }
        } else if balance_1 > U256::ZERO {
            let unspents_1 = provider.btc_list_unspent(&account_1.addr).await.unwrap();
            if !unspents_1.is_empty() {
                (account_1, 1usize, account)
            } else {
                println!("No UTXOs available, skipping test");
                return;
            }
        } else {
            println!("No balance available in either account, skipping test");
            return;
        };

        let unspents = provider.btc_list_unspent(&from_account.addr).await.unwrap();
        let actual_balance: u64 = unspents.iter().map(|u| u.value).sum();
        let max_balance = U256::from(actual_balance);

        println!(
            "Sending from account {}, balance: {} satoshis",
            from_index, actual_balance
        );

        let dest_addr = to_account.addr.clone();

        let mut txn_req = bg
            .build_token_transfer(btc_token, from_account, dest_addr.clone(), max_balance)
            .await
            .unwrap();

        match &txn_req {
            TransactionRequest::Bitcoin((tx, meta)) => {
                assert!(tx.input.len() > 0, "Should have at least one input");
                assert!(tx.output.len() > 0, "Should have at least one output");
                assert_eq!(meta.chain_hash, net_config.hash());
                assert!(meta.btc_witness_utxos.is_some());
                assert_eq!(
                    meta.token_info,
                    Some((max_balance, btc_token.decimals, btc_token.symbol.clone()))
                );

                let total_output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                let total_input: u64 = meta
                    .btc_witness_utxos
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|u| u.value.to_sat())
                    .sum();
                let fee = total_input.saturating_sub(total_output);

                println!("Total input: {} satoshis", total_input);
                println!("Total output: {} satoshis", total_output);
                println!("Fee: {} satoshis", fee);

                assert!(
                    total_output < total_input,
                    "Output should be less than input to account for fees"
                );
                assert!(fee > 0, "Fee should be greater than zero");
                assert!(
                    total_output <= max_balance.to::<u64>(),
                    "Output should not exceed requested max balance"
                );
            }
            _ => panic!("Expected Bitcoin transaction request"),
        }

        let params = provider.btc_estimate_params_batch(&txn_req).await.unwrap();

        println!(
            "Fee estimates - slow: {}, market: {}, fast: {}",
            params.slow, params.market, params.fast
        );

        use crate::bg_tx::update_tx_from_params;
        update_tx_from_params(&mut txn_req, params.clone(), max_balance).unwrap();

        match &txn_req {
            TransactionRequest::Bitcoin((tx, meta)) => {
                let total_output_after: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                let total_input: u64 = meta
                    .btc_witness_utxos
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|u| u.value.to_sat())
                    .sum();
                let actual_fee = total_input.saturating_sub(total_output_after);

                println!("After update_tx_from_params:");
                println!("  Total output: {} satoshis", total_output_after);
                println!("  Actual fee: {} satoshis", actual_fee);
                println!("  Output count: {}", tx.output.len());

                assert_eq!(
                    total_input,
                    total_output_after + actual_fee,
                    "Total input should equal output + fee"
                );

                assert_eq!(
                    tx.output.len(),
                    1,
                    "Max balance transfer should have exactly 1 output (no change)"
                );

                assert!(actual_fee > 0, "Fee should be greater than zero");

                assert_eq!(
                    total_output_after + actual_fee,
                    actual_balance,
                    "Output + fee should equal the full balance (sender balance becomes 0)"
                );
            }
            _ => panic!("Expected Bitcoin transaction request"),
        }

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();

        let signed_tx = wallet
            .sign_transaction(txn_req, from_index, &argon_seed, None)
            .await
            .unwrap();

        assert!(
            signed_tx.verify().unwrap(),
            "Signed transaction should be valid"
        );

        let txns = vec![signed_tx];
        let broadcasted_txns = bg.broadcast_signed_transactions(0, txns).await.unwrap();

        assert_eq!(broadcasted_txns.len(), 1);
        let tx_hash = broadcasted_txns[0].metadata.hash.clone().unwrap();
        println!("Max amount transaction broadcasted with hash: {}", tx_hash);

        let wallet_check = bg.get_wallet_by_index(0).unwrap();
        let history_check = wallet_check.get_history().unwrap();
        assert!(history_check.len() > 0, "Transaction should be in history");
    }

    #[tokio::test]
    async fn test_build_token_transfer_scilla_max_amount() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [
            (0, "scilla Acc 2".to_string()),
            (1, "scilla Acc 3".to_string()),
        ];

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Scilla".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![test_data::gen_zil_token()],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();
        bg.swap_zilliqa_chain(0, 1).unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        let accs = data.get_accounts().unwrap();
        let account = &accs[0];
        let account_1 = &accs[1];

        let addr_str = account.addr.auto_format();
        let addr_str_1 = account_1.addr.auto_format();

        assert_eq!(
            addr_str, "zil1d4c4vntch9jpn3fj9d4ugpuap8cmdj7alnrxvv",
            "Account 0 should match expected SegWit address"
        );
        assert_eq!(
            addr_str_1, "zil1yzzzyac7hc3n93ca85xm4kytrk44j23yddppmy",
            "Account 1 should match expected SegWit address"
        );

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();
        let scilla_token = ftokens.first().unwrap();

        assert!(scilla_token.native, "ZIL token should be native");
        assert_eq!(scilla_token.symbol, "ZIL", "Token symbol should be BTC");

        let balance_0 = scilla_token
            .balances
            .get(&account.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        let balance_1 = scilla_token
            .balances
            .get(&account_1.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);

        let (from_index, from_account, to_account, amount) = if balance_0 > U256::ZERO {
            (0, account, account_1, balance_0)
        } else if balance_1 > U256::ZERO {
            (1, account_1, account, balance_1)
        } else {
            panic!("acocunt 1 and 2 not enough funds");
        };

        let provider = bg.get_provider(net_config.hash()).unwrap();
        let mut txn_req = bg
            .build_token_transfer(scilla_token, from_account, to_account.addr.clone(), amount)
            .await
            .unwrap();
        let params = provider
            .estimate_params_batch(&txn_req, &from_account.addr, 10, None)
            .await
            .unwrap();

        update_tx_from_params(&mut txn_req, params.clone(), amount).unwrap();

        match txn_req {
            TransactionRequest::Zilliqa((ref tx_zil, _)) => {
                assert_ne!(U256::from(tx_zil.amount), amount);
            }
            _ => {
                panic!("wrong tx");
            }
        }

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();

        let signed_tx = wallet
            .sign_transaction(txn_req, from_index, &argon_seed, None)
            .await
            .unwrap();
        assert!(signed_tx.verify().unwrap());

        match signed_tx {
            proto::tx::TransactionReceipt::Zilliqa((signed_zil_tx, _)) => {
                assert_eq!(
                    signed_zil_tx.pub_key,
                    from_account.pub_key.as_ref().unwrap().as_bytes()
                );
                assert_eq!(signed_zil_tx.version, 21_823_489);

                let gas_price: u128 = params.gas_price.try_into().unwrap();
                assert_eq!(signed_zil_tx.gas_price, gas_price.to_be_bytes());
                assert_eq!(U256::from(signed_zil_tx.gas_limit), 50);
                assert_eq!(
                    signed_zil_tx.to_addr.as_slice(),
                    to_account.addr.addr_bytes()
                );
                let zil_amount = U256::from(u128::from_be_bytes(signed_zil_tx.amount));
                let shoud_be_amount = amount - params.current;

                assert_eq!(zil_amount, shoud_be_amount);
            }
            _ => {
                panic!("wrong tx")
            }
        }

        // let h = bg
        //     .broadcast_signed_transactions(0, from_index, vec![signed_tx])
        //     .await
        //     .unwrap();

        // dbg!(&h.first().unwrap().metadata.hash);

        // sleep(Duration::from_secs(10));

        // bg.sync_ftokens_balances(0).await.unwrap();
        // let ftokens = wallet.get_ftokens().unwrap();
        // let scilla_token = ftokens.first().unwrap();
        // let sender_blk = scilla_token.balances.get(&from_index).unwrap();

        // assert_eq!(*sender_blk, U256::ZERO);
    }

    #[tokio::test]
    async fn test_eth_max_amount_transfer_anvil() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let accounts = [
            gen_eth_account(0, "Anvil Acc 0"),
            gen_eth_account(1, "Anvil Acc 1"),
        ];

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Anvil Max Transfer".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_anvil_token()],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let accs = data.get_accounts().unwrap();
        let account_0 = &accs[0];
        let account_1 = &accs[1];

        assert_eq!(
            account_0.addr.to_string().to_lowercase(),
            anvil_accounts::ACCOUNT_0.to_lowercase()
        );
        assert_eq!(
            account_1.addr.to_string().to_lowercase(),
            anvil_accounts::ACCOUNT_1.to_lowercase()
        );

        let ftokens = wallet.get_ftokens().unwrap();
        let eth_token = ftokens.first().unwrap();
        let balance_0 = eth_token
            .balances
            .get(&account_0.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        let balance_1 = eth_token
            .balances
            .get(&account_1.addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);

        let (from_index, from_account, to_account, amount) = if balance_0 > balance_1 {
            (0, account_0, account_1, balance_0)
        } else if balance_1 > balance_0 {
            (1, account_1, account_0, balance_1)
        } else {
            (0, account_0, account_1, balance_0)
        };

        let mut tx = bg
            .build_token_transfer(eth_token, from_account, to_account.addr.clone(), amount)
            .await
            .unwrap();

        let provider = bg.get_provider(net_config.hash()).unwrap();
        let params = provider
            .estimate_params_batch(&tx, &from_account.addr, 10, None)
            .await
            .unwrap();

        update_tx_from_params(&mut tx, params.clone(), amount).unwrap();

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();
        let signed_tx = wallet
            .sign_transaction(tx, from_index, &argon_seed, None)
            .await
            .unwrap();

        assert!(signed_tx.verify().unwrap());

        match bg.broadcast_signed_transactions(0, vec![signed_tx]).await {
            Ok(broadcasted_txns) => {
                assert_eq!(broadcasted_txns.len(), 1);
                assert!(broadcasted_txns[0].metadata.hash.is_some());

                sleep(Duration::from_secs(2));

                bg.check_pending_txns(0).await.unwrap();

                let wallet = bg.get_wallet_by_index(0).unwrap();
                let history = wallet.get_history().unwrap();

                assert_eq!(history.len(), 1);
                assert_eq!(history[0].status, TransactionStatus::Success);

                let evm_json = history[0].evm.as_ref().unwrap();
                let tx_data: Value = serde_json::from_str(evm_json).unwrap();

                let gas_used = U256::from_str(tx_data["gasUsed"].as_str().unwrap()).unwrap();

                let _total_fee = if let Some(priority_fee_str) =
                    tx_data["maxPriorityFeePerGas"].as_str()
                {
                    let effective_gas_price =
                        U256::from_str(tx_data["effectiveGasPrice"].as_str().unwrap()).unwrap();
                    let max_priority_fee = U256::from_str(priority_fee_str).unwrap();
                    let base_fee = effective_gas_price - max_priority_fee;
                    gas_used * (base_fee + max_priority_fee)
                } else {
                    let gas_price = U256::from_str(tx_data["gasPrice"].as_str().unwrap()).unwrap();
                    gas_used * gas_price
                };

                bg.sync_ftokens_balances(0).await.unwrap();

                let wallet = bg.get_wallet_by_index(0).unwrap();
                let ftokens = wallet.get_ftokens().unwrap();
                let eth_token = ftokens.first().unwrap();
                let _final_balance = eth_token
                    .balances
                    .get(&from_account.addr.to_hash())
                    .copied()
                    .unwrap_or(U256::ZERO);

                // assert_eq!(final_balance, U256::ZERO);
            }
            Err(e) => {
                dbg!(e);
            }
        }
    }

    #[tokio::test]
    async fn test_fetch_tron_ftoken_meta() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_tron_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [gen_tron_account(0, "Tron Acc 0")];

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
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
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(
            data.get_account(0).unwrap().addr.auto_format(),
            tron_addresses::ADDR_0
        );

        let btt_contract =
            Address::from_tron_address("TNuoKL1ni8aoshfFL1ASca1Gou9RXwAzfn").unwrap();
        let btt_meta = bg.fetch_ftoken_meta(0, btt_contract).await.unwrap();

        assert!(!btt_meta.name.is_empty());
        assert!(!btt_meta.symbol.is_empty());
        assert!(btt_meta.decimals > 0);
        assert_eq!(btt_meta.chain_hash, net_config.hash());
        assert!(!btt_meta.native);
        assert!(!btt_meta.default);
        assert!(btt_meta
            .balances
            .contains_key(&data.get_accounts().unwrap()[0].addr.to_hash()));

        bg.wallets
            .first_mut()
            .unwrap()
            .add_ftoken(btt_meta)
            .unwrap();

        let usdt_contract =
            Address::from_tron_address("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf").unwrap();
        let usdt_meta = bg.fetch_ftoken_meta(0, usdt_contract).await.unwrap();

        assert!(!usdt_meta.name.is_empty());
        assert!(!usdt_meta.symbol.is_empty());
        assert!(usdt_meta.decimals > 0);
        assert_eq!(usdt_meta.chain_hash, net_config.hash());
        assert!(!usdt_meta.native);
        assert!(!usdt_meta.default);
        assert!(usdt_meta
            .balances
            .contains_key(&data.get_accounts().unwrap()[0].addr.to_hash()));

        bg.wallets
            .first_mut()
            .unwrap()
            .add_ftoken(usdt_meta)
            .unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let ftokens = bg.wallets.first().unwrap().get_ftokens().unwrap();

        assert_eq!(ftokens.len(), 3);
        assert!(ftokens[0].native);
        assert!(ftokens[0].default);
        assert!(!ftokens[1].native);
        assert!(!ftokens[2].native);
    }

    #[tokio::test]
    async fn test_solana_tokens() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_sol_devnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [(1, "sol 1".to_string()), (2, "sol 2".to_string())];

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_config.hash(),
            mnemonic_str: &mnemonic_secret,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Sol wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![gen_sol_token()],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::DerivationType::AccountChange(0, 0).to_u8(),
        })
        .await
        .unwrap();

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let ftokens = wallet.get_ftokens().unwrap();

        dbg!(&ftokens);

        let accs = data.get_accounts().unwrap();
        dbg!(accs.len());
        assert_eq!(accs.len(), 2, "Should have 2 accounts");

        dbg!(accs[0].addr.auto_format());
        dbg!(accs[1].addr.auto_format());

        assert_eq!(
            accs[0].addr.auto_format(),
            "AqynRZwvVqUPRwRJXvm6odUb3t93fDjnWe3p6BeuUFxD"
        );
        assert_eq!(
            accs[1].addr.auto_format(),
            "CqMbRgMuEhQi9BUS8xP44Wk5nENm48FqJnfjEi4eNb1k"
        );

        let ftokens = wallet.get_ftokens().unwrap();
        let sol_token = ftokens.first().unwrap();
        assert!(sol_token.native);
        assert_eq!(sol_token.symbol, "SOL");

        let balance_0 = sol_token
            .balances
            .get(&accs[0].addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        let balance_1 = sol_token
            .balances
            .get(&accs[1].addr.to_hash())
            .copied()
            .unwrap_or(U256::ZERO);
        dbg!(balance_0, balance_1);

        let (from_account, to_account) = if balance_1 > U256::ZERO {
            (&accs[1], accs[0].addr.clone())
        } else if balance_0 > U256::ZERO {
            (&accs[0], accs[1].addr.clone())
        } else {
            panic!("No funded Solana account for transfer");
        };
        let amount = U256::from(1_000_000_000u64);

        let txn_req = bg
            .build_token_transfer(sol_token, from_account, to_account.clone(), amount)
            .await
            .unwrap();

        match &txn_req {
            TransactionRequest::Solana((sol_tx, meta)) => {
                dbg!(sol_tx.message.len());
                dbg!(&meta.chain_hash);
                dbg!(&meta.token_info);
                dbg!(&meta.signer);
                assert!(!sol_tx.message.is_empty());
                assert_eq!(meta.chain_hash, net_config.hash());
                assert_eq!(
                    meta.token_info,
                    Some((amount, sol_token.decimals, sol_token.symbol.clone()))
                );
                assert_eq!(meta.signer, Some(from_account.addr.clone()));
            }
            _ => panic!("Expected Solana transaction request"),
        }

        let argon_seed = bg
            .unlock_wallet_with_password(&SecretString::new(TEST_PASSWORD.into()), None, 0)
            .await
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        wallet
            .add_next_bip39_account("sol 3".to_string(), 3, None, "", &argon_seed)
            .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let accs = data.get_accounts().unwrap();
        assert_eq!(accs.len(), 3);
        assert_eq!(
            accs[2].addr.auto_format(),
            "9Tj3srBSxH7RFRCm8uharreY7ZBS49XSfpwCeYa7Xaqp"
        );

        let signed_tx = wallet
            .sign_transaction(txn_req, 0, &argon_seed, None)
            .await
            .unwrap();

        dbg!(signed_tx.verify().unwrap());
        assert!(
            signed_tx.verify().unwrap(),
            "Signed Solana tx should verify"
        );

        let (sender_index, receiver_addr) = if balance_1 > U256::ZERO {
            (1usize, accs[2].addr.clone())
        } else if balance_0 > U256::ZERO {
            (0usize, accs[1].addr.clone())
        } else {
            panic!("No funded Solana account for transfer");
        };

        let sender_balance = match sender_index {
            0 => balance_0,
            _ => balance_1,
        };
        let sender_acc = &accs[sender_index];
        dbg!(sender_index, sender_balance);

        let chain = bg.get_provider(net_config.hash()).unwrap();
        let empty_sol_tx =
            TransactionRequest::Solana((SolanaTransaction { message: vec![] }, Default::default()));
        let fee_params = chain
            .estimate_params_batch(&empty_sol_tx, &sender_acc.addr, 0, None)
            .await
            .unwrap();
        let fee_lamports = u64::try_from(fee_params.gas_price).unwrap();
        dbg!(fee_lamports);

        let max_amount = sender_balance - U256::from(fee_lamports);
        dbg!(max_amount);

        let txn_req = bg
            .build_token_transfer(sol_token, sender_acc, receiver_addr, max_amount)
            .await
            .unwrap();

        let signed_tx = wallet
            .sign_transaction(txn_req, sender_index, &argon_seed, None)
            .await
            .unwrap();

        dbg!(signed_tx.verify().unwrap());

        let broadcasted = bg
            .broadcast_signed_transactions(0, vec![signed_tx])
            .await
            .unwrap();

        dbg!(broadcasted.len());
        dbg!(&broadcasted[0].metadata.hash);
        assert_eq!(broadcasted.len(), 1);
        assert!(broadcasted[0].metadata.hash.is_some());

        tokio::time::sleep(std::time::Duration::from_secs(20)).await;

        bg.check_pending_txns(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let history = wallet.get_history().unwrap();

        dbg!(history.len());
        dbg!(&history[0].status);
        dbg!(&history[0].solana);

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, TransactionStatus::Success);
    }
}
