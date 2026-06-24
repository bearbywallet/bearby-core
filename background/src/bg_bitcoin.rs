use crate::bg_wallet::WalletManagement;
use crate::{bg_provider::ProvidersManagement, Background, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use errors::wallet::WalletErrors;
use network::btc::BtcOperations;
use proto::address::Address;
use proto::btc_tx::BitcoinMetadata;
use proto::btc_utils::{AddressChain, BtcAccountXpubsInput, ByteCodec};
use proto::tx::{TransactionMetadata, TransactionRequest};
use proto::U256;
use std::collections::HashMap;
use token::ft::FToken;
use wallet::account::AccountV2;
use wallet::bitcoin_wallet::{
    append_new_change_address, build_op_return_output, build_unsigned_btc_transaction_with_extras,
    scan_btc_chains_for_xpubs, BitcoinWallet,
};
use wallet::wallet_storage::StorageOperations;

#[async_trait]
pub trait BitcoinManagement {
    type Error;

    async fn scan_btc_account_history(
        &self,
        xpubs: &BtcAccountXpubsInput,
        ledger_index: u8,
        chain_hash: u64,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;

    async fn rotate_btc_account(
        &self,
        wallet_index: usize,
        account_index: usize,
        xpubs: &BtcAccountXpubsInput,
    ) -> std::result::Result<(), Self::Error>;

    /// Build a native-BTC deposit paying `amount_sat` to `vault`.
    /// Pass `Some(memo)` for THORChain-style OP_RETURN; `None` for a plain vault transfer
    /// (e.g., Relay.link). `fee_rate` is sats-per-vbyte. Reuses the same UTXO selection /
    /// signing-metadata plumbing as a plain BTC transfer, adding only the optional memo output.
    /// `xpubs` (HD wallets) lets the builder bootstrap a fresh P2WPKH change address when the
    /// stored chain has no unused internal entry, mirroring `prepare_and_sign_btc_transaction`.
    #[allow(clippy::too_many_arguments)]
    async fn build_btc_deposit_with_memo(
        &self,
        token: &FToken,
        from: &AccountV2,
        vault: Address,
        amount_sat: u64,
        memo: Option<&str>,
        fee_rate: Option<u64>,
        xpubs: Option<&BtcAccountXpubsInput>,
    ) -> std::result::Result<TransactionRequest, Self::Error>;
}

#[async_trait]
impl BitcoinManagement for Background {
    type Error = errors::background::BackgroundError;

    async fn scan_btc_account_history(
        &self,
        xpubs: &BtcAccountXpubsInput,
        ledger_index: u8,
        chain_hash: u64,
    ) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let provider = self.get_provider(chain_hash)?;
        let chains =
            scan_btc_chains_for_xpubs(xpubs, ledger_index as usize, &provider.config).await?;
        Ok(chains)
    }

    async fn rotate_btc_account(
        &self,
        wallet_index: usize,
        account_index: usize,
        xpubs: &BtcAccountXpubsInput,
    ) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let provider = self.get_provider(data.chain_hash)?;

        let old_addr = data.get_account(account_index)?.addr.clone();
        let mut ftokens = wallet.get_ftokens()?;
        let old_balance = ftokens
            .iter()
            .find(|t| t.native && t.chain_hash == data.chain_hash)
            .and_then(|t| t.balances.get(&old_addr.to_hash()).copied())
            .unwrap_or(U256::ZERO);

        wallet
            .rotate_account(xpubs, account_index, &provider.config)
            .await?;

        let data = wallet.get_wallet_data()?;
        let new_addr = data.get_account(account_index)?.addr.clone();

        if let Some(token) = ftokens
            .iter_mut()
            .find(|t| t.native && t.chain_hash == data.chain_hash)
        {
            token.balances.remove(&old_addr.to_hash());
            token.balances.insert(new_addr.to_hash(), old_balance);
        }
        wallet.save_ftokens(&ftokens)?;

        Ok(())
    }

    async fn build_btc_deposit_with_memo(
        &self,
        token: &FToken,
        from: &AccountV2,
        vault: Address,
        amount_sat: u64,
        memo: Option<&str>,
        fee_rate: Option<u64>,
        xpubs: Option<&BtcAccountXpubsInput>,
    ) -> Result<TransactionRequest> {
        let (wallet_ref, account_index) = self
            .wallets
            .iter()
            .find_map(|w| {
                let data = w.get_wallet_data().ok()?;
                let idx = data
                    .get_accounts()
                    .ok()?
                    .iter()
                    .position(|a| a.addr == from.addr)?;
                Some((w, idx))
            })
            .ok_or_else(|| {
                BackgroundError::WalletError(WalletErrors::BincodeError(
                    "BTC sender not found in any wallet".to_string(),
                ))
            })?;

        let wallet_data = wallet_ref.get_wallet_data()?;
        let mut chains = wallet_ref.get_btc_addresses(account_index, wallet_data.chain_hash)?;
        let provider = self.get_provider(wallet_data.chain_hash)?;

        let mut appended_change = false;
        if let Some(xpubs) = xpubs {
            let needs_new_change = chains
                .get(&bitcoin::AddressType::P2wpkh)
                .map(|c| c.get_internal().is_err())
                .unwrap_or(true);
            if needs_new_change {
                let network = provider
                    .config
                    .bitcoin_network()
                    .unwrap_or(bitcoin::Network::Bitcoin);
                append_new_change_address(
                    &mut chains,
                    xpubs,
                    account_index,
                    network,
                    bitcoin::AddressType::P2wpkh,
                )
                .map_err(BackgroundError::WalletError)?;
                appended_change = true;
            }
        }

        // Refresh UTXOs from electrum before building: stored state goes stale
        // after a broadcast (spent inputs are cleared but change is not credited),
        // and listunspent also surfaces mempool change from a prior swap.
        let refreshed = match provider.batch_btc_list_unspent(&mut chains).await {
            Ok(()) => true,
            Err(_) => false,
        };
        if refreshed || appended_change {
            wallet_ref.save_btc_addresses(account_index, &chains, wallet_data.chain_hash)?;
        }

        let extra_outputs = memo
            .map(|m| build_op_return_output(m.as_bytes()))
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();

        let (tx, witness_utxos, input_meta) = build_unsigned_btc_transaction_with_extras(
            &chains,
            vec![(vault, amount_sat)],
            extra_outputs,
            fee_rate,
        )?;

        let input_meta = input_meta
            .into_iter()
            .map(|(at, path)| (at.to_byte(), path))
            .collect();

        let metadata = TransactionMetadata {
            chain_hash: token.chain_hash,
            signer: Some(from.addr.clone()),
            token_info: Some((U256::from(amount_sat), token.decimals, token.symbol.clone())),
            broadcast: true,
            ..Default::default()
        };
        let btc_meta = BitcoinMetadata {
            witness_utxos,
            input_meta,
        };

        Ok(TransactionRequest::Bitcoin((tx, metadata, btc_meta)))
    }
}

#[cfg(test)]
mod tests_bg_bitcoin {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement,
        bg_storage::StorageManagement, bg_wallet::WalletManagement, BackgroundBip39Params,
        BackgroundLedgerParams,
    };
    use config::bip39::EN_WORDS;
    use config::session::AuthMethod;
    use errors::wallet::WalletErrors;
    use pqbip39::mnemonic::Mnemonic;
    use proto::keypair::KeyPair;
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::SecretString;
    use settings::wallet_settings::WalletSettings;
    use test_data::{
        empty_passphrase, gen_btc_regtest_conf, gen_eth_mainnet_conf, gen_zil_testnet_conf,
    };
    use wallet::bitcoin_wallet::{pick_primary_btc_entry, BitcoinWallet};
    use wallet::wallet_account::AccountManagement;
    use wallet::wallet_storage::StorageOperations;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_scan_btc_account_history_offline_returns_all_four_chains() {
        let (mut bg, _dir) = setup_test_background();

        let offline_btc_conf = ChainConfig {
            rpc: vec!["ssl://localhost:1".to_string()],
            slip_44: crypto::slip44::BITCOIN,
            testnet: Some(true),
            ..gen_btc_regtest_conf()
        };
        bg.add_provider(offline_btc_conf.clone()).unwrap();

        let random_words = Background::gen_bip39(24).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &random_words).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let network = offline_btc_conf
            .bitcoin_network()
            .unwrap_or(bitcoin::Network::Bitcoin);

        let ledger_indexes: [u8; 3] = [0, 2, 5];
        let mut accounts = Vec::new();
        let mut account_names = Vec::new();
        let mut btc_chains: HashMap<u8, HashMap<bitcoin::AddressType, AddressChain>> =
            HashMap::new();

        for &li in &ledger_indexes {
            let xpubs = BtcAccountXpubsInput::from_seed(&seed, li as u32, network).unwrap();

            let chains = bg
                .scan_btc_account_history(&xpubs, li, offline_btc_conf.hash())
                .await
                .unwrap();

            for addr_type in [
                bitcoin::AddressType::P2pkh,
                bitcoin::AddressType::P2sh,
                bitcoin::AddressType::P2wpkh,
                bitcoin::AddressType::P2tr,
            ] {
                let chain = chains
                    .get(&addr_type)
                    .unwrap_or_else(|| panic!("missing chain for {:?}", addr_type));
                assert!(
                    !chain.external.is_empty(),
                    "{:?} external chain must not be empty (offline fallback)",
                    addr_type,
                );
            }

            let entry = pick_primary_btc_entry(&chains).unwrap();
            let addr_str = entry.address.auto_format();
            assert!(
                addr_str.starts_with("bcrt1q") || addr_str.starts_with("tb1q"),
                "expected P2WPKH address for ledger_index {}, got: {}",
                li,
                addr_str,
            );

            btc_chains.insert(li, chains);

            accounts.push((li, None));
            account_names.push(format!("BTC Ledger {}", li));
        }

        bg.add_ledger_wallet(
            BackgroundLedgerParams {
                ledger_id: vec![1],
                accounts,
                wallet_name: "Ledger BTC".to_string(),
                account_names,
                wallet_index: 0,
                biometric_type: AuthMethod::None,
                wallet_settings: WalletSettings::default(),
                chain_hash: offline_btc_conf.hash(),
                ftokens: vec![],
                btc_chains,
            },
            WalletSettings::default(),
        )
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let all_accounts = data.get_accounts().unwrap();
        assert_eq!(all_accounts.len(), 3);

        for (pos, &li) in ledger_indexes.iter().enumerate() {
            let acc = &all_accounts[pos];
            assert_eq!(
                acc.account_type.value(),
                li as usize,
                "pos={}: account_type must match ledger_index",
                pos,
            );

            let addr_str = acc.addr.auto_format();
            assert!(
                addr_str.starts_with("bcrt1q") || addr_str.starts_with("tb1q"),
                "pos={}: expected P2WPKH addr, got {}",
                pos,
                addr_str,
            );

            let stored_chains = wallet
                .get_btc_addresses(pos, offline_btc_conf.hash())
                .unwrap();
            assert_eq!(
                stored_chains.len(),
                4,
                "pos={} should have 4 address types (offline fallback)",
                pos,
            );

            let p2wpkh = stored_chains.get(&bitcoin::AddressType::P2wpkh).unwrap();
            assert!(
                !p2wpkh.external.is_empty(),
                "pos={} P2WPKH external chain must not be empty",
                pos,
            );

            assert_eq!(
                acc.addr, p2wpkh.external[0].address,
                "pos={}: account addr must match first P2WPKH external entry",
                pos,
            );

            for entry in p2wpkh.external.iter().chain(p2wpkh.internal.iter()) {
                let path_account = entry.path.get_account_index();
                assert_eq!(
                    path_account, li as usize,
                    "pos={}: path account index must be ledger_index {} but got {}",
                    pos, li, path_account,
                );
            }
        }

        let new_li: u8 = 7;
        let xpubs = BtcAccountXpubsInput::from_seed(&seed, new_li as u32, network).unwrap();
        let new_chains = bg
            .scan_btc_account_history(&xpubs, new_li, offline_btc_conf.hash())
            .await
            .unwrap();
        let new_entry = pick_primary_btc_entry(&new_chains).unwrap();

        wallet
            .add_ledger_account(
                "BTC Ledger 7".to_string(),
                new_li,
                None,
                Some(new_chains.clone()),
                &offline_btc_conf,
            )
            .unwrap();

        let data_after = wallet.get_wallet_data().unwrap();
        let all_after = data_after.get_accounts().unwrap();
        assert_eq!(all_after.len(), 4);

        let appended = &all_after[3];
        assert_eq!(appended.account_type.value(), new_li as usize);
        assert_eq!(appended.addr, new_entry.address);
        assert_eq!(appended.name, "BTC Ledger 7");
        assert_eq!(
            data_after.selected_account, 0,
            "selected_account must be unchanged"
        );
        assert_eq!(data_after.bip, data.bip, "bip must be unchanged");

        let stored_new = wallet
            .get_btc_addresses(3, offline_btc_conf.hash())
            .unwrap();
        assert_eq!(stored_new.len(), 4);
        let stored_p2wpkh = stored_new.get(&bitcoin::AddressType::P2wpkh).unwrap();
        assert_eq!(stored_p2wpkh.external[0].address, appended.addr);

        let eth_conf = gen_eth_mainnet_conf();
        let kp = KeyPair::gen_keccak256().unwrap();
        let pk = kp.get_pubkey().unwrap();
        let mismatched = wallet.add_ledger_account(
            "ETH on BTC wallet".to_string(),
            0,
            Some(pk),
            None,
            &eth_conf,
        );
        assert_eq!(
            mismatched.unwrap_err(),
            WalletErrors::InvalidAccountType,
            "must reject mismatched chain"
        );

        let missing_btc_chains =
            wallet.add_ledger_account("no chains".to_string(), 0, None, None, &offline_btc_conf);
        assert!(
            matches!(
                missing_btc_chains.unwrap_err(),
                WalletErrors::BincodeError(_)
            ),
            "must reject missing btc_chains for BTC"
        );
    }

    #[tokio::test]
    async fn test_add_ledger_account_non_btc_append_and_guards() {
        let (mut bg, _dir) = setup_test_background();

        let zil_conf = gen_zil_testnet_conf();
        bg.add_provider(zil_conf.clone()).unwrap();

        let kp0 = KeyPair::gen_sha256().unwrap();
        let pk0 = kp0.get_pubkey().unwrap();
        let addr0 = pk0.get_addr().unwrap();

        bg.add_ledger_wallet(
            BackgroundLedgerParams {
                ledger_id: vec![2],
                accounts: vec![(0u8, Some(pk0))],
                wallet_name: "ZIL Ledger".to_string(),
                account_names: vec!["ZIL Ledger 0".to_string()],
                wallet_index: 0,
                biometric_type: AuthMethod::None,
                wallet_settings: WalletSettings::default(),
                chain_hash: zil_conf.hash(),
                ftokens: vec![],
                btc_chains: HashMap::new(),
            },
            WalletSettings::default(),
        )
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data_before = wallet.get_wallet_data().unwrap();
        let accounts_before = data_before.get_accounts().unwrap();
        assert_eq!(accounts_before.len(), 1);
        assert_eq!(accounts_before[0].addr, addr0);
        assert!(accounts_before[0].pub_key.is_some());

        let kp1 = KeyPair::gen_sha256().unwrap();
        let pk1 = kp1.get_pubkey().unwrap();
        let expected_addr = pk1.get_addr().unwrap();

        wallet
            .add_ledger_account("ZIL Ledger 3".to_string(), 3, Some(pk1), None, &zil_conf)
            .unwrap();

        let data_after = wallet.get_wallet_data().unwrap();
        let accounts_after = data_after.get_accounts().unwrap();
        assert_eq!(accounts_after.len(), 2);

        let appended = &accounts_after[1];
        assert_eq!(appended.account_type.value(), 3);
        assert_eq!(appended.addr, expected_addr);
        assert!(appended.pub_key.is_some());
        assert_eq!(data_after.selected_account, data_before.selected_account);
        assert_eq!(data_after.bip, data_before.bip);

        let btc_conf = gen_btc_regtest_conf();
        let mismatched =
            wallet.add_ledger_account("BTC on ZIL wallet".to_string(), 0, None, None, &btc_conf);
        assert_eq!(
            mismatched.unwrap_err(),
            WalletErrors::InvalidAccountType,
            "must reject BTC account on ZIL ledger wallet"
        );

        let missing_pk = wallet.add_ledger_account("no pk".to_string(), 1, None, None, &zil_conf);
        assert!(
            matches!(missing_pk.unwrap_err(), WalletErrors::BincodeError(_)),
            "must reject missing pub_key for non-BTC"
        );
    }

    #[tokio::test]
    async fn test_add_ledger_account_rejects_non_ledger_wallet() {
        let (mut bg, _dir) = setup_test_background();

        let eth_conf = gen_eth_mainnet_conf();
        bg.add_provider(eth_conf.clone()).unwrap();

        let password: SecretString = SecretString::new(test_data::TEST_PASSWORD.into());
        let words = Background::gen_bip39(24).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: eth_conf.hash(),
            mnemonic_str: &words,
            accounts: &[(0, "ETH Account 0".to_string())],
            wallet_settings: WalletSettings::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BIP39 Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let kp = KeyPair::gen_keccak256().unwrap();
        let pk = kp.get_pubkey().unwrap();

        let rejected =
            wallet.add_ledger_account("Ledger on BIP39".to_string(), 0, Some(pk), None, &eth_conf);
        assert_eq!(
            rejected.unwrap_err(),
            WalletErrors::InvalidAccountType,
            "must reject add_ledger_account on non-Ledger wallet"
        );
    }
}
