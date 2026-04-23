use crate::{
    bg_connections::ConnectionManagement, bg_provider::ProvidersManagement,
    bg_storage::StorageManagement, Background, BackgroundLedgerParams, Result,
};
use async_trait::async_trait;
use cipher::{
    argon2::{self, Argon2Seed},
    keychain::KeyChain,
};
use config::{
    bip39::EN_WORDS,
    cipher::{PROOF_SALT, PROOF_SIZE},
    session::AuthMethod,
};
use crypto::{bip49::DerivationPath, slip44};
use errors::{account::AccountErrors, background::BackgroundError, wallet::WalletErrors};
use pqbip39::mnemonic::Mnemonic;
use proto::pubkey::PubKey;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use session::management::{SessionManagement, SessionManager};
use settings::wallet_settings::WalletSettings;
use std::sync::Arc;
use wallet::{
    wallet_account::AccountManagement, wallet_init::WalletInit, wallet_security::WalletSecurity,
    wallet_storage::StorageOperations, Bip39Params, LedgerParams, SecretKeyParams, Wallet,
    WalletConfig,
};

use crate::{BackgroundBip39Params, BackgroundSKParams};

#[async_trait]
pub trait WalletManagement {
    type Error;

    async fn unlock_wallet_with_password(
        &self,
        password: &SecretString,
        device_indicators: Option<&[String]>,
        wallet_index: usize,
    ) -> std::result::Result<Argon2Seed, Self::Error>;

    async fn unlock_wallet_with_session(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<Argon2Seed, Self::Error>;

    async fn add_bip39_wallet<'a>(
        &'a mut self,
        params: BackgroundBip39Params<'_>,
    ) -> std::result::Result<(), Self::Error>;

    async fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
    ) -> std::result::Result<(), Self::Error>;

    async fn add_sk_wallet<'a>(
        &'a mut self,
        params: BackgroundSKParams<'_>,
    ) -> std::result::Result<(), Self::Error>;

    fn swap_zilliqa_chain(
        &self,
        wallet_index: usize,
        account_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    fn get_wallet_by_index(&self, wallet_index: usize)
        -> std::result::Result<&Wallet, Self::Error>;
    async fn set_biometric(
        &self,
        password: Option<&SecretString>,
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> std::result::Result<(), Self::Error>;

    fn delete_wallet(&mut self, wallet_index: usize) -> std::result::Result<(), Self::Error>;

    async fn select_bitcoin_address_format(
        &self,
        wallet_index: usize,
        new_bip: u32,
        password: Option<&SecretString>,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl WalletManagement for Background {
    type Error = BackgroundError;

    async fn set_biometric(
        &self,
        password: Option<&SecretString>,
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;

        let argon_seed = if data.biometric_type != AuthMethod::None && password.is_none() {
            self.unlock_wallet_with_session(wallet_index).await?
        } else if let Some(pass) = password {
            self.unlock_wallet_with_password(pass, None, wallet_index)
                .await?
        } else {
            return Err(BackgroundError::ProviderDepends(
                "invalid params".to_string(),
            ));
        };

        if new_biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        data.biometric_type = new_biometric_type;
        wallet.save_wallet_data(data)?;

        Ok(())
    }

    async fn unlock_wallet_with_password(
        &self,
        password: &SecretString,
        device_indicators: Option<&[String]>,
        wallet_index: usize,
    ) -> Result<Argon2Seed> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;

        let argon_seed = if let Some(device_indicators) = device_indicators {
            let device_indicator = device_indicators.join(":");
            let argon_seed = argon2::derive_key(
                password.expose_secret().as_bytes(),
                device_indicator.as_bytes(),
                &data.settings.argon_params.into_config(),
            )?;

            wallet.unlock(&argon_seed)?;

            let salt = session::device::get_device_signature();
            let new_argon_seed = argon2::derive_key(
                password.expose_secret().as_bytes(),
                &salt,
                &data.settings.argon_params.into_config(),
            )?;

            wallet.migrate_salt(&argon_seed, &new_argon_seed)?;

            if data.biometric_type != AuthMethod::None {
                let session = SessionManager::new(
                    Arc::clone(&self.storage),
                    0,
                    &wallet.wallet_address,
                    &data.settings.cipher_orders,
                );
                let secert_bytes = SecretSlice::new(new_argon_seed.into());

                session.create_session(secert_bytes).await?;
            }

            new_argon_seed
        } else {
            let salt = session::device::get_device_signature();
            let argon_seed = argon2::derive_key(
                password.expose_secret().as_bytes(),
                &salt,
                &data.settings.argon_params.into_config(),
            )?;

            wallet.unlock(&argon_seed)?;

            argon_seed
        };

        Ok(argon_seed)
    }

    async fn unlock_wallet_with_session(&self, wallet_index: usize) -> Result<Argon2Seed> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;

        let session = SessionManager::new(
            Arc::clone(&self.storage),
            0,
            &wallet.wallet_address,
            &data.settings.cipher_orders,
        );
        let seed_bytes: Argon2Seed = session
            .unlock_session()
            .await?
            .expose_secret()
            .to_vec()
            .try_into()
            .map_err(|_| {
                BackgroundError::SessionErrors(
                    errors::session::SessionErrors::InvalidDecryptSession,
                )
            })?;

        Ok(seed_bytes)
    }

    fn swap_zilliqa_chain(&self, wallet_index: usize, account_index: usize) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let account = data.get_mut_account(account_index)?;

        match &account.pub_key {
            Some(PubKey::Secp256k1Sha256(pub_key)) => {
                account.pub_key = Some(PubKey::Secp256k1Keccak256(*pub_key));
            }
            Some(PubKey::Secp256k1Keccak256(pub_key)) => {
                account.pub_key = Some(PubKey::Secp256k1Sha256(*pub_key));
            }
            _ => {
                return Err(AccountErrors::InvalidPubKeyType)?;
            }
        }

        let pk = account
            .pub_key
            .as_ref()
            .ok_or(AccountErrors::InvalidPubKeyType)?;
        account.addr = pk.get_addr()?;
        wallet.save_wallet_data(data)?;

        Ok(())
    }

    async fn add_bip39_wallet<'a>(&'a mut self, params: BackgroundBip39Params<'_>) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let chains: Vec<_> = self.get_providers().into_iter().map(|p| p.config).collect();
        let device_salt = session::device::get_device_signature();
        let argon_seed = argon2::derive_key(
            params.password.expose_secret().as_bytes(),
            &device_salt,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let mnemonic_str_secret = <&SecretString>::from(params.mnemonic_str);
        let mnemonic = if params.mnemonic_check {
            Mnemonic::parse_str(&EN_WORDS, &mnemonic_str_secret)?
        } else {
            Mnemonic::parse_str_without_checksum(&EN_WORDS, &mnemonic_str_secret)?
        };
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                proof,
                mnemonic: &mnemonic,
                passphrase: params.passphrase,
                indexes: params.accounts,
                wallet_name: params.wallet_name,
                biometric_type: params.biometric_type,
                chain_config: &provider.config,
                chains: &chains,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;
        self.storage.flush()?;

        Ok(())
    }

    async fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
    ) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_salt = session::device::get_device_signature();
        let argon_seed = argon2::derive_key(
            &device_salt,
            b"",
            &wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &wallet_settings.argon_params.into_config(),
        )?;

        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: wallet_settings,
        };
        let wallet = Wallet::from_ledger(
            LedgerParams {
                accounts: params.accounts,
                ledger_id: params.ledger_id,
                proof,
                account_names: params.account_names,
                wallet_name: params.wallet_name,
                wallet_index: params.wallet_index,
                bip: params.bip,
                chain_config: &provider.config,
                biometric_type: params.biometric_type,
                derivation_type: params.derivation_type,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(())
    }

    async fn add_sk_wallet<'a>(&'a mut self, params: BackgroundSKParams<'_>) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_salt = session::device::get_device_signature();
        let argon_seed = argon2::derive_key(
            params.password.expose_secret().as_bytes(),
            &device_salt,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk: params.secret_key,
                proof,
                wallet_name: params.wallet_name,
                bip: params.bip,
                biometric_type: params.biometric_type,
                chain_config: &provider.config,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(())
    }

    fn get_wallet_by_index(&self, wallet_index: usize) -> Result<&Wallet> {
        self.wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))
    }

    async fn select_bitcoin_address_format(
        &self,
        wallet_index: usize,
        new_bip: u32,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;

        if data.slip44 != slip44::BITCOIN {
            return Err(WalletErrors::InvalidBIPPath(data.slip44, new_bip).into());
        }

        if new_bip == data.bip {
            return Ok(());
        }

        let reference_len = data
            .slip44_accounts
            .values()
            .flat_map(|m| m.values())
            .map(|a| a.len())
            .max()
            .unwrap_or(0);
        let needs_derivation = data
            .slip44_accounts
            .get(&slip44::BITCOIN)
            .and_then(|bip_map| bip_map.get(&new_bip))
            .map(|accounts| accounts.len() < reference_len)
            .unwrap_or(true);

        if needs_derivation {
            let seed = if data.biometric_type != AuthMethod::None {
                self.unlock_wallet_with_session(wallet_index).await?
            } else if let Some(pass) = password {
                self.unlock_wallet_with_password(pass, None, wallet_index)
                    .await?
            } else {
                return Err(BackgroundError::AuthenticationRequired);
            };

            let provider = self.get_provider(data.chain_hash)?;
            wallet.ensure_chain_accounts(
                &mut data,
                slip44::BITCOIN,
                provider.config.bitcoin_network(),
                &seed,
                "",
            )?;
        }

        data.bip = new_bip;
        data.bip_preferences.insert(data.slip44, new_bip);
        wallet.save_wallet_data(data)?;

        Ok(())
    }

    fn delete_wallet(&mut self, wallet_index: usize) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_address = wallet.wallet_address;
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        wallet.clear_data()?;
        wallet.clear_history()?;
        wallet.clear_ftokens()?;
        self.clear_connection(wallet_index)?;

        indicators.retain(|&x| x != wallet_address);
        self.wallets.retain(|x| x.wallet_address != wallet_address);
        self.save_indicators(indicators)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use crate::{bg_crypto::CryptoOperations, bg_provider::ProvidersManagement};
    use crypto::{bip49::DerivationPath, slip44};
    use proto::{address::Address, keypair::KeyPair};
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use test_data::empty_passphrase;
    use wallet::wallet_account::AccountManagement;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_net_conf() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Test Network".to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["https://test.network".to_string()],
            features: vec![],
            slip_44: slip44::ZILLIQA,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password: SecretString = SecretString::new("shit password".into());
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(0, "Zilliqa wallet".to_string())];

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let words = Background::gen_bip39(24).unwrap();

        let accounts = [(1, "Eth Wallet".to_string()), (2, "account 1".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            accounts: &accounts,
            mnemonic_str: &words,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_wallet() {
        let (mut bg, dir) = setup_test_background();

        let password: SecretString = SecretString::new("shit password".into());
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(0, "Zilliqa wallet".to_string())];
        let keypair = KeyPair::gen_sha256().unwrap();

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: &password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        bg.add_sk_wallet(BackgroundSKParams {
            secret_key: keypair.get_secretkey().unwrap(),
            password: &password,
            chain_hash: net_conf.hash(),
            wallet_settings: Default::default(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 2);

        assert!(bg.delete_wallet(3).is_err());

        bg.delete_wallet(0).unwrap();
        assert_eq!(bg.wallets.len(), 1);
        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_zilliqa_legacy_accounts() {
        let (mut bg, _dir) = setup_test_background();
        let net_conf = create_test_net_conf();
        let password: SecretString = SecretString::new("shit password".into());
        let words = Background::gen_bip39(24).unwrap();

        bg.add_provider(net_conf.clone()).unwrap();

        let accounts = [(0, "Zilliqa wallet".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "Test Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        if let Address::Secp256k1Sha256(_) = wallet
            .get_wallet_data()
            .unwrap()
            .get_selected_account()
            .unwrap()
            .addr
        {
            assert!(true);
        } else {
            panic!("address should convert to legacy mode");
        }

        for i in 1..20 {
            wallet
                .add_next_bip39_account(format!("Zilliqa account {}", i), i, None, "", &argon_seed)
                .unwrap();

            bg.swap_zilliqa_chain(0, i).unwrap();
        }

        let data = wallet.get_wallet_data().unwrap();

        let accounts = data.get_accounts().unwrap();
        for acc in accounts {
            assert!(
                matches!(acc.addr, Address::Secp256k1Sha256(_)),
                "address should be in legacy mode"
            );
        }

        for i in 0..accounts.len() {
            bg.swap_zilliqa_chain(0, i).unwrap();
        }

        let data = wallet.get_wallet_data().unwrap();
        let accounts = data.get_accounts().unwrap();

        for acc in accounts {
            assert!(
                matches!(acc.addr, Address::Secp256k1Keccak256(_)),
                "address should be in evm mode"
            );
        }
    }

    #[tokio::test]
    async fn test_add_bitcoin_sk_wallet() {
        use test_data::{gen_btc_testnet_conf, TEST_PASSWORD};

        let (mut bg, _dir) = setup_test_background();
        let btc_conf = gen_btc_testnet_conf();
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Testnet, bitcoin::AddressType::P2wpkh).unwrap();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());

        bg.add_provider(btc_conf.clone()).unwrap();
        bg.add_sk_wallet(BackgroundSKParams {
            secret_key: keypair.get_secretkey().unwrap(),
            password: &password,
            chain_hash: btc_conf.hash(),
            wallet_settings: Default::default(),
            wallet_name: "Bitcoin Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP84_PURPOSE,
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.wallet_name, "Bitcoin Wallet");
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert!(matches!(
            data.get_selected_account().unwrap().addr,
            Address::Secp256k1Bitcoin(_)
        ));

        drop(bg);

        let bg = Background::from_storage_path(&_dir).unwrap();
        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let restored_data = wallet.get_wallet_data().unwrap();

        assert_eq!(restored_data.wallet_name, "Bitcoin Wallet");
        assert!(matches!(
            restored_data.get_selected_account().unwrap().addr,
            Address::Secp256k1Bitcoin(_)
        ));
    }

    #[tokio::test]
    async fn test_select_bitcoin_address_format() {
        use test_data::{gen_btc_testnet_conf, TEST_PASSWORD};

        let (mut bg, _dir) = setup_test_background();
        let btc_conf = gen_btc_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(0, "Bitcoin account".to_string())];

        bg.add_provider(btc_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: btc_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BTC Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);

        bg.select_bitcoin_address_format(0, DerivationPath::BIP86_PURPOSE, Some(&password))
            .await
            .unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            data.bip_preferences.get(&slip44::BITCOIN),
            Some(&DerivationPath::BIP86_PURPOSE)
        );

        bg.select_bitcoin_address_format(0, DerivationPath::BIP44_PURPOSE, Some(&password))
            .await
            .unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            data.bip_preferences.get(&slip44::BITCOIN),
            Some(&DerivationPath::BIP44_PURPOSE)
        );

        bg.select_bitcoin_address_format(0, DerivationPath::BIP49_PURPOSE, Some(&password))
            .await
            .unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP49_PURPOSE);
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            data.bip_preferences.get(&slip44::BITCOIN),
            Some(&DerivationPath::BIP49_PURPOSE)
        );
    }

    #[tokio::test]
    async fn test_select_bitcoin_address_format_with_extra_accounts() {
        use test_data::{gen_btc_testnet_conf, TEST_PASSWORD};

        let (mut bg, _dir) = setup_test_background();
        let btc_conf = gen_btc_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(0, "Bitcoin account".to_string())];

        bg.add_provider(btc_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: btc_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BTC Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let argon_seed = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        wallet
            .add_next_bip39_account(
                "Bitcoin account 1".to_string(),
                1,
                Some(bitcoin::Network::Testnet),
                "",
                &argon_seed,
            )
            .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.get_accounts().unwrap().len(), 2);

        bg.select_bitcoin_address_format(0, DerivationPath::BIP44_PURPOSE, Some(&password))
            .await
            .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);
        assert_eq!(data.get_accounts().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_select_bitcoin_address_format_not_bitcoin() {
        let (mut bg, _dir) = setup_test_background();
        let net_conf = create_test_net_conf();
        let password: SecretString = SecretString::new("test password".into());
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(0, "Account".to_string())];

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "ETH Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let result = bg
            .select_bitcoin_address_format(0, DerivationPath::BIP84_PURPOSE, Some(&password))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_select_bitcoin_address_format_same_bip() {
        use test_data::{gen_btc_testnet_conf, TEST_PASSWORD};

        let (mut bg, _dir) = setup_test_background();
        let btc_conf = gen_btc_testnet_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(0, "Bitcoin account".to_string())];

        bg.add_provider(btc_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            mnemonic_check: true,
            chain_hash: btc_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: "BTC Wallet".to_string(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        bg.select_bitcoin_address_format(0, DerivationPath::BIP84_PURPOSE, Some(&password))
            .await
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);
    }
}
