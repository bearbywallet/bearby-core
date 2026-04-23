use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use std::sync::Arc;

use async_trait::async_trait;
use cipher::{
    argon2::{self, Argon2Seed, ARGON2_DEFAULT_CONFIG},
    keychain::KeyChain,
    options::CipherOrders,
};
use config::{
    bip39::EN_WORDS,
    cipher::{PROOF_SALT, PROOF_SIZE},
    session::AuthMethod,
    sha::SHA256_SIZE,
    storage::{GLOBAL_SETTINGS_DB_KEY_V1, INDICATORS_DB_KEY_V1},
};
use errors::background::BackgroundError;
use pqbip39::mnemonic::Mnemonic;
use rpc::network_config::ChainConfig;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use session::management::{SessionManagement, SessionManager};
use settings::common_settings::CommonSettings;
use storage::codec;
use storage::LocalStorage;
use token::ft::FToken;
use wallet::{
    account_type::AccountType, wallet_crypto::WalletCrypto, wallet_data::{WalletDataV1, WalletDataV2},
    wallet_init::WalletInit, wallet_storage::StorageOperations, wallet_types::WalletTypes, Wallet,
    WalletAddrType,
};

use crate::Background;

pub const SIGNATURE: &[u8] = b"ZILPAY_BACKUP";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyStoreV0 {
    pub wallet_data: WalletDataV1,
    pub wallet_address: WalletAddrType,
    pub chain_config: ChainConfig,
    pub ftokens: Vec<FToken>,
    pub keys: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyStore {
    pub wallet_data: WalletDataV2,
    pub wallet_address: WalletAddrType,
    pub chain_config: ChainConfig,
    pub ftokens: Vec<FToken>,
    pub keys: Vec<u8>,
}

impl From<KeyStoreV0> for KeyStore {
    fn from(v0: KeyStoreV0) -> Self {
        Self {
            wallet_data: v0.wallet_data.into(),
            wallet_address: v0.wallet_address,
            chain_config: v0.chain_config,
            ftokens: v0.ftokens,
            keys: v0.keys,
        }
    }
}

impl KeyStore {
    pub fn from_backup(cipher_backup: Vec<u8>, argon_seed: &Argon2Seed) -> Result<KeyStore> {
        if cipher_backup.len() <= SIGNATURE.len() || &cipher_backup[..SIGNATURE.len()] != SIGNATURE
        {
            return Err(BackgroundError::InvalidBackupSignature);
        }

        if cipher_backup.len() <= SIGNATURE.len() + 1 {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let version = cipher_backup[SIGNATURE.len()];

        if cipher_backup.len() <= SIGNATURE.len() + 2 {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let cipher_orders_len = cipher_backup[SIGNATURE.len() + 1] as usize;

        if cipher_backup.len() < SIGNATURE.len() + 2 + cipher_orders_len {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let cipher_orders_start = SIGNATURE.len() + 2;
        let cipher_orders_end = cipher_orders_start + cipher_orders_len;
        let cipher_orders_bytes = &cipher_backup[cipher_orders_start..cipher_orders_end];

        let mut cipher_orders = Vec::with_capacity(cipher_orders_len);
        for &byte in cipher_orders_bytes {
            if let Ok(cipher) = CipherOrders::from_code(byte) {
                cipher_orders.push(cipher);
            } else {
                return Err(BackgroundError::InvalidBackupFormat);
            }
        }

        if cipher_orders.is_empty() {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let encrypted_data = cipher_backup[cipher_orders_end..].to_vec();

        let keychain = KeyChain::from_seed(argon_seed)?;
        let decrypted_data = keychain.decrypt(encrypted_data, &cipher_orders)?;

        match version {
            0 => {
                let keystore_v0: KeyStoreV0 = bincode::deserialize(&decrypted_data)?;
                Ok(keystore_v0.into())
            }
            1 => {
                let warp = storage::data_warp::DataWarp::from_bytes(decrypted_data.into())?;
                let keystore: KeyStore = codec::deserialize(&warp)?;
                Ok(keystore)
            }
            _ => Err(BackgroundError::UnsupportedBackupVersion(version)),
        }
    }
}

#[async_trait]
pub trait StorageManagement {
    type Error;

    fn from_storage_path(path: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings;
    fn get_indicators(storage: Arc<LocalStorage>) -> Vec<[u8; SHA256_SIZE]>;
    fn save_indicators(
        &self,
        indicators: Vec<[u8; SHA256_SIZE]>,
    ) -> std::result::Result<(), Self::Error>;
    fn save_settings(&self, settings: CommonSettings) -> std::result::Result<(), Self::Error>;
    async fn get_keystore(
        &self,
        wallet_index: usize,
        password: &SecretString,
    ) -> std::result::Result<Vec<u8>, Self::Error>;
    async fn load_keystore(
        &mut self,
        backup_cipher: Vec<u8>,
        password: &SecretString,
        biometric_type: AuthMethod,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl StorageManagement for Background {
    type Error = BackgroundError;

    async fn load_keystore(
        &mut self,
        backup_cipher: Vec<u8>,
        password: &SecretString,
        biometric_type: AuthMethod,
    ) -> Result<()> {
        let argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )?;
        let mut keystore = KeyStore::from_backup(backup_cipher, &argon_seed)?;

        {
            let providers = self.get_providers();

            if !providers
                .iter()
                .any(|p| p.config.hash() == keystore.chain_config.hash())
            {
                self.add_provider(keystore.chain_config)?;
            }
        }

        let device_salt = session::device::get_device_signature();
        let argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            &device_salt,
            &keystore.wallet_data.settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let argon_params = keystore.wallet_data.settings.argon_params.clone();
        let cipher_orders = keystore.wallet_data.settings.cipher_orders.clone();

        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &argon_params.into_config(),
        )?;
        let cipher_proof = keychain.make_proof(&proof, &cipher_orders)?;

        keystore.wallet_data.biometric_type = biometric_type.clone();

        match &mut keystore.wallet_data.wallet_type {
            WalletTypes::Ledger(_) => {
                let proof_key =
                    Wallet::safe_storage_save(&cipher_proof, Arc::clone(&self.storage))?;
                keystore.wallet_data.proof_key = proof_key;
            }
            WalletTypes::SecretKey => {
                let cipher_sk = keychain.encrypt(keystore.keys, &cipher_orders)?;
                let cipher_proof = keychain.make_proof(&proof, &cipher_orders)?;
                let proof_key =
                    Wallet::safe_storage_save(&cipher_proof, Arc::clone(&self.storage))?;
                let cipher_entropy_key =
                    Wallet::safe_storage_save(&cipher_sk, Arc::clone(&self.storage))?;

                keystore.wallet_data.proof_key = proof_key;

                if let Some(bip_accounts) = keystore
                    .wallet_data
                    .slip44_accounts
                    .get_mut(&keystore.wallet_data.slip44)
                {
                    if let Some(acc_list) = bip_accounts.get_mut(&keystore.wallet_data.bip) {
                        if let Some(acc) = acc_list.first_mut() {
                            acc.account_type = AccountType::PrivateKey(cipher_entropy_key);
                        }
                    }
                }
            }
            WalletTypes::SecretPhrase((storage_key, _)) => {
                let words = String::from_utf8(keystore.keys).map_err(|_| {
                    BackgroundError::Bip39Error(pqbip39::errors::Bip39Error::UnknownWord(0))
                })?;
                let mnemonic = Mnemonic::parse_str_without_checksum(
                    &EN_WORDS,
                    &SecretString::from(words),
                )?;
                let mnemonic_entropy: Vec<u8> = mnemonic.to_entropy().expose_secret().to_vec();
                let cipher_entropy = keychain.encrypt(mnemonic_entropy, &cipher_orders)?;
                let cipher_entropy_key =
                    Wallet::safe_storage_save(&cipher_entropy, Arc::clone(&self.storage))?;
                let proof_key =
                    Wallet::safe_storage_save(&cipher_proof, Arc::clone(&self.storage))?;

                keystore.wallet_data.proof_key = proof_key;
                *storage_key = cipher_entropy_key;
            }
        }

        let wallet_address: [u8; SHA256_SIZE] = Wallet::wallet_key_gen();
        let wallet = Wallet::from(Arc::clone(&self.storage), wallet_address);

        if keystore.wallet_data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &keystore.wallet_data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        wallet.save_wallet_data(keystore.wallet_data)?;
        wallet.save_ftokens(&keystore.ftokens)?;
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;
        self.storage.flush()?;

        Ok(())
    }

    async fn get_keystore(&self, wallet_index: usize, password: &SecretString) -> Result<Vec<u8>> {
        let argon_seed = self
            .unlock_wallet_with_password(password, None, wallet_index)
            .await?;
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_data = wallet.get_wallet_data()?;
        let ftokens = wallet.get_ftokens()?;
        let chain_config = self.get_provider(wallet_data.chain_hash)?.config;
        let cipher_orders = wallet_data.settings.cipher_orders.clone();
        let keys = match wallet_data.wallet_type {
            WalletTypes::Ledger(_) => Vec::with_capacity(0),
            WalletTypes::SecretPhrase((_, _)) => wallet
                .reveal_mnemonic(&argon_seed)?
                .to_phrase()
                .expose_secret()
                .as_bytes()
                .to_vec(),
            WalletTypes::SecretKey => wallet
                .reveal_keypair(0, &argon_seed, None)?
                .get_secretkey()?
                .to_bytes()?
                .to_vec(),
        };
        let keystore = KeyStore {
            wallet_data,
            chain_config,
            ftokens,
            keys,
            wallet_address: wallet.wallet_address,
        };
        let new_argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )?;

        let keystore_bytes = codec::serialize(&keystore)?.to_bytes();
        let keystore_version: u8 = 1;
        let keychain = KeyChain::from_seed(&new_argon_seed)?;
        let cipher_bytes = keychain.encrypt(keystore_bytes, &cipher_orders)?;
        let cipher_orders_bytes = cipher_orders.iter().map(|c| c.code()).collect::<Vec<u8>>();

        let total_len = SIGNATURE.len() + 1 + 1 + cipher_orders_bytes.len() + cipher_bytes.len();
        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(SIGNATURE);
        result.push(keystore_version);
        result.push(cipher_orders_bytes.len() as u8);
        result.extend(cipher_orders_bytes);
        result.extend(cipher_bytes);

        Ok(result)
    }

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings {
        storage
            .get_versioned::<CommonSettings>(GLOBAL_SETTINGS_DB_KEY_V1)
            .unwrap_or_default()
    }

    fn get_indicators(storage: Arc<LocalStorage>) -> Vec<[u8; SHA256_SIZE]> {
        storage
            .get(INDICATORS_DB_KEY_V1)
            .unwrap_or_default()
            .chunks(SHA256_SIZE)
            .map(|chunk| {
                let mut array = [0u8; SHA256_SIZE];
                array.copy_from_slice(chunk);
                array
            })
            .collect::<Vec<[u8; SHA256_SIZE]>>()
    }

    fn from_storage_path(path: &str) -> Result<Self> {
        let storage = LocalStorage::from(path)?;
        let storage = Arc::new(storage);
        let indicators = Self::get_indicators(Arc::clone(&storage));
        let mut wallets = Vec::with_capacity(indicators.len());
        let mut valid_indicators = Vec::with_capacity(indicators.len());

        for addr in &indicators {
            let w = Wallet::init_wallet(*addr, Arc::clone(&storage))?;

            if w.try_get_wallet_data().is_some() {
                wallets.push(w);
                valid_indicators.push(*addr);
            }
        }

        if valid_indicators.len() != indicators.len() {
            let bytes: Vec<u8> = valid_indicators
                .iter()
                .flat_map(|array| array.iter().cloned())
                .collect();
            storage.set(INDICATORS_DB_KEY_V1, &bytes)?;
            storage.flush()?;
        }

        Ok(Self { storage, wallets })
    }

    fn save_settings(&self, settings: CommonSettings) -> Result<()> {
        self.storage
            .set_versioned(GLOBAL_SETTINGS_DB_KEY_V1, &settings)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_indicators(&self, indicators: Vec<[u8; SHA256_SIZE]>) -> Result<()> {
        let bytes: Vec<u8> = indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage.set(INDICATORS_DB_KEY_V1, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_storage {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement, bg_wallet::WalletManagement,
        BackgroundBip39Params, BackgroundSKParams,
    };
    use crypto::{
        bip49::DerivationPath,
        slip44::{BITCOIN, ETHEREUM, ZILLIQA},
    };
    use proto::keypair::KeyPair;
    use rand::RngExt;
    use wallet::account::AccountV1;
    use wallet::account_type::AccountType;
    use wallet::wallet_data::WalletDataV1;

    use test_data::{
        empty_passphrase, gen_anvil_net_conf, gen_btc_mainnet_conf, gen_zil_mainnet_conf,
        ANVIL_MNEMONIC, TEST_PASSWORD,
    };

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_store_and_load_from_storage() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password: SecretString = SecretString::new("shit password".into());
        let words = Background::gen_bip39(12).unwrap();
        let accounts = [(0, "Name".to_string())];
        let net_conf = gen_anvil_net_conf();

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet_address = bg.wallets.first().unwrap().wallet_address;

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.first().unwrap().wallet_address, wallet_address);
    }

    #[tokio::test]
    async fn test_multiple_wallets() {
        let (mut bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("shit password".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(0, "Wallet1".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::from("Wallet1"),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        // Add second wallet
        let words2 = Background::gen_bip39(12).unwrap();
        let accounts2 = [(0, "Wallet2".to_string())];
        let password2: SecretString = SecretString::new("2 shit password".into());

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password2,
            chain_hash: net_conf.hash(),
            mnemonic_check: true,
            mnemonic_str: &words2,
            accounts: &accounts2,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::from("Wallet2"),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 2);
        assert_ne!(bg.wallets[0].wallet_address, bg.wallets[1].wallet_address);
    }

    #[tokio::test]
    async fn test_keystore_bip39() {
        let (mut bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("shit password".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(0, "keystore wallet".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::from("shit walelt"),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();
        let keystore_bytes = bg.get_keystore(0, &password).await.unwrap();
        let argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )
        .unwrap();
        let keystore = KeyStore::from_backup(keystore_bytes, &argon_seed).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let wallet_data = wallet.get_wallet_data().unwrap();

        assert_eq!(
            keystore.keys,
            words1.expose_secret().as_bytes().to_vec()
        );
        assert_eq!(keystore.chain_config, net_conf);
        assert_eq!(keystore.wallet_address, wallet.wallet_address);
        assert_eq!(keystore.wallet_data, wallet_data);
    }

    #[tokio::test]
    async fn test_keystore_key() {
        let (mut bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("shit password".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let keypair = KeyPair::gen_keccak256().unwrap();

        bg.add_sk_wallet(BackgroundSKParams {
            password: &password,
            secret_key: keypair.get_secretkey().unwrap(),
            wallet_name: "sk wallet".to_string(),
            biometric_type: AuthMethod::None,
            wallet_settings: Default::default(),
            chain_hash: net_conf.hash(),
            ftokens: net_conf.ftokens.clone(),
            bip: DerivationPath::BIP44_PURPOSE,
        })
        .await
        .unwrap();

        let keystore_bytes = bg.get_keystore(0, &password).await.unwrap();
        let argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )
        .unwrap();
        let keystore = KeyStore::from_backup(keystore_bytes, &argon_seed).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let wallet_data = wallet.get_wallet_data().unwrap();

        assert_eq!(
            keystore.keys,
            keypair.get_secretkey().unwrap().to_bytes().unwrap()
        );
        assert_eq!(keystore.chain_config, net_conf);
        assert_eq!(keystore.wallet_address, wallet.wallet_address);
        assert_eq!(keystore.wallet_data, wallet_data);
    }

    #[tokio::test]
    async fn test_load_from_keystore_bip39() {
        let (mut bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("shit password".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [
            (0, "keystore wallet 0".to_string()),
            (1, "keystore wallet 1".to_string()),
        ];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::from("shit walelt"),
            biometric_type: AuthMethod::None,
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let keystore_bytes = bg.get_keystore(0, &password).await.unwrap();

        bg.load_keystore(keystore_bytes, &password, AuthMethod::None)
            .await
            .unwrap();

        let wallet0 = bg.get_wallet_by_index(0).unwrap();
        let restored_wallet_data0 = wallet0.get_wallet_data().unwrap();

        let wallet1 = bg.get_wallet_by_index(1).unwrap();
        let restored_wallet_data1 = wallet1.get_wallet_data().unwrap();

        assert_ne!(
            restored_wallet_data0.proof_key,
            restored_wallet_data1.proof_key
        );
        assert_ne!(
            restored_wallet_data0.wallet_type,
            restored_wallet_data1.wallet_type
        );
        assert_eq!(
            restored_wallet_data0.settings,
            restored_wallet_data1.settings
        );
        assert_eq!(
            restored_wallet_data0.slip44_accounts,
            restored_wallet_data1.slip44_accounts
        );
        assert_eq!(
            restored_wallet_data0.wallet_name,
            restored_wallet_data1.wallet_name
        );
        assert_eq!(
            restored_wallet_data0.selected_account,
            restored_wallet_data1.selected_account
        );
        assert_eq!(restored_wallet_data0.biometric_type, AuthMethod::None);
        assert_eq!(restored_wallet_data1.biometric_type, AuthMethod::None);
        assert_eq!(
            restored_wallet_data0.chain_hash,
            restored_wallet_data1.chain_hash
        );

        let seed_bytes0 = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let seed_bytes1 = bg
            .unlock_wallet_with_password(&password, None, 1)
            .await
            .unwrap();

        let words0 = wallet0.reveal_mnemonic(&seed_bytes0).unwrap();
        let words1 = wallet1.reveal_mnemonic(&seed_bytes1).unwrap();

        assert_eq!(words1, words0);
    }

    #[tokio::test]
    async fn test_load_from_keystore_keypair() {
        let (mut bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("shit password".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let keypair = KeyPair::gen_keccak256().unwrap();

        bg.add_sk_wallet(BackgroundSKParams {
            password: &password,
            secret_key: keypair.get_secretkey().unwrap(),
            wallet_name: "sk wallet".to_string(),
            biometric_type: AuthMethod::None,
            wallet_settings: Default::default(),
            chain_hash: net_conf.hash(),
            ftokens: net_conf.ftokens.clone(),
            bip: DerivationPath::BIP44_PURPOSE,
        })
        .await
        .unwrap();

        let keystore_bytes = bg.get_keystore(0, &password).await.unwrap();

        bg.load_keystore(keystore_bytes, &password, AuthMethod::None)
            .await
            .unwrap();

        let wallet0 = bg.get_wallet_by_index(0).unwrap();
        let restored_wallet_data0 = wallet0.get_wallet_data().unwrap();

        let wallet1 = bg.get_wallet_by_index(1).unwrap();
        let restored_wallet_data1 = wallet1.get_wallet_data().unwrap();

        assert_ne!(
            restored_wallet_data0.proof_key,
            restored_wallet_data1.proof_key
        );
        assert_eq!(
            restored_wallet_data0.wallet_type,
            restored_wallet_data1.wallet_type
        );
        assert_eq!(
            restored_wallet_data0.settings,
            restored_wallet_data1.settings
        );
        let acc0 = restored_wallet_data0.get_account(0).unwrap();
        let acc1 = restored_wallet_data1.get_account(0).unwrap();

        assert_ne!(acc0.account_type, acc1.account_type);
        assert_eq!(acc0.name, acc1.name);
        assert_eq!(acc0.addr, acc1.addr);
        assert_eq!(acc0.pub_key, acc1.pub_key);
        assert_eq!(
            restored_wallet_data0.wallet_name,
            restored_wallet_data1.wallet_name
        );
        assert_eq!(
            restored_wallet_data0.selected_account,
            restored_wallet_data1.selected_account
        );
        assert_eq!(restored_wallet_data1.biometric_type, AuthMethod::None);
        assert_eq!(
            restored_wallet_data0.chain_hash,
            restored_wallet_data1.chain_hash
        );

        let seed_bytes0 = bg
            .unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let seed_bytes1 = bg
            .unlock_wallet_with_password(&password, None, 1)
            .await
            .unwrap();

        let keypair0 = wallet0.reveal_keypair(0, &seed_bytes0, None).unwrap();
        let keypair1 = wallet1.reveal_keypair(0, &seed_bytes1, None).unwrap();

        assert_eq!(keypair0, keypair1);
    }

    #[tokio::test]
    async fn test_data_bip39() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let eth = gen_anvil_net_conf();
        let btc = gen_btc_mainnet_conf();
        let zil = gen_zil_mainnet_conf();

        bg.add_provider(eth.clone()).unwrap();
        bg.add_provider(btc.clone()).unwrap();
        bg.add_provider(zil.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string()), (1, "acc 1".to_string())];

        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: btc.ftokens.clone(),
            bip: DerivationPath::BIP86_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.slip44, BITCOIN);
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
        assert_eq!(data.selected_account, 0);
        assert_eq!(data.chain_hash, btc.hash());
        assert_eq!(data.get_accounts().unwrap().len(), 2);

        let check_account =
            |acc: &wallet::account::AccountV2, name: &str, index: usize, addr: &str| {
                assert_eq!(acc.name, name);
                assert_eq!(acc.account_type, AccountType::Bip39HD(index));
                assert_eq!(acc.addr.to_string(), addr);
            };

        let btc = &data.slip44_accounts[&0];
        assert_eq!(btc.len(), 4);
        assert!(btc.contains_key(&44));
        assert!(btc.contains_key(&49));
        assert!(btc.contains_key(&84));
        assert!(btc.contains_key(&86));

        let bip44_btc = &btc[&44];
        assert_eq!(bip44_btc.len(), 2);
        check_account(
            &bip44_btc[0],
            "acc 0",
            0,
            "1Ei9UmLQv4o4UJTy5r5mnGFeC9auM3W5P1",
        );
        check_account(
            &bip44_btc[1],
            "acc 1",
            1,
            "14RBPsg6mBkLSJokkzeuoCkTtoeD3nK2Kz",
        );
        assert!(bip44_btc[0].pub_key.is_none());
        assert!(bip44_btc[1].pub_key.is_none());

        let bip49_btc = &btc[&49];
        assert_eq!(bip49_btc.len(), 2);
        check_account(
            &bip49_btc[0],
            "acc 0",
            0,
            "39sr5B8UAdxeoXbnpdw4frfxXwWwEChwzp",
        );
        check_account(
            &bip49_btc[1],
            "acc 1",
            1,
            "37EtUYWDGFUYhF65JqZMkkiUd4dDmwHv8J",
        );
        assert!(bip49_btc[0].pub_key.is_none());
        assert!(bip49_btc[1].pub_key.is_none());

        let bip84_btc = &btc[&84];
        assert_eq!(bip84_btc.len(), 2);
        check_account(
            &bip84_btc[0],
            "acc 0",
            0,
            "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te",
        );
        check_account(
            &bip84_btc[1],
            "acc 1",
            1,
            "bc1qp533522veg9uyhpx3sva9vqrnfzmt262n4lsuq",
        );
        assert!(bip84_btc[0].pub_key.is_none());
        assert!(bip84_btc[1].pub_key.is_none());

        let bip86_btc = &btc[&86];
        assert_eq!(bip86_btc.len(), 2);
        check_account(
            &bip86_btc[0],
            "acc 0",
            0,
            "bc1pfzhx49qe6s5exppe5hqljg3n6587xk0w75xqr70pgdt7ygnfkssqxqjd9l",
        );
        check_account(
            &bip86_btc[1],
            "acc 1",
            1,
            "bc1p0lks35d0spqsvz2t3t0kqus38wrlpmcjtvvupkfkwdrzfh6zjyps9rvd6v",
        );
        assert!(bip86_btc[0].pub_key.is_none());
        assert!(bip86_btc[1].pub_key.is_none());

        let eth = &data.slip44_accounts.get(&ETHEREUM).unwrap();
        assert_eq!(eth.len(), 1);
        assert!(eth.contains_key(&DerivationPath::BIP44_PURPOSE));
        let bip44_eth = &eth[&DerivationPath::BIP44_PURPOSE];
        assert_eq!(bip44_eth.len(), 2);
        check_account(
            &bip44_eth[0],
            "acc 0",
            0,
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        );
        check_account(
            &bip44_eth[1],
            "acc 1",
            1,
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        );
        assert!(bip44_eth[0].pub_key.is_none());
        assert!(bip44_eth[1].pub_key.is_none());

        let zil = &data.slip44_accounts[&ZILLIQA];
        assert_eq!(zil.len(), 1);
        assert!(zil.contains_key(&DerivationPath::BIP44_PURPOSE));
        let bip44_zil = &zil[&DerivationPath::BIP44_PURPOSE];
        assert_eq!(bip44_zil.len(), 2);
        check_account(
            &bip44_zil[0],
            "acc 0",
            0,
            "0xBE9390B088c7651Af28751CEb84e233Be3B8162D",
        );
        check_account(
            &bip44_zil[1],
            "acc 1",
            1,
            "0x9E546758fBDcdCd3926d946ad628d0ED7A419106",
        );
        assert_eq!(
            bip44_zil[0].pub_key.clone().unwrap().to_string(),
            "0102d8855750cd4a1b807e1f88069781d8197b7743b51c00e57e72f66258fa6c2333"
        );
        assert_eq!(
            bip44_zil[1].pub_key.clone().unwrap().to_string(),
            "01036f38095333ea8c152dd909aea1fd2c381e3bd4628bc2a391ad82d0c238d9bddd"
        );

        let selected = data.get_selected_account().unwrap();
        assert_eq!(selected.name, "acc 0");
        assert_eq!(
            selected.addr.to_string(),
            "bc1pfzhx49qe6s5exppe5hqljg3n6587xk0w75xqr70pgdt7ygnfkssqxqjd9l"
        );

        let acc1 = data.get_account(1).unwrap();
        assert_eq!(acc1.name, "acc 1");
        assert_eq!(
            acc1.addr.to_string(),
            "bc1p0lks35d0spqsvz2t3t0kqus38wrlpmcjtvvupkfkwdrzfh6zjyps9rvd6v"
        );
        assert!(data.get_account(99).is_err());

        let accounts = data.get_accounts().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].name, "acc 0");
        assert_eq!(accounts[1].name, "acc 1");

        let mut data = wallet.get_wallet_data().unwrap();

        data.slip44 = ETHEREUM;
        data.bip = DerivationPath::BIP44_PURPOSE;
        let eth_selected = data.get_selected_account().unwrap();
        assert_eq!(
            eth_selected.addr.to_string(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        let eth_accounts = data.get_accounts().unwrap();
        assert_eq!(eth_accounts.len(), 2);

        data.slip44 = ZILLIQA;
        let zil_acc = data.get_account(0).unwrap();
        assert_eq!(
            zil_acc.addr.to_string(),
            "0xBE9390B088c7651Af28751CEb84e233Be3B8162D"
        );

        data.slip44 = 9999;
        assert!(data.get_selected_account().is_err());
        assert!(data.get_accounts().is_err());

        data.slip44 = 0;
        data.bip = DerivationPath::BIP86_PURPOSE;
        data.remove_account(1);
        for bip_map in data.slip44_accounts.values() {
            for accounts in bip_map.values() {
                assert_eq!(accounts.len(), 1);
                assert_eq!(accounts[0].name, "acc 0");
            }
        }

        data.remove_account(0);
        for bip_map in data.slip44_accounts.values() {
            for accounts in bip_map.values() {
                assert!(accounts.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_keystore_v0_import() {
        let (bg, _) = setup_test_background();
        let net_conf = gen_anvil_net_conf();
        let password: SecretString = SecretString::new("test password v0".into());

        bg.add_provider(net_conf.clone()).unwrap();

        let words = Background::gen_bip39(12).unwrap();
        let accounts_v1 = vec![AccountV1 {
            name: "v0 account".to_string(),
            account_type: AccountType::Bip39HD(0),
            addr: proto::address::Address::from_str_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
            pub_key: proto::pubkey::PubKey::Secp256k1Keccak256([0u8; 33]),
            chain_hash: net_conf.hash(),
            chain_id: 1,
            slip_44: ETHEREUM,
        }];

        let wallet_data_v1 = WalletDataV1 {
            proof_key: 0,
            wallet_type: WalletTypes::SecretPhrase((0, Default::default())),
            settings: Default::default(),
            wallet_name: "v0 wallet".to_string(),
            accounts: accounts_v1,
            selected_account: 0,
            biometric_type: AuthMethod::None,
            default_chain_hash: net_conf.hash(),
        };

        let keystore_v0 = KeyStoreV0 {
            wallet_data: wallet_data_v1,
            wallet_address: [0u8; SHA256_SIZE],
            chain_config: net_conf.clone(),
            ftokens: vec![],
            keys: words.expose_secret().as_bytes().to_vec(),
        };

        let keystore_bytes = bincode::serialize(&keystore_v0).unwrap();

        let argon_seed = argon2::derive_key(
            password.expose_secret().as_bytes(),
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let cipher_orders = vec![CipherOrders::AESGCM256];
        let cipher_bytes = keychain.encrypt(keystore_bytes, &cipher_orders).unwrap();
        let cipher_orders_bytes: Vec<u8> = cipher_orders.iter().map(|c| c.code()).collect();

        let mut backup_v0 = Vec::with_capacity(
            SIGNATURE.len() + 1 + 1 + cipher_orders_bytes.len() + cipher_bytes.len(),
        );
        backup_v0.extend_from_slice(SIGNATURE);
        backup_v0.push(0); // version 0
        backup_v0.push(cipher_orders_bytes.len() as u8);
        backup_v0.extend(cipher_orders_bytes);
        backup_v0.extend(cipher_bytes);

        let restored = KeyStore::from_backup(backup_v0, &argon_seed).unwrap();

        assert_eq!(restored.keys, words.expose_secret().as_bytes().to_vec());
        assert_eq!(restored.chain_config, net_conf);
        assert_eq!(restored.wallet_data.wallet_name, "v0 wallet");
        assert_eq!(restored.wallet_data.slip44, ETHEREUM);
    }
}
