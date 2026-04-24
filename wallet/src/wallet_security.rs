use crate::wallet_data::WalletDataV2;
use crate::wallet_storage::StorageOperations;
use crate::wallet_types::WalletTypes;
use crate::Result;
use crate::Wallet;
use cipher::argon2::{derive_key, Argon2Seed};
use cipher::keychain::KeyChain;
use config::cipher::{PROOF_SALT, PROOF_SIZE};
use errors::wallet::WalletErrors;

pub trait WalletSecurity {
    type Error;

    fn unlock(&self, seed_bytes: &Argon2Seed) -> std::result::Result<(), Self::Error>;
    fn migrate_salt(
        &self,
        seed_bytes: &Argon2Seed,
        new_seed_bytes: &Argon2Seed,
    ) -> std::result::Result<(), Self::Error>;
}

impl WalletSecurity for Wallet {
    type Error = WalletErrors;

    fn unlock(&self, seed_bytes: &Argon2Seed) -> Result<()> {
        self.unlock_iternel(seed_bytes)?;

        Ok(())
    }

    fn migrate_salt(
        &self,
        seed_bytes: &Argon2Seed,
        new_seed_bytes: &Argon2Seed,
    ) -> std::result::Result<(), Self::Error> {
        let data = self.get_wallet_data()?;
        let keychain = KeyChain::from_seed(seed_bytes)?;
        let new_keychain = KeyChain::from_seed(new_seed_bytes)?;

        match data.wallet_type {
            WalletTypes::SecretPhrase((entropy_key, _)) => {
                let entropy_storage_key = usize::to_le_bytes(entropy_key);
                let cipher_entropy = self.storage.get(&entropy_storage_key)?;
                let decrypted_entropy =
                    keychain.decrypt(cipher_entropy, &data.settings.cipher_orders)?;
                let new_cipher_entropy =
                    new_keychain.encrypt(decrypted_entropy, &data.settings.cipher_orders)?;
                self.storage
                    .set(&entropy_storage_key, &new_cipher_entropy)?;
            }
            WalletTypes::SecretKey => {
                let account = data.get_selected_account()?;
                let sk_storage_key = usize::to_le_bytes(account.account_type.value());
                let cipher_sk = self.storage.get(&sk_storage_key)?;
                let sk_bytes = keychain.decrypt(cipher_sk, &data.settings.cipher_orders)?;
                let new_cipher_sk = new_keychain.encrypt(sk_bytes, &data.settings.cipher_orders)?;
                self.storage.set(&sk_storage_key, &new_cipher_sk)?;
            }
            _ => return Err(WalletErrors::InvalidHexToWalletType),
        }

        self.update_proof_with_new_seed(new_seed_bytes, &new_keychain, &data)?;

        Ok(())
    }
}

impl Wallet {
    fn update_proof_with_new_seed(
        &self,
        new_seed_bytes: &Argon2Seed,
        new_keychain: &KeyChain,
        data: &WalletDataV2,
    ) -> Result<()> {
        let proof_storage_key = usize::to_le_bytes(data.proof_key);
        let argon2_config = data.settings.argon_params.into_config();
        let new_proof = derive_key(&new_seed_bytes[..PROOF_SIZE], PROOF_SALT, &argon2_config)
            .map_err(WalletErrors::ArgonCipherErrors)?;
        let new_cipher_proof = new_keychain.make_proof(&new_proof, &data.settings.cipher_orders)?;
        self.storage.set(&proof_storage_key, &new_cipher_proof)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests_security {
    use std::sync::Arc;

    use cipher::{argon2::derive_key, keychain::KeyChain, options::CipherOrders};
    use config::{bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};

    use errors::wallet::WalletErrors;
    use pqbip39::mnemonic::Mnemonic;
    use proto::keypair::KeyPair;
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::SecretString;
    use settings::wallet_settings::WalletSettings;
    use storage::LocalStorage;
    use test_data::{empty_passphrase, ANVIL_MNEMONIC, TEST_PASSWORD};

    use crate::{
        wallet_crypto::WalletCrypto, wallet_init::WalletInit, wallet_security::WalletSecurity,
        wallet_storage::StorageOperations, Bip39Params, SecretKeyParams, Wallet, WalletConfig,
    };

    fn gen_settings() -> WalletSettings {
        WalletSettings {
            argon_params: Default::default(),
            features: Default::default(),
            network: Default::default(),
            rates_api_options: Default::default(),
            cipher_orders: vec![CipherOrders::AESGCM256],
        }
    }

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[test]
    fn test_migrate_sk() {
        let (storage, _dir) = setup_test_storage();

        let settings = gen_settings();
        let argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            b"",
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            b"",
            &settings.argon_params.into_config(),
        )
        .unwrap();

        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0";
        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: name.to_string(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![],
        )
        .unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(
            data.slip44_accounts
                .get(&data.slip44)
                .map(|a| a.len())
                .unwrap_or(0),
            1
        );
        assert_eq!(
            wallet.reveal_mnemonic(&argon_seed),
            Err(WalletErrors::InvalidAccountType)
        );
        assert_eq!(
            wallet.reveal_keypair(0, &argon_seed, None),
            Ok(keypair.clone())
        );

        let new_salt = b"test_new_salty";
        let new_argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            new_salt,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        wallet.migrate_salt(&argon_seed, &new_argon_seed).unwrap();

        assert!(wallet.reveal_keypair(0, &argon_seed, None).is_err());
        assert_eq!(wallet.reveal_keypair(0, &new_argon_seed, None), Ok(keypair));
    }

    #[test]
    fn test_migrate_bip39() {
        let (storage, _dir) = setup_test_storage();
        let settings = gen_settings();
        let argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            b"",
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let indexes = [0, 1, 2].map(|i| (i, format!("Bitcoin Account {i}")));
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            b"",
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &indexes,
                wallet_name: "Bitcoin Wallet".to_string(),
                biometric_type: AuthMethod::None,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        assert_eq!(wallet.reveal_mnemonic(&argon_seed), Ok(mnemonic.clone()));

        let data = wallet.get_wallet_data().unwrap();

        let new_salt = b"test_new_salty";
        let new_argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            new_salt,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        wallet.migrate_salt(&argon_seed, &new_argon_seed).unwrap();

        assert!(wallet.reveal_mnemonic(&argon_seed).is_err());

        assert_eq!(wallet.reveal_mnemonic(&new_argon_seed), Ok(mnemonic));
    }
}
