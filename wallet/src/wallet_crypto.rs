use std::sync::Arc;

use crate::{wallet_storage::StorageOperations, wallet_types::WalletTypes, Result, Wallet};
use cipher::{argon2::Argon2Seed, keychain::KeyChain};
use config::bip39::EN_WORDS;
use crypto::bip49::DerivationPath;
use errors::wallet::WalletErrors;
use network::{common::Provider, provider::NetworkProvider};
use pqbip39::mnemonic::Mnemonic;
use proto::{address::Address, keypair::KeyPair, secret_key::SecretKey, signature::Signature};
use secrecy::SecretString;

pub trait WalletCrypto {
    type Error;

    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<KeyPair, Self::Error>;
    fn reveal_mnemonic<'a>(
        &self,
        seed_bytes: &Argon2Seed,
    ) -> std::result::Result<Mnemonic<'a>, Self::Error>;
    fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<Signature, Self::Error>;
}

impl WalletCrypto for Wallet {
    type Error = WalletErrors;

    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<KeyPair> {
        let keychain = KeyChain::from_seed(seed_bytes)?;
        let data = self.get_wallet_data()?;

        match data.wallet_type {
            WalletTypes::SecretKey => {
                let account = data.get_account(account_index)?;
                let storage_key = usize::to_le_bytes(account.account_type.value());
                let cipher_sk = self.storage.get(&storage_key)?;
                let sk_bytes = keychain.decrypt(cipher_sk, &data.settings.cipher_orders)?;
                let sk = SecretKey::from_bytes(sk_bytes.into())?;
                let keypair = KeyPair::from_secret_key(sk)?;

                Ok(keypair)
            }
            WalletTypes::SecretPhrase((_key, is_phr)) => {
                if is_phr && passphrase.is_none() {
                    return Err(WalletErrors::PassphraseIsNone);
                }

                let account = data.get_account(account_index)?;
                let providers = NetworkProvider::load_network_configs(Arc::clone(&self.storage));

                let provider = providers
                    .iter()
                    .find(|&p| p.config.hash() == data.chain_hash)
                    .ok_or(WalletErrors::ProviderNotExist(data.chain_hash))?;
                let m = self.reveal_mnemonic(seed_bytes)?;
                let seed_secret = m.to_seed(&SecretString::from(passphrase.unwrap_or("")))?;
                let hd_index = account.account_type.value();
                let (bip_purpose, network) = match &account.addr {
                    Address::Secp256k1Bitcoin(_) => {
                        let purpose = account.addr.get_bip_purpose();
                        let net = account.addr.get_bitcoin_network()?;
                        (purpose, Some(net))
                    }
                    _ => (DerivationPath::BIP44_PURPOSE, None),
                };

                let derivation =
                    crypto::bip49::DerivationType::with_index(data.derivation_type, hd_index)?;
                let bip_path = crypto::bip49::DerivationPath::new(
                    provider.config.slip_44,
                    derivation,
                    bip_purpose,
                    network,
                );
                let mut keypair = KeyPair::from_bip39_seed(&seed_secret, &bip_path)?;

                match account.addr {
                    Address::Secp256k1Sha256(_) => {
                        keypair = keypair.to_sha256();
                    }
                    Address::Secp256k1Keccak256(_) => {
                        keypair = keypair.to_keccak256();
                    }
                    Address::Secp256k1Tron(_) => {
                        keypair = keypair.to_tron();
                    }
                    Address::Secp256k1Bitcoin(_) => {
                        let addr_type = account.addr.get_bitcoin_address_type()?;
                        let net = account.addr.get_bitcoin_network()?;
                        keypair = keypair.to_bitcoin(net, addr_type);
                    }
                    Address::Ed25519Solana(_) => {}
                }

                Ok(keypair)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn reveal_mnemonic<'a>(&self, seed_bytes: &Argon2Seed) -> Result<Mnemonic<'a>> {
        let data = self.get_wallet_data()?;

        match data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain = KeyChain::from_seed(seed_bytes)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher = self.storage.get(&storage_key)?;
                let decypted = keychain.decrypt(cipher, &data.settings.cipher_orders)?;

                // TODO: add more Languages
                // 32 this is max which can be entropy
                let m = if let Ok(mnemonic_str) = String::from_utf8(decypted.clone()) {
                    if let Ok(m) = Mnemonic::parse_str_without_checksum(
                        &EN_WORDS,
                        &SecretString::from(mnemonic_str),
                    ) {
                        m
                    } else {
                        Mnemonic::from_entropy(&EN_WORDS, &decypted)?
                    }
                } else {
                    Mnemonic::from_entropy(&EN_WORDS, &decypted)?
                };

                Ok(m)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<Signature> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let sig = keypair.sign_message(msg)?;
        let vrify = keypair.verify_sig(msg, &sig)?;

        if !vrify {
            return Err(WalletErrors::InvalidVerifySig);
        }

        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{wallet_init::WalletInit, Bip39Params, SecretKeyParams, Wallet, WalletConfig};
    use cipher::argon2::{derive_key, ARGON2_DEFAULT_CONFIG};
    use config::{argon::KEY_SIZE, cipher::PROOF_SIZE, session::AuthMethod};
    use crypto::{bip49::DerivationPath, slip44};
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::ExposeSecret;
    use storage::LocalStorage;
    use test_data::{ANVIL_MNEMONIC, TEST_PASSWORD};

    const PASSPHRASE: &str = "";

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    fn create_test_wallet_from_secret_key(
        storage: Arc<LocalStorage>,
        argon_seed: &Argon2Seed,
    ) -> Wallet {
        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();

        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();

        Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: "Wallet from SK".to_string(),
                bip: DerivationPath::BIP44_PURPOSE,
                biometric_type: AuthMethod::Biometric,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![],
        )
        .unwrap()
    }

    fn create_test_wallet_from_mnemonic(
        storage: Arc<LocalStorage>,
        argon_seed: &Argon2Seed,
        indexes: &[(usize, String)],
        chain_config: &ChainConfig,
        bip: u32,
    ) -> Wallet {
        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };

        let provider = NetworkProvider::new(chain_config.clone());
        NetworkProvider::save_network_configs(&[provider], Arc::clone(&storage)).unwrap();

        Wallet::from_bip39_words(
            Bip39Params {
                chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: PASSPHRASE,
                indexes,
                wallet_name: "Test Wallet".to_string(),
                bip,
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
                derivation_type: crypto::bip49::default_derivation_type(),
            },
            wallet_config,
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn test_reveal_keypair_from_secret_key() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let wallet = create_test_wallet_from_secret_key(Arc::clone(&storage), &argon_seed);

        // Reveal the keypair for account 0
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        // Verify the keypair can sign and verify messages
        let msg = b"test message";
        let sig = keypair.sign_message(msg).unwrap();
        let verified = keypair.verify_sig(msg, &sig).unwrap();

        assert!(verified);

        // Verify the address matches the account address
        let data = wallet.get_wallet_data().unwrap();
        let account_addr = &data.get_account(0).unwrap().addr;
        let keypair_addr = keypair.get_addr().unwrap();

        assert_eq!(account_addr, &keypair_addr);
    }

    #[test]
    fn test_reveal_keypair_from_secret_key_invalid_index() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let wallet = create_test_wallet_from_secret_key(Arc::clone(&storage), &argon_seed);

        // Try to reveal keypair for non-existent account
        let result = wallet.reveal_keypair(999, &argon_seed, None);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(WalletErrors::InvalidBIPPathIndex(_, _, 999))
        ));
    }

    #[test]
    fn test_reveal_keypair_zilliqa_bip44() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0, 1, 2].map(|i| (i, format!("Zilliqa Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::ZILLIQA;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        for i in 0..3 {
            let keypair = wallet.reveal_keypair(i, &argon_seed, None).unwrap();

            // Verify the address matches
            let data = wallet.get_wallet_data().unwrap();
            let account_addr = &data.get_account(i).unwrap().addr;
            let keypair_addr = keypair.get_addr().unwrap();

            assert_eq!(account_addr, &keypair_addr);

            // Verify it's a Zilliqa address (BIP39-derived Zilliqa accounts use Keccak256)
            assert!(matches!(keypair_addr, Address::Secp256k1Keccak256(_)));
        }
    }

    #[test]
    fn test_reveal_keypair_ethereum_bip44() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0, 1].map(|i| (i, format!("Ethereum Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::ETHEREUM;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        for i in 0..2 {
            let keypair = wallet.reveal_keypair(i, &argon_seed, None).unwrap();

            // Verify the address matches
            let data = wallet.get_wallet_data().unwrap();
            let account_addr = &data.get_account(i).unwrap().addr;
            let keypair_addr = keypair.get_addr().unwrap();

            assert_eq!(account_addr, &keypair_addr);

            // Verify it's an Ethereum address (Secp256k1Keccak256)
            assert!(matches!(keypair_addr, Address::Secp256k1Keccak256(_)));
        }
    }

    #[test]
    fn test_reveal_keypair_bitcoin_bip44_p2pkh() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Bitcoin BIP44 Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::BITCOIN;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let account_addr = &data.get_account(0).unwrap().addr;
        let keypair_addr = keypair.get_addr().unwrap();

        assert_eq!(account_addr, &keypair_addr);

        assert!(matches!(keypair_addr, Address::Secp256k1Bitcoin(_)));

        // Verify it's using P2pkh (legacy address starting with 1)
        let addr_str = keypair_addr.auto_format();
        assert!(addr_str.starts_with('1'));
    }

    #[test]
    fn test_reveal_keypair_bitcoin_bip49_p2sh() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Bitcoin BIP49 Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::BITCOIN;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP49_PURPOSE,
        );

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let account_addr = &data.get_account(0).unwrap().addr;
        let keypair_addr = keypair.get_addr().unwrap();

        assert_eq!(account_addr, &keypair_addr);

        assert!(matches!(keypair_addr, Address::Secp256k1Bitcoin(_)));

        // Verify it's using P2sh (nested SegWit address starting with 3)
        let addr_str = keypair_addr.auto_format();
        assert!(addr_str.starts_with('3'));
    }

    #[test]
    fn test_reveal_keypair_bitcoin_bip84_p2wpkh() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0, 1].map(|i| (i, format!("Bitcoin BIP84 Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::BITCOIN;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP84_PURPOSE,
        );

        for i in 0..2 {
            let keypair = wallet.reveal_keypair(i, &argon_seed, None).unwrap();

            // Verify the address matches
            let data = wallet.get_wallet_data().unwrap();
            let account_addr = &data.get_account(i).unwrap().addr;
            let keypair_addr = keypair.get_addr().unwrap();

            assert_eq!(account_addr, &keypair_addr);

            // Verify it's a Bitcoin address
            assert!(matches!(keypair_addr, Address::Secp256k1Bitcoin(_)));

            // Verify it's using P2wpkh (native SegWit address starting with bc1q)
            let addr_str = keypair_addr.auto_format();
            assert!(addr_str.starts_with("bc1q"));
        }
    }

    #[test]
    fn test_reveal_keypair_bitcoin_bip86_p2tr() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Bitcoin BIP86 Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::BITCOIN;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP86_PURPOSE,
        );

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let account_addr = &data.get_account(0).unwrap().addr;
        let keypair_addr = keypair.get_addr().unwrap();

        assert_eq!(account_addr, &keypair_addr);

        assert!(matches!(keypair_addr, Address::Secp256k1Bitcoin(_)));

        // Verify it's using P2tr (Taproot address starting with bc1p)
        let addr_str = keypair_addr.auto_format();
        assert!(addr_str.starts_with("bc1p"));
    }

    #[test]
    fn test_reveal_mnemonic_success() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::ZILLIQA;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        let revealed_mnemonic = wallet.reveal_mnemonic(&argon_seed).unwrap();

        assert_eq!(
            revealed_mnemonic.to_phrase().expose_secret(),
            ANVIL_MNEMONIC
        );
    }

    #[test]
    fn test_reveal_mnemonic_wrong_seed() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::ZILLIQA;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        let wrong_seed = [0u8; KEY_SIZE];
        let result = wallet.reveal_mnemonic(&wrong_seed);

        // Should fail with decryption error
        assert!(result.is_err());
    }

    #[test]
    fn test_reveal_mnemonic_on_secret_key_wallet() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let wallet = create_test_wallet_from_secret_key(Arc::clone(&storage), &argon_seed);

        // Try to reveal mnemonic on a SecretKey wallet
        let result = wallet.reveal_mnemonic(&argon_seed);

        // Should fail with InvalidAccountType error
        assert!(result.is_err());
        assert!(matches!(result, Err(WalletErrors::InvalidAccountType)));
    }

    #[test]
    fn test_sign_message_with_revealed_keypair() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::ZILLIQA;
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP44_PURPOSE,
        );

        let msg = b"Hello, Zilliqa!";
        let signature = wallet.sign_message(msg, 0, &argon_seed, None).unwrap();

        // Reveal the keypair and verify the signature
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let verified = keypair.verify_sig(msg, &signature).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_reveal_keypair_bitcoin_testnet() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let indexes = [0].map(|i| (i, format!("Bitcoin Testnet Account {i}")));

        let mut chain_config = ChainConfig::default();
        chain_config.slip_44 = slip44::BITCOIN;
        chain_config.testnet = Some(true);
        let wallet = create_test_wallet_from_mnemonic(
            Arc::clone(&storage),
            &argon_seed,
            &indexes,
            &chain_config,
            DerivationPath::BIP84_PURPOSE,
        );

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let account_addr = &data.get_account(0).unwrap().addr;
        let keypair_addr = keypair.get_addr().unwrap();

        assert_eq!(account_addr, &keypair_addr);

        let addr_str = keypair_addr.auto_format();
        assert!(addr_str.starts_with("tb1q"));
    }
}
