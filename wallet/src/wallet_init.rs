use crate::{
    account::{self, AccountV2},
    bitcoin_wallet::BitcoinWallet,
    wallet_data::WalletDataV2,
    wallet_types::WalletTypes,
    Result, SecretKeyParams, Wallet, WalletAddrType,
};
use async_trait::async_trait;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use config::sha::SHA256_SIZE;
use errors::{account::AccountErrors, wallet::WalletErrors};
use proto::pubkey::PubKey;
use secrecy::ExposeSecret;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use token::ft::FToken;

use crate::{wallet_storage::StorageOperations, Bip39Params, LedgerParams, WalletConfig};

#[async_trait]
pub trait WalletInit {
    type Error;

    fn from_ledger(
        params: LedgerParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    fn from_sk(
        params: SecretKeyParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    fn wallet_key_gen() -> WalletAddrType;

    async fn from_bip39_words(
        params: Bip39Params<'_>,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
}

#[async_trait]
impl WalletInit for Wallet {
    type Error = WalletErrors;

    fn wallet_key_gen() -> WalletAddrType {
        let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());
        let mut chacha_key = [0u8; SHA256_SIZE];

        rng.fill_bytes(&mut chacha_key);

        chacha_key
    }

    fn from_ledger(
        params: LedgerParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;

        drop(cipher_proof);

        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        let target_network = params.chain_config.bitcoin_network();
        let target_bip = crypto::bip49::DerivationPath::default_bip(params.chain_config.slip_44);
        let accounts: Vec<AccountV2> = params
            .accounts
            .into_iter()
            .zip(params.account_names.into_iter())
            .map(|((ledger_index, pub_key, addr), account_name)| {
                let pub_key = match pub_key {
                    Some(PubKey::Secp256k1Sha256(_)) => pub_key,
                    _ => None,
                };
                let addr = if let Some(network) = target_network {
                    match &addr {
                        proto::address::Address::Secp256k1Bitcoin(_) => {
                            addr.re_encode_btc_network(network)?
                        }
                        _ => addr,
                    }
                } else {
                    addr
                };
                Ok(AccountV2 {
                    account_type: crate::account_type::AccountType::Ledger(ledger_index as usize),
                    addr,
                    name: account_name,
                    pub_key,
                })
            })
            .collect::<std::result::Result<Vec<account::AccountV2>, AccountErrors>>()?;
        let slip44_accounts = HashMap::from([(
            params.chain_config.slip_44,
            HashMap::from([(target_bip, accounts)]),
        )]);

        let data = WalletDataV2 {
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: config.settings,
            slip44_accounts,
            slip44: params.chain_config.slip_44,
            wallet_type: WalletTypes::Ledger(params.ledger_id),
            selected_account: 0,
            chain_hash: params.chain_config.hash(),
            bip: target_bip,
            bip_preferences: HashMap::new(),
            derivation_type: 0,
        };
        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(wallet)
    }

    fn from_sk(
        params: SecretKeyParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let sk_as_bytes = params.sk.to_bytes()?;

        let cipher_sk = config
            .keychain
            .encrypt(sk_as_bytes.to_vec(), &config.settings.cipher_orders)?;
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key = Self::safe_storage_save(&cipher_sk, Arc::clone(&config.storage))?;
        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        let target_bip = crypto::bip49::DerivationPath::default_bip(params.chain_config.slip_44);

        // SecretKey may stores only one account.
        let account = AccountV2::from_secret_key(
            params.sk,
            params.wallet_name.to_owned(),
            cipher_entropy_key,
            params.chain_config.slip_44,
        )?;
        let slip44_accounts = HashMap::from([(
            params.chain_config.slip_44,
            HashMap::from([(target_bip, vec![account])]),
        )]);

        let data = WalletDataV2 {
            bip: target_bip,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: config.settings,
            slip44_accounts,
            slip44: params.chain_config.slip_44,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0,
            chain_hash: params.chain_config.hash(),
            bip_preferences: HashMap::new(),
            derivation_type: 0,
        };
        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(wallet)
    }

    async fn from_bip39_words(
        params: Bip39Params<'_>,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let mnemonic_phrase = params.mnemonic.to_phrase();
        let mnemonic_str: Vec<u8> = mnemonic_phrase.expose_secret().as_bytes().to_vec();
        let cipher_entropy = config
            .keychain
            .encrypt(mnemonic_str, &config.settings.cipher_orders)?;
        let mnemonic_seed_secret = Arc::new(params.mnemonic.to_seed(params.passphrase)?);
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key =
            Self::safe_storage_save(&cipher_entropy, Arc::clone(&config.storage))?;
        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        let target_bip = crypto::bip49::DerivationPath::default_bip(params.chain_config.slip_44);
        let chain_hash = params.chain_config.hash();

        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        let mut slip44_accounts: HashMap<u32, HashMap<u32, Vec<AccountV2>>> = HashMap::new();
        let mut seen_slip44: HashSet<u32> = HashSet::new();

        for chain in params
            .chains
            .iter()
            .filter(|c| seen_slip44.insert(c.slip_44))
        {
            let slip44 = chain.slip_44;
            let bip = crypto::bip49::DerivationPath::default_bip(slip44);
            let network = chain.bitcoin_network();
            let mut accounts = Vec::with_capacity(params.indexes.len());

            for (idx, name) in params.indexes.iter() {
                let account = if slip44 == crypto::slip44::BITCOIN {
                    wallet
                        .generate_wallet(&mnemonic_seed_secret, *idx, name.clone(), chain)
                        .await?
                } else {
                    let path = crypto::bip49::DerivationPath::with_index(slip44, (0, 0, *idx));
                    AccountV2::from_hd(&mnemonic_seed_secret, name.clone(), &path, network)?
                };
                accounts.push(account);
            }

            slip44_accounts
                .entry(slip44)
                .or_default()
                .insert(bip, accounts);
        }

        let data = WalletDataV2 {
            chain_hash,
            bip: target_bip,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type.clone(),
            proof_key,
            settings: config.settings,
            slip44_accounts,
            slip44: params.chain_config.slip_44,
            wallet_type: WalletTypes::SecretPhrase((
                cipher_entropy_key,
                !params.passphrase.expose_secret().is_empty(),
            )),
            selected_account: 0,
            bip_preferences: HashMap::new(),
            derivation_type: 0,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;
        wallet.storage.flush()?;

        Ok(wallet)
    }
}

#[cfg(test)]
mod tests_init_wallet {
    use std::sync::Arc;

    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{argon::KEY_SIZE, bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};
    use crypto::slip44;
    use errors::wallet::WalletErrors;
    use pqbip39::mnemonic::Mnemonic;
    use proto::keypair::KeyPair;
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::SecretString;
    use storage::LocalStorage;
    use test_data::{empty_passphrase, ANVIL_MNEMONIC, TEST_PASSWORD};

    use crate::{
        wallet_crypto::WalletCrypto, wallet_init::WalletInit, wallet_storage::StorageOperations,
        wallet_types::WalletTypes, Bip39Params, SecretKeyParams, Wallet, WalletConfig,
    };

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[tokio::test]
    async fn test_init_from_bip39_zil() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(|i| (i, format!("account {i}")));
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig {
            slip_44: slip44::ZILLIQA,
            ..Default::default()
        };
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &indexes,
                wallet_name: "Wllaet name".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();

        match data.wallet_type {
            WalletTypes::SecretPhrase((_, is_phr)) => {
                assert!(!is_phr);
            }
            _ => panic!("invalid type"),
        }

        assert_eq!(data.get_accounts().unwrap().len(), indexes.len());

        let wallet_addr = wallet.wallet_address;

        drop(wallet);

        let res_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();

        assert!(res_wallet.reveal_mnemonic(&[0u8; KEY_SIZE]).is_err());
        assert!(res_wallet.reveal_mnemonic(&argon_seed).is_ok());
    }

    #[tokio::test]
    async fn test_init_from_bip39_btc() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let indexes = [0, 1, 2].map(|i| (i, format!("Bitcoin Account {i}")));
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
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
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();

        let accounts = data.get_accounts().unwrap();
        assert_eq!(accounts.len(), indexes.len());

        for account in accounts {
            let addr_str = account.addr.auto_format();
            assert!(addr_str.starts_with("bc1"));
        }
    }

    #[test]
    fn test_init_from_sk() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();

        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0";
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
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

        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            wallet.reveal_mnemonic(&argon_seed),
            Err(WalletErrors::InvalidAccountType)
        );

        let wallet_address = wallet.wallet_address;
        let w = Wallet::init_wallet(wallet_address, Arc::clone(&storage)).unwrap();
        let w_data = w.get_wallet_data().unwrap();

        assert_eq!(w_data, data);
    }
}
