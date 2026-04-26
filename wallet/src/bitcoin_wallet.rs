use crate::{account::AccountV2, Result, Wallet, WalletAddrType};
use async_trait::async_trait;
use config::sha::SHA512_SIZE;
use config::storage::BTC_ADDRESSES_DB_KEY_V1;
use errors::wallet::WalletErrors;
use network::btc::BtcOperations;
use network::provider::NetworkProvider;
use proto::btc_utils::{generate_btc_addresses, AddressChain, ByteCodec, GAP_LIMIT};
use rpc::network_config::ChainConfig;
use secrecy::SecretBox;
use std::collections::HashMap;

const MAX_GAP_EXTENSIONS: u32 = 3;

#[async_trait]
pub trait BitcoinWallet {
    type Error;

    async fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        name: String,
        chain: &ChainConfig,
    ) -> std::result::Result<AccountV2, Self::Error>;

    fn get_btc_addresses(
        &self,
        account_index: usize,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;

    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize) -> Vec<u8>;
}

#[async_trait]
impl BitcoinWallet for Wallet {
    type Error = WalletErrors;

    async fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        name: String,
        chain: &ChainConfig,
    ) -> Result<AccountV2> {
        let network = chain.bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin);
        let provider = NetworkProvider::new(chain.clone());
        let preferred_type = bitcoin::AddressType::P2tr;

        let mut master: HashMap<bitcoin::AddressType, AddressChain> = HashMap::new();
        let mut next_start: u32 = 0;
        let mut scan_succeeded = false;
        let mut last_scan_view: Option<HashMap<bitcoin::AddressType, AddressChain>> = None;

        for _ in 0..MAX_GAP_EXTENSIONS {
            let batch =
                generate_btc_addresses(seed, account_index, network, next_start, GAP_LIMIT)?;

            for (addr_type, batch_chain) in batch {
                let target = master.entry(addr_type).or_insert_with(|| AddressChain {
                    external: Vec::new(),
                    internal: Vec::new(),
                });
                target.external.extend(batch_chain.external);
                target.internal.extend(batch_chain.internal);
            }
            next_start = next_start.saturating_add(GAP_LIMIT);

            let mut scan_view = master.clone();
            match provider.batch_script_get_history(&mut scan_view).await {
                Ok(()) => {
                    scan_succeeded = true;
                    let preferred = scan_view.get(&preferred_type).expect("seeded above");
                    let done =
                        preferred.get_external().is_ok() && preferred.get_internal().is_ok();
                    last_scan_view = Some(scan_view);
                    if done {
                        break;
                    }
                }
                Err(e) => {
                    println!("[generate_wallet] scan failed (offline?): {:?}", e);
                    break;
                }
            }
        }

        let to_persist = last_scan_view.as_ref().unwrap_or(&master);
        let stored: Vec<(u8, AddressChain)> = to_persist
            .iter()
            .map(|(addr_type, chain)| (addr_type.to_byte(), chain.clone()))
            .collect();
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index);
        self.storage.set_versioned(&key, &stored)?;

        let entry = if scan_succeeded {
            let view = last_scan_view.as_ref().expect("set on Ok branch");
            let preferred = view.get(&preferred_type).expect("seeded above");
            match preferred.get_external() {
                Ok(e) => e.clone(),
                Err(_) => {
                    println!(
                        "[generate_wallet] gap limit ({}) exceeded for account {} - wallet may have unscanned activity beyond this window",
                        MAX_GAP_EXTENSIONS * GAP_LIMIT,
                        account_index
                    );
                    master
                        .get(&preferred_type)
                        .expect("seeded above")
                        .external
                        .first()
                        .expect("non-empty after generation")
                        .clone()
                }
            }
        } else {
            master
                .get(&preferred_type)
                .expect("seeded above")
                .external
                .first()
                .expect("non-empty after generation")
                .clone()
        };

        let account = AccountV2::from_hd(seed, name, &entry.path, Some(network))?;
        Ok(account)
    }

    fn get_btc_addresses(
        &self,
        account_index: usize,
    ) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index);
        let stored: Vec<(u8, AddressChain)> = self.storage.get_versioned(&key)?;

        let mut map = HashMap::with_capacity(stored.len());
        for (byte, chain) in stored {
            let addr_type = bitcoin::AddressType::from_byte(byte).map_err(|_| {
                WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!(
                    "invalid address type byte: {}",
                    byte
                )))
            })?;
            map.insert(addr_type, chain);
        }

        Ok(map)
    }

    #[inline]
    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize) -> Vec<u8> {
        let idx_bytes = account_index.to_le_bytes();
        [key.as_slice(), BTC_ADDRESSES_DB_KEY_V1, idx_bytes.as_slice()].concat()
    }
}

#[cfg(test)]
mod tests_bitcoin_wallet {
    use super::*;
    use crate::{wallet_init::WalletInit, Bip39Params, WalletConfig};
    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};
    use pqbip39::mnemonic::Mnemonic;
    use rand::RngExt;
    use rpc::network_config::ChainConfig as RpcChainConfig;
    use secrecy::SecretString;
    use settings::wallet_settings::WalletSettings;
    use std::sync::Arc;
    use storage::LocalStorage;
    use test_data::{empty_passphrase, ANVIL_MNEMONIC, TEST_PASSWORD};

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[tokio::test]
    async fn test_generate_and_load_btc_addresses() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let indexes = [0].map(|i| (i, format!("BTC Account {i}")));
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings,
        };
        let chain_config = RpcChainConfig::default();

        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &indexes,
                wallet_name: "BTC Test Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let account = wallet
            .generate_wallet(&seed, 0, "BTC Account 0".to_string(), &chain_config)
            .await
            .unwrap();

        assert!(account.addr.auto_format().starts_with("bc1"));

        let loaded = wallet.get_btc_addresses(0).unwrap();
        assert!(loaded.contains_key(&bitcoin::AddressType::P2tr));
    }
}
