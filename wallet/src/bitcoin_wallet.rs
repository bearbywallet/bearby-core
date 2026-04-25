use crate::{Result, Wallet, WalletAddrType};
use config::sha::SHA512_SIZE;
use config::storage::BTC_ADDRESSES_DB_KEY_V1;
use errors::wallet::WalletErrors;
use proto::btc_utils::{generate_btc_addresses, AddressChain, ByteCodec, GAP_LIMIT};
use rpc::network_config::ChainConfig;
use secrecy::SecretBox;
use std::collections::HashMap;

pub trait BitcoinWallet {
    type Error;

    fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;

    fn get_btc_addresses(
        &self,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;

    fn get_btc_addresses_db_key(key: &WalletAddrType) -> Vec<u8>;
}

impl BitcoinWallet for Wallet {
    type Error = WalletErrors;

    fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> Result<()> {
        let network = chain.bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin);
        let addresses = generate_btc_addresses(seed, account_index, network, 0, GAP_LIMIT)?;

        let stored: Vec<(u8, AddressChain)> = addresses
            .into_iter()
            .map(|(addr_type, chain)| (addr_type.to_byte(), chain))
            .collect();

        let key = Self::get_btc_addresses_db_key(&self.wallet_address);

        self.storage.set_versioned(&key, &stored)?;
        self.storage.flush()?;

        Ok(())
    }

    fn get_btc_addresses(&self) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let key = Self::get_btc_addresses_db_key(&self.wallet_address);
        let stored: Vec<(u8, AddressChain)> = self.storage.get_versioned(&key)?;

        let mut map = HashMap::with_capacity(stored.len());
        for (byte, chain) in stored {
            let addr_type = bitcoin::AddressType::from_byte(byte)
                .map_err(|_| WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(
                    format!("invalid address type byte: {}", byte)
                )))?;
            map.insert(addr_type, chain);
        }

        Ok(map)
    }

    #[inline]
    fn get_btc_addresses_db_key(key: &WalletAddrType) -> Vec<u8> {
        [key, BTC_ADDRESSES_DB_KEY_V1].concat()
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
    use config::{
        bip39::EN_WORDS,
        cipher::PROOF_SIZE,
        session::AuthMethod,
    };
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

    #[test]
    fn test_generate_and_load_btc_addresses() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            b"",
            &ARGON2_DEFAULT_CONFIG,
        )
        .unwrap();
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
        .unwrap();

        wallet.generate_wallet(&seed, 0, &chain_config).unwrap();

        let loaded = wallet.get_btc_addresses().unwrap();

        let expected =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT).unwrap();

        assert_eq!(loaded.len(), expected.len());

        for addr_type in [
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2sh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2tr,
        ] {
            let loaded_chain = loaded
                .get(&addr_type)
                .expect(&format!("missing type {:?}", addr_type));
            let expected_chain = expected
                .get(&addr_type)
                .expect(&format!("missing type {:?}", addr_type));

            assert_eq!(loaded_chain.external.len(), expected_chain.external.len());
            assert_eq!(loaded_chain.internal.len(), expected_chain.internal.len());

            for (loaded_entry, expected_entry) in loaded_chain
                .external
                .iter()
                .zip(expected_chain.external.iter())
            {
                assert_eq!(loaded_entry.address, expected_entry.address);
                assert_eq!(loaded_entry.path, expected_entry.path);
                assert_eq!(loaded_entry.history, expected_entry.history);
            }

            for (loaded_entry, expected_entry) in loaded_chain
                .internal
                .iter()
                .zip(expected_chain.internal.iter())
            {
                assert_eq!(loaded_entry.address, expected_entry.address);
                assert_eq!(loaded_entry.path, expected_entry.path);
                assert_eq!(loaded_entry.history, expected_entry.history);
            }
        }
    }
}
