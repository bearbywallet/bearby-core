use crate::wallet_data::WalletDataV1;
use crate::wallet_data::WalletDataV2;
use crate::wallet_token::TokenManagement;
use crate::wallet_transaction::WalletTransaction;
use crate::Result;
use crate::Wallet;
use crate::WalletAddrType;
use errors::wallet::WalletErrors;
use history::transaction::HistoricalTransaction;
use rand::RngExt;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use storage::LocalStorage;
use token::ft::FToken;

pub trait StorageOperations {
    type Error;

    fn init_wallet(
        wallet_address: WalletAddrType,
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
    fn safe_storage_save(
        cipher_entropy: &[u8],
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<usize, Self::Error>;
    fn save_wallet_data(&self, data: WalletDataV2) -> std::result::Result<(), Self::Error>;
    fn save_ftokens(&self, ftokens: &[FToken]) -> std::result::Result<(), Self::Error>;
    fn add_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error>;
    fn save_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error>;
    fn get_wallet_data(&self) -> std::result::Result<WalletDataV2, Self::Error>;
    fn try_get_wallet_data(&self) -> Option<WalletDataV2>;
    fn get_history(&self) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;
    fn get_ftokens(&self) -> std::result::Result<Vec<FToken>, Self::Error>;
    fn clear_data(&self) -> std::result::Result<(), Self::Error>;
    fn clear_ftokens(&self) -> std::result::Result<(), Self::Error>;
    fn clear_history(&self) -> std::result::Result<(), Self::Error>;
}

impl StorageOperations for Wallet {
    type Error = WalletErrors;

    fn init_wallet(wallet_address: WalletAddrType, storage: Arc<LocalStorage>) -> Result<Self> {
        Ok(Self {
            storage,
            wallet_address,
        })
    }

    fn clear_data(&self) -> Result<()> {
        self.storage.remove(self.wallet_address.as_slice())?;

        Ok(())
    }

    fn clear_ftokens(&self) -> std::result::Result<(), Self::Error> {
        let ftokens_key = Wallet::get_token_db_key(&self.wallet_address);

        self.storage.remove(&ftokens_key)?;

        Ok(())
    }

    fn clear_history(&self) -> std::result::Result<(), Self::Error> {
        let history_db_key = Wallet::get_db_history_key(&self.wallet_address);

        self.storage.remove(&history_db_key)?;

        Ok(())
    }

    fn get_wallet_data(&self) -> Result<WalletDataV2> {
        match self
            .storage
            .get_versioned::<WalletDataV2>(self.wallet_address.as_slice())
        {
            Ok(data) => Ok(data),
            Err(_) => {
                let v1: WalletDataV1 = self
                    .storage
                    .get_versioned(self.wallet_address.as_slice())
                    .map_err(WalletErrors::from)?;
                let v2: WalletDataV2 = v1.into();
                self.save_wallet_data(v2.clone())?;
                Ok(v2)
            }
        }
    }

    fn try_get_wallet_data(&self) -> Option<WalletDataV2> {
        match self
            .storage
            .get_versioned::<WalletDataV2>(self.wallet_address.as_slice())
        {
            Ok(data) => Some(data),
            Err(_) => {
                let v1: WalletDataV1 = self
                    .storage
                    .get_versioned(self.wallet_address.as_slice())
                    .ok()?;
                let v2: WalletDataV2 = v1.into();
                self.save_wallet_data(v2.clone()).ok()?;
                Some(v2)
            }
        }
    }

    fn get_ftokens(&self) -> Result<Vec<FToken>> {
        let ftokens_key = Wallet::get_token_db_key(&self.wallet_address);
        match self.storage.get_versioned::<Vec<FToken>>(&ftokens_key) {
            Ok(tokens) => Ok(tokens),
            Err(_) => Ok(Vec::with_capacity(0)),
        }
    }

    fn get_history(&self) -> Result<Vec<HistoricalTransaction>> {
        let history_db_key = Wallet::get_db_history_key(&self.wallet_address);
        match self
            .storage
            .get_versioned::<Vec<HistoricalTransaction>>(&history_db_key)
        {
            Ok(history) => Ok(history),
            Err(_) => Ok(Vec::with_capacity(0)),
        }
    }

    fn safe_storage_save(cipher_entropy: &[u8], storage: Arc<LocalStorage>) -> Result<usize> {
        let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());
        let mut cipher_entropy_key: usize;

        loop {
            cipher_entropy_key = rng.random::<u64>() as usize;
            let key = usize::to_le_bytes(cipher_entropy_key);
            let is_exists_key = storage.exists(&key)?;

            if is_exists_key {
                continue;
            }

            storage.set(&key, cipher_entropy)?;

            break;
        }

        Ok(cipher_entropy_key)
    }

    fn save_wallet_data(&self, data: WalletDataV2) -> Result<()> {
        self.storage.set_versioned(&self.wallet_address, &data)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_ftokens(&self, ftokens: &[FToken]) -> std::result::Result<(), Self::Error> {
        let token_key = Wallet::get_token_db_key(&self.wallet_address);

        self.storage.set_versioned(&token_key, &ftokens)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error> {
        let history_db_key = Wallet::get_db_history_key(&self.wallet_address);

        self.storage.set_versioned(&history_db_key, &history)?;
        self.storage.flush()?;

        Ok(())
    }

    fn add_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error> {
        let new_history = {
            match self.get_history() {
                Ok(mut db_history) => {
                    db_history.extend_from_slice(history);
                    db_history
                }
                Err(_) => history.to_vec(),
            }
        };

        self.save_history(&new_history)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_wallet_storage {
    use super::*;
    use crate::{wallet_data::WalletDataV2, wallet_types::WalletTypes};
    use config::{session::AuthMethod, sha::SHA256_SIZE};
    use crypto::bip49::DerivationPath;
    use secrecy::SecretString;
    use settings::wallet_settings::WalletSettings;
    use std::collections::HashMap;
    use std::sync::Arc;
    use storage::LocalStorage;
    use token::ft::FToken;

    fn setup() -> (WalletAddrType, Arc<LocalStorage>) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let wallet_address = [42u8; SHA256_SIZE];
        let storage = Arc::new(LocalStorage::from(&dir).unwrap());

        (wallet_address, storage)
    }

    #[test]
    fn test_init_wallet() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage.clone());
        assert!(wallet.is_ok());

        let wallet = wallet.unwrap();
        assert_eq!(wallet.wallet_address, wallet_address);
    }

    #[test]
    fn test_safe_storage_save() {
        let (_, storage) = setup();
        let cipher_entropy = vec![1, 2, 3, 4, 5];

        let result = Wallet::safe_storage_save(&cipher_entropy, storage.clone());
        assert!(result.is_ok());

        let key = result.unwrap();
        let stored_data = storage.get(&usize::to_le_bytes(key));
        assert!(stored_data.is_ok());
        assert_eq!(stored_data.unwrap(), cipher_entropy);
    }

    #[test]
    fn test_wallet_data_operations() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        // Create test wallet data
        let test_data = WalletDataV2 {
            proof_key: 0,
            wallet_type: WalletTypes::SecretKey,
            settings: WalletSettings::default(),
            wallet_name: String::new(),
            slip44_accounts: HashMap::new(),
            slip44: 0,
            bip: DerivationPath::BIP44_PURPOSE,
            selected_account: 0,
            biometric_type: AuthMethod::None,
            chain_hash: 0,
            bip_preferences: HashMap::new(),
            derivation_type: crypto::bip49::default_derivation_type(),
        };

        // Test saving wallet data
        assert!(wallet.save_wallet_data(test_data.clone()).is_ok());

        // Test retrieving wallet data
        let retrieved_data = wallet.get_wallet_data();
        assert!(retrieved_data.is_ok());
        assert_eq!(retrieved_data.unwrap(), test_data);
    }

    #[test]
    fn test_ftoken_operations() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        // Create test tokens
        let test_tokens = vec![FToken::zil(0)];

        // Test saving tokens
        assert!(wallet.save_ftokens(&test_tokens).is_ok());

        // Test retrieving tokens
        let retrieved_tokens = wallet.get_ftokens();
        assert!(retrieved_tokens.is_ok());
        assert_eq!(retrieved_tokens.unwrap(), test_tokens);
    }

    #[test]
    fn test_v1_to_v2_migration() {
        use crate::account::{AccountV1, AccountV2};
        use crate::account_type::AccountType;
        use crate::wallet_data::WalletDataV1;
        use config::bip39::EN_WORDS;
        use crypto::bip49::DerivationPath;
        use crypto::slip44;
        use pqbip39::mnemonic::Mnemonic;
        use proto::pubkey::PubKey;
        use storage::data_warp::DataWarp;

        let (wallet_address, storage) = setup();
        let mnemonic =
            Mnemonic::parse_str(&EN_WORDS, &SecretString::from(test_data::ANVIL_MNEMONIC)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();
        let chain_hash: u64 = 777;
        let chain_id: u64 = 1;

        let bip84 = |index: usize| {
            DerivationPath::new(
                slip44::BITCOIN,
                crypto::bip49::DerivationType::AddressIndex(0, 0, index),
                DerivationPath::BIP84_PURPOSE,
                Some(bitcoin::Network::Bitcoin),
            )
        };

        let acc0_v2 = AccountV2::from_hd(&seed, "BTC 0".into(), &bip84(0)).unwrap();
        let acc1_v2 = AccountV2::from_hd(&seed, "BTC 1".into(), &bip84(1)).unwrap();
        let acc2_v2 = AccountV2::from_hd(&seed, "BTC 2".into(), &bip84(2)).unwrap();

        let make_v1 = |acc: &AccountV2, index: usize| AccountV1 {
            name: acc.name.clone(),
            account_type: AccountType::Bip39HD(index),
            addr: acc.addr.clone(),
            pub_key: PubKey::Secp256k1Keccak256([0u8; 33]),
            chain_hash,
            chain_id,
            slip_44: slip44::BITCOIN,
        };

        let acc0 = make_v1(&acc0_v2, 0);
        let acc1 = make_v1(&acc1_v2, 1);
        let acc2 = make_v1(&acc2_v2, 2);

        let v1_data = WalletDataV1 {
            proof_key: 42,
            wallet_type: WalletTypes::SecretPhrase((0, false)),
            settings: WalletSettings::default(),
            wallet_name: "BTC Wallet".into(),
            accounts: vec![acc0.clone(), acc1.clone(), acc2.clone()],
            selected_account: 1,
            biometric_type: AuthMethod::None,
            default_chain_hash: chain_hash,
        };

        let bincode_bytes = bincode::serialize(&v1_data).unwrap();
        let warp = DataWarp {
            payload: bincode_bytes,
            version: 0,
        };
        storage
            .set_raw(wallet_address.as_slice(), &warp.to_bytes())
            .unwrap();
        storage.flush().unwrap();

        let wallet = Wallet::init_wallet(wallet_address, storage.clone()).unwrap();
        let v2 = wallet.get_wallet_data().unwrap();

        assert_eq!(v2.slip44, slip44::BITCOIN);
        assert_eq!(v2.chain_hash, chain_hash);
        assert_eq!(v2.proof_key, 42);
        assert_eq!(v2.wallet_type, WalletTypes::SecretPhrase((0, false)));
        assert_eq!(v2.wallet_name, "BTC Wallet");
        assert_eq!(v2.selected_account, 1);
        assert_eq!(v2.biometric_type, AuthMethod::None);

        let bip_accounts = v2.slip44_accounts.get(&slip44::BITCOIN).unwrap();
        let accounts = bip_accounts.get(&DerivationPath::BIP84_PURPOSE).unwrap();
        assert_eq!(accounts.len(), 3);

        for (i, (v2_acc, v1_acc)) in accounts
            .iter()
            .zip([&acc0_v2, &acc1_v2, &acc2_v2])
            .enumerate()
        {
            assert_eq!(v2_acc.name, v1_acc.name);
            assert_eq!(v2_acc.addr, v1_acc.addr);
            assert_eq!(v2_acc.account_type, AccountType::Bip39HD(i));
            assert_eq!(v2_acc.pub_key, None);
        }

        let v2_reload = wallet.get_wallet_data().unwrap();
        assert_eq!(v2, v2_reload);

        let direct: WalletDataV2 = storage.get_versioned(wallet_address.as_slice()).unwrap();
        assert_eq!(direct, v2);
    }
}
