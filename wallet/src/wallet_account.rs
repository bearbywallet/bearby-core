use crate::{
    account::AccountV2, account_type::AccountType, wallet_crypto::WalletCrypto,
    wallet_data::WalletDataV2, wallet_storage::StorageOperations, wallet_types::WalletTypes,
    Result, Wallet,
};
use cipher::argon2::Argon2Seed;
use crypto::bip49::{DerivationPath, DerivationType};
use crypto::slip44;
use errors::wallet::WalletErrors;
use proto::{pubkey::PubKey, secret_key::SecretKey};
use rpc::network_config::ChainConfig;
use secrecy::SecretString;
use std::collections::HashSet;
use std::sync::Arc;

pub trait AccountManagement {
    type Error;

    fn update_ledger_accounts(
        &self,
        accounts: Vec<(u8, Option<PubKey>, proto::address::Address, String)>,
        chain: &ChainConfig,
        bip: u32,
    ) -> std::result::Result<(), Self::Error>;
    fn add_next_bip39_account(
        &self,
        name: String,
        index: usize,
        network: Option<bitcoin::Network>,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
    ) -> std::result::Result<(), Self::Error>;
    fn ensure_chain_accounts(
        &self,
        data: &mut WalletDataV2,
        target_slip44: u32,
        network: Option<bitcoin::Network>,
        seed_bytes: &Argon2Seed,
        passphrase: &str,
    ) -> std::result::Result<(), Self::Error>;
    fn select_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
    fn delete_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
}

impl AccountManagement for Wallet {
    type Error = WalletErrors;

    fn delete_account(&self, account_index: usize) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        data.remove_account(account_index);
        let accounts = data.get_accounts()?;
        data.selected_account = accounts.len() - 1;
        self.save_wallet_data(data)?;

        Ok(())
    }

    fn update_ledger_accounts(
        &self,
        accounts: Vec<(u8, Option<PubKey>, proto::address::Address, String)>,
        chain: &ChainConfig,
        bip: u32,
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;

        if data.wallet_type.code() != AccountType::Ledger(0).code() {
            return Err(WalletErrors::InvalidAccountType);
        }

        let target_network = chain.bitcoin_network();
        let mut new_accounts = Vec::with_capacity(accounts.len());

        for (ledger_index, pub_key, addr, name) in accounts.into_iter() {
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
            new_accounts.push(AccountV2 {
                account_type: AccountType::Ledger(ledger_index as usize),
                addr,
                name,
                pub_key,
            });
        }

        data.slip44_accounts
            .entry(chain.slip_44)
            .or_default()
            .insert(bip, new_accounts);

        data.bip = bip;
        data.bip_preferences.insert(chain.slip_44, bip);

        self.save_wallet_data(data)?;

        Ok(())
    }

    fn ensure_chain_accounts(
        &self,
        data: &mut WalletDataV2,
        target_slip44: u32,
        network: Option<bitcoin::Network>,
        seed_bytes: &Argon2Seed,
        passphrase: &str,
    ) -> Result<()> {
        let reference: Vec<(usize, String)> = data
            .slip44_accounts
            .values()
            .flat_map(|bip_map| bip_map.values())
            .max_by_key(|accounts| accounts.len())
            .map(|accounts| {
                accounts
                    .iter()
                    .map(|a| (a.account_type.value(), a.name.clone()))
                    .collect()
            })
            .unwrap_or_else(|| vec![(0, String::new())]);

        let supported_bips = DerivationPath::supported_bips(target_slip44);
        let bip_map = data.slip44_accounts.entry(target_slip44).or_default();

        let mut missing_per_bip: Vec<(u32, Vec<(usize, String)>)> = Vec::new();
        for &bip in supported_bips {
            let existing: HashSet<usize> = bip_map
                .get(&bip)
                .map(|accounts| accounts.iter().map(|a| a.account_type.value()).collect())
                .unwrap_or_default();
            let missing: Vec<(usize, String)> = reference
                .iter()
                .filter(|(idx, _)| !existing.contains(idx))
                .cloned()
                .collect();
            if !missing.is_empty() {
                missing_per_bip.push((bip, missing));
            }
        }

        if missing_per_bip.is_empty() {
            return Ok(());
        }

        match &data.wallet_type {
            WalletTypes::SecretKey => {
                let keypair = self.reveal_keypair(0, seed_bytes, None)?;
                let sk = keypair.get_secretkey()?;
                let raw_key: [u8; 32] = sk.as_ref().try_into().map_err(|_| {
                    WalletErrors::FailToGetSKBytes(
                        errors::keypair::SecretKeyError::SecretKeySliceError,
                    )
                })?;

                for (bip, missing) in missing_per_bip {
                    let accounts = bip_map.entry(bip).or_default();
                    for (storage_key, name) in missing {
                        let new_sk = match target_slip44 {
                            slip44::TRON => SecretKey::Secp256k1Tron(raw_key),
                            slip44::BITCOIN => {
                                let addr_type = DerivationPath::new(
                                    slip44::BITCOIN,
                                    crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
                                    bip,
                                    None,
                                )
                                .get_address_type();
                                SecretKey::Secp256k1Bitcoin((
                                    raw_key,
                                    network.unwrap_or(bitcoin::Network::Bitcoin),
                                    addr_type,
                                ))
                            }
                            _ => SecretKey::Secp256k1Keccak256Ethereum(raw_key),
                        };
                        accounts.push(AccountV2::from_secret_key(
                            new_sk,
                            name,
                            storage_key,
                            target_slip44,
                        )?);
                    }
                }
            }
            WalletTypes::SecretPhrase(_) => {
                let m = self.reveal_mnemonic(seed_bytes)?;
                let mnemonic_seed_secret =
                    Arc::new(m.to_seed(&SecretString::from(passphrase))?);
                let eff_derivation_type = if target_slip44 == slip44::SOLANA {
                    2
                } else {
                    data.derivation_type
                };

                let mut handles = Vec::new();
                for (bip, missing) in missing_per_bip {
                    let seed = Arc::clone(&mnemonic_seed_secret);
                    let net = network;
                    handles.push(std::thread::spawn(
                        move || -> std::result::Result<(u32, Vec<AccountV2>), WalletErrors> {
                            let mut accounts = Vec::with_capacity(missing.len());
                            for (idx, name) in missing {
                                let derivation = crypto::bip49::DerivationType::with_index(
                                    eff_derivation_type,
                                    idx,
                                )?;
                                let path = DerivationPath::new(target_slip44, derivation, bip, net);
                                let account = AccountV2::from_hd(&seed, name, &path)?;
                                accounts.push(account);
                            }
                            Ok((bip, accounts))
                        },
                    ));
                }

                for handle in handles {
                    let (bip, new_accounts) =
                        handle.join().map_err(|_| WalletErrors::ThreadPanic)??;
                    bip_map.entry(bip).or_default().extend(new_accounts);
                }
            }
            _ => return Err(WalletErrors::InvalidAccountType),
        }

        Ok(())
    }

    fn add_next_bip39_account(
        &self,
        name: String,
        index: usize,
        network: Option<bitcoin::Network>,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        let m = self.reveal_mnemonic(seed_bytes)?;
        let mnemonic_seed_secret = m.to_seed(&SecretString::from(passphrase))?;
        let eff_derivation_type = if data.slip44 == slip44::SOLANA {
            2
        } else {
            data.derivation_type
        };
        let derivation = DerivationType::with_index(eff_derivation_type, index)?;
        let bip49 = DerivationPath::new(data.slip44, derivation, data.bip, network);
        let has_account = data
            .slip44_accounts
            .get(&data.slip44)
            .and_then(|bip_map| bip_map.get(&data.bip))
            .map(|accounts| {
                accounts
                    .iter()
                    .any(|account| account.account_type.value() == bip49.get_index())
            })
            .unwrap_or(false);

        if has_account {
            return Err(WalletErrors::ExistsAccount(bip49.get_index()));
        }

        let hd_account = AccountV2::from_hd(&mnemonic_seed_secret, name, &bip49)?;

        data.slip44_accounts
            .get_mut(&data.slip44)
            .and_then(|bip_map| bip_map.get_mut(&data.bip))
            .ok_or(WalletErrors::InvalidBIPPath(data.slip44, data.bip))?
            .push(hd_account);
        self.save_wallet_data(data)?;

        Ok(())
    }

    fn select_account(&self, account_index: usize) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        let accounts = data.get_accounts()?;

        if accounts.is_empty() {
            return Err(WalletErrors::NoAccounts);
        }

        if account_index >= accounts.len() {
            return Err(WalletErrors::InvalidAccountIndex(account_index));
        }

        data.selected_account = account_index;
        self.save_wallet_data(data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        wallet_account::AccountManagement, wallet_init::WalletInit,
        wallet_storage::StorageOperations, Bip39Params, Wallet, WalletConfig,
    };
    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};
    use crypto::bip49::DerivationPath;
    use errors::wallet::WalletErrors;
    use pqbip39::mnemonic::Mnemonic;
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::SecretString;
    use std::sync::Arc;
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

    #[test]
    fn test_select_account() {
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let (storage, _dir) = setup_test_storage();

        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();

        // Create wallet with 3 accounts
        let indexes = [0, 1, 2].map(|i| (i, format!("account {i}")));

        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();

        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                proof,
                mnemonic: &mnemonic,
                passphrase: PASSPHRASE,
                indexes: &indexes,
                wallet_name: "Select Account Test Wallet".to_string(),
                bip: DerivationPath::BIP44_PURPOSE,
                derivation_type: crypto::bip49::default_derivation_type(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .unwrap();
        let data = wallet.get_wallet_data().unwrap();

        // Test 1: Initial state should have account 0 selected
        assert_eq!(data.selected_account, 0);

        // Test 2: Successfully select valid account indices
        assert!(wallet.select_account(1).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 1);

        assert!(wallet.select_account(2).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 2);

        assert!(wallet.select_account(0).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0);

        // Test 3: Try to select invalid index (out of bounds)
        assert!(matches!(
            wallet.select_account(3),
            Err(WalletErrors::InvalidAccountIndex(3))
        ));
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0); // Should remain unchanged

        // Test 4: Try to select index way out of bounds
        assert!(matches!(
            wallet.select_account(999),
            Err(WalletErrors::InvalidAccountIndex(999))
        ));
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0); // Should remain unchanged

        // Test 5: Verify persistence after selection
        wallet.select_account(1).unwrap();

        let wallet_addr = wallet.wallet_address;
        let loaded_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();
        let data = loaded_wallet.get_wallet_data().unwrap();

        assert_eq!(data.selected_account, 1);
    }
}
