use crate::{
    account::AccountV2, account_type::AccountType, bitcoin_wallet::BitcoinWallet,
    wallet_crypto::WalletCrypto, wallet_data::WalletDataV2, wallet_storage::StorageOperations,
    wallet_types::WalletTypes, Result, Wallet,
};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use crypto::bip49::DerivationPath;
use crypto::slip44;
use errors::wallet::WalletErrors;
use proto::btc_utils::AddressChain;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use rpc::network_config::ChainConfig;
use secrecy::SecretString;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[async_trait]
pub trait AccountManagement {
    type Error;

    fn update_ledger_accounts(
        &self,
        accounts: Vec<(u8, Option<PubKey>, proto::address::Address, String)>,
        chain: &ChainConfig,
        bip: u32,
    ) -> std::result::Result<(), Self::Error>;
    async fn add_next_bip39_account(
        &self,
        name: String,
        index: usize,
        passphrase: &SecretString,
        seed_bytes: &Argon2Seed,
        chains: &[ChainConfig],
    ) -> std::result::Result<(), Self::Error>;
    fn ensure_chain_accounts(
        &self,
        data: &mut WalletDataV2,
        target_slip44: u32,
        network: Option<bitcoin::Network>,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
    ) -> std::result::Result<(), Self::Error>;
    fn add_ledger_account(
        &self,
        name: String,
        ledger_index: u8,
        pub_key: Option<PubKey>,
        btc_chains: Option<HashMap<bitcoin::AddressType, AddressChain>>,
        chain_config: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;
    fn select_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
    fn delete_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl AccountManagement for Wallet {
    type Error = WalletErrors;

    fn delete_account(&self, account_index: usize) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        data.remove_account(account_index);
        let accounts = data.get_accounts()?;
        data.selected_account = accounts.len() - 1;
        self.save_wallet_data(&data)?;

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

        self.save_wallet_data(&data)?;

        Ok(())
    }

    fn ensure_chain_accounts(
        &self,
        data: &mut WalletDataV2,
        target_slip44: u32,
        network: Option<bitcoin::Network>,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
    ) -> Result<()> {
        let reference: Vec<(usize, &str)> = data
            .slip44_accounts
            .values()
            .flat_map(|bip_map| bip_map.values())
            .max_by_key(|accounts| accounts.len())
            .map(|accounts| {
                accounts
                    .iter()
                    .map(|a| (a.account_type.value(), a.name.as_str()))
                    .collect()
            })
            .unwrap_or_else(|| vec![(0, "")]);

        let target_bip = DerivationPath::default_bip(target_slip44);

        let existing: HashSet<usize> = data
            .slip44_accounts
            .get(&target_slip44)
            .and_then(|bip_map| bip_map.get(&target_bip))
            .map(|accounts| accounts.iter().map(|a| a.account_type.value()).collect())
            .unwrap_or_default();
        let missing: Vec<(usize, String)> = reference
            .into_iter()
            .filter(|(idx, _)| !existing.contains(idx))
            .map(|(idx, name)| (idx, name.to_owned()))
            .collect();

        let bip_map = data.slip44_accounts.entry(target_slip44).or_default();

        if missing.is_empty() {
            return Ok(());
        }

        match &data.wallet_type {
            WalletTypes::SecretKey => {
                let keypair = self.reveal_keypair(0, seed_bytes, passphrase)?;
                let sk = keypair.get_secretkey()?;
                let raw_key: [u8; 32] = sk.as_ref().try_into().map_err(|_| {
                    WalletErrors::FailToGetSKBytes(
                        errors::keypair::SecretKeyError::SecretKeySliceError,
                    )
                })?;

                let accounts = bip_map.entry(target_bip).or_default();
                for (storage_key, name) in missing {
                    let new_sk = match target_slip44 {
                        slip44::TRON => SecretKey::Secp256k1Tron(raw_key),
                        slip44::BITCOIN => {
                            let addr_type = DerivationPath::with_index(slip44::BITCOIN, (0, 0, 0))
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
            WalletTypes::SecretPhrase(_) => {
                let m = self.reveal_mnemonic(seed_bytes)?;
                let mnemonic_seed_secret = Arc::new(m.to_seed(passphrase)?);

                let accounts = bip_map.entry(target_bip).or_default();
                for (idx, name) in missing {
                    let path = if target_slip44 == slip44::BITCOIN {
                        DerivationPath::with_index(target_slip44, (idx, 0, 0))
                    } else {
                        DerivationPath::with_index(target_slip44, (0, 0, idx))
                    };
                    let account = AccountV2::from_hd(&mnemonic_seed_secret, name, &path, network)?;
                    accounts.push(account);
                }
            }
            _ => return Err(WalletErrors::InvalidAccountType),
        }

        Ok(())
    }

    fn add_ledger_account(
        &self,
        name: String,
        ledger_index: u8,
        pub_key: Option<PubKey>,
        btc_chains: Option<HashMap<bitcoin::AddressType, AddressChain>>,
        chain_config: &ChainConfig,
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;

        if data.wallet_type.code() != AccountType::Ledger(0).code() {
            return Err(WalletErrors::InvalidAccountType);
        }

        if chain_config.slip_44 != data.slip44 {
            return Err(WalletErrors::InvalidAccountType);
        }

        let target_bip = DerivationPath::default_bip(chain_config.slip_44);

        let storage_position = data
            .slip44_accounts
            .get(&chain_config.slip_44)
            .and_then(|m| m.get(&target_bip))
            .map(|v| v.len())
            .unwrap_or(0);

        if chain_config.slip_44 == slip44::BITCOIN {
            if let Some(chains) = btc_chains.as_ref() {
                self.save_btc_addresses(storage_position, chains, chain_config.hash())?;
            }
        }

        let account = AccountV2::from_ledger(
            ledger_index,
            name,
            pub_key,
            btc_chains.as_ref(),
            chain_config,
        )?;

        data.slip44_accounts
            .entry(chain_config.slip_44)
            .or_default()
            .entry(target_bip)
            .or_default()
            .push(account);

        self.save_wallet_data(&data)?;

        Ok(())
    }

    async fn add_next_bip39_account(
        &self,
        name: String,
        index: usize,
        passphrase: &SecretString,
        seed_bytes: &Argon2Seed,
        chains: &[ChainConfig],
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        let m = self.reveal_mnemonic(seed_bytes)?;
        let mnemonic_seed_secret = Arc::new(m.to_seed(passphrase)?);
        let wallet_chain_hash = data.chain_hash;
        let wallet_slip44 = data.slip44;

        let mut seen_slip44: HashSet<u32> = HashSet::new();
        for chain in chains.iter().filter(|c| seen_slip44.insert(c.slip_44)) {
            let slip44 = chain.slip_44;
            let effective_chain = if slip44 == wallet_slip44 {
                chains
                    .iter()
                    .find(|c| c.hash() == wallet_chain_hash)
                    .unwrap_or(chain)
            } else {
                chain
            };
            let bip = crypto::bip49::DerivationPath::default_bip(slip44);
            let network = effective_chain.bitcoin_network();

            let already_exists = data
                .slip44_accounts
                .get(&slip44)
                .and_then(|bip_map| bip_map.get(&bip))
                .is_some_and(|accounts| accounts.iter().any(|a| a.account_type.value() == index));
            if already_exists {
                #[cfg(debug_assertions)]
                eprintln!("[add-account] skip_existing slip44={slip44} index={index}");
                continue;
            }

            let hd_account = if slip44 == crypto::slip44::BITCOIN {
                self.generate_bip39_btc_account(
                    &mnemonic_seed_secret,
                    index,
                    name.clone(),
                    effective_chain,
                )
                .await?
            } else {
                let path = crypto::bip49::DerivationPath::with_index(slip44, (0, 0, index));
                AccountV2::from_hd(&mnemonic_seed_secret, name.clone(), &path, network)?
            };

            data.slip44_accounts
                .entry(slip44)
                .or_default()
                .entry(bip)
                .or_default()
                .push(hd_account);
        }

        self.save_wallet_data(&data)?;

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
        self.save_wallet_data(&data)?;

        Ok(())
    }
}
