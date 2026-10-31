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
use crypto::bip49::{DerivationPath, DerivationType};
use errors::{account::AccountErrors, background::BackgroundError};
use network::{btc::BtcOperations, provider::NetworkProvider};
use pqbip39::mnemonic::Mnemonic;
use proto::{
    address::Address,
    btc_utils::{AddressChain, BtcAddressEntry},
    pubkey::PubKey,
    U256,
};
use rpc::network_config::ChainConfig;
use secrecy::{ExposeSecret, SecretBox, SecretSlice, SecretString};
use session::management::{SessionManagement, SessionManager};
use settings::wallet_settings::WalletSettings;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use token::ft::FToken;
use wallet::{
    account::AccountV2, bitcoin_wallet::BitcoinWallet, wallet_account::AccountManagement,
    wallet_init::WalletInit, wallet_security::WalletSecurity, wallet_storage::StorageOperations,
    Bip39Params, LedgerParams, SecretKeyParams, Wallet, WalletConfig,
};

use crate::{BackgroundBip39Params, BackgroundSKParams};

const RECOVERY_CACHE_TTL_SECS: u64 = 86_400;
const RECOVERY_SUB_BATCH_SIZE: usize = 25;

static RECOVERY_CACHE_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
static RECOVERY_SEED_CACHE: std::sync::LazyLock<
    std::sync::Mutex<Option<([u8; 32], [u8; 64])>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Bip39ChainBalance {
    pub chain_name: String,
    pub chain_hash: u64,
    pub slip44: u32,
    pub addr: String,
    pub symbol: String,
    pub balance: String,
    pub decimals: u8,
    pub tx_count: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Bip39DiscoveredAccount {
    pub index: u32,
    pub addr: String,
    pub legacy_addr: Option<String>,
    pub balance: String,
    pub decimals: u8,
    pub symbol: String,
    pub tx_count: u32,
    pub has_activity: bool,
    pub chain_balances: Vec<Bip39ChainBalance>,
}

#[derive(Clone, Debug)]
pub struct Bip39ScanChunkParams<'a> {
    pub mnemonic_str: &'a SecretString,
    pub passphrase: &'a SecretString,
    pub mnemonic_check: bool,
    pub primary_chain: &'a ChainConfig,
    pub chains: &'a [ChainConfig],
    pub start_index: u32,
    pub count: u32,
    pub total_target: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bip39ScanChunkResult {
    pub accounts: Vec<Bip39DiscoveredAccount>,
    pub scanned_from: u32,
    pub scanned_to: u32,
    pub total_target: u32,
    pub cached_count: u32,
    pub network_error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct Bip39RecoveryScanCache {
    pub updated_at: u64,
    pub scanned_accounts: BTreeMap<u32, Bip39DiscoveredAccount>,
}

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

    fn derive_bip39_first_account(
        &self,
        mnemonic_str: &SecretString,
        passphrase: &SecretString,
        mnemonic_check: bool,
        primary_chain: &ChainConfig,
        chains: &[ChainConfig],
    ) -> std::result::Result<Bip39DiscoveredAccount, Self::Error>;

    async fn scan_bip39_accounts_chunk(
        &self,
        params: Bip39ScanChunkParams<'_>,
    ) -> std::result::Result<Bip39ScanChunkResult, Self::Error>;
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
        wallet.save_wallet_data(&data)?;

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

        if let Ok(provider) = self.get_provider(data.chain_hash) {
            wallet
                .migrate_btc_storage_if_needed(&argon_seed, &provider.config)
                .await?;
        }

        self.sync_chain_accounts(wallet_index, &argon_seed).await?;

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

        if let Ok(provider) = self.get_provider(data.chain_hash) {
            wallet
                .migrate_btc_storage_if_needed(&seed_bytes, &provider.config)
                .await?;
        }

        self.sync_chain_accounts(wallet_index, &seed_bytes).await?;

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
                Err(AccountErrors::InvalidPubKeyType)?;
            }
        }

        let pk = account
            .pub_key
            .as_ref()
            .ok_or(AccountErrors::InvalidPubKeyType)?;
        account.addr = pk.get_addr()?;
        wallet.save_wallet_data(&data)?;

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
        let mnemonic_str_secret = params.mnemonic_str;
        let mnemonic = if params.mnemonic_check {
            Mnemonic::parse_str(&EN_WORDS, mnemonic_str_secret)?
        } else {
            Mnemonic::parse_str_without_checksum(&EN_WORDS, mnemonic_str_secret)?
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
        )
        .await?;
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
                chain_config: &provider.config,
                biometric_type: params.biometric_type,
                btc_chains: params.btc_chains,
            },
            wallet_config,
            ftokens,
        )
        .await?;
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
                biometric_type: params.biometric_type,
                chain_config: &provider.config,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if provider.config.slip_44 == crypto::slip44::BITCOIN {
            if let Ok(mut chains) = wallet.get_btc_addresses(0, params.chain_hash) {
                use network::btc::BtcOperations;
                if let Err(e) = provider.batch_script_get_history(&mut chains).await {
                    println!(
                        "[add_sk_wallet] btc history scan failed (offline?): {:?}",
                        e
                    );
                } else {
                    let _ = wallet.save_btc_addresses(0, &chains, params.chain_hash);
                }
            }
        }

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

    fn derive_bip39_first_account(
        &self,
        mnemonic_str: &SecretString,
        passphrase: &SecretString,
        mnemonic_check: bool,
        primary_chain: &ChainConfig,
        chains: &[ChainConfig],
    ) -> Result<Bip39DiscoveredAccount> {
        let effective_chains = Self::build_effective_chains(primary_chain, chains);
        let cache_key =
            Self::recovery_scan_cache_key(mnemonic_str, passphrase, &effective_chains);
        if let Some(cache) = self.load_recovery_scan_cache(&cache_key) {
            if let Some(first) = cache.scanned_accounts.get(&0) {
                return Ok(first.clone());
            }
        }

        let mnemonic_seed_secret = Self::resolve_mnemonic_seed(
            mnemonic_str,
            passphrase,
            mnemonic_check,
        )?;
        let (entry, _, _) =
            Self::derive_single_bip39_account_entry(&mnemonic_seed_secret, 0, primary_chain)?;
        Ok(entry)
    }

    async fn scan_bip39_accounts_chunk(
        &self,
        params: Bip39ScanChunkParams<'_>,
    ) -> Result<Bip39ScanChunkResult> {
        let start = params.start_index;
        let end = (params.start_index.saturating_add(params.count)).min(params.total_target);
        if start >= end {
            return Ok(Bip39ScanChunkResult {
                accounts: Vec::new(),
                scanned_from: start,
                scanned_to: start,
                total_target: params.total_target,
                cached_count: 0,
                network_error: None,
            });
        }

        let effective_chains = Self::build_effective_chains(params.primary_chain, params.chains);
        let cache_key = Self::recovery_scan_cache_key(
            params.mnemonic_str,
            params.passphrase,
            &effective_chains,
        );
        let initial_cache = self.load_recovery_scan_cache(&cache_key).unwrap_or_default();

        let missing_indices: Vec<u32> = (start..end)
            .filter(|idx| !initial_cache.scanned_accounts.contains_key(idx))
            .collect();
        let cached_count = (end - start).saturating_sub(missing_indices.len() as u32);

        if missing_indices.is_empty() {
            let accounts = (start..end)
                .filter_map(|idx| initial_cache.scanned_accounts.get(&idx))
                .filter(|entry| entry.index == 0 || entry.has_activity)
                .cloned()
                .collect();

            return Ok(Bip39ScanChunkResult {
                accounts,
                scanned_from: start,
                scanned_to: end,
                total_target: params.total_target,
                cached_count,
                network_error: None,
            });
        }

        let mnemonic_seed_secret = Self::resolve_mnemonic_seed(
            params.mnemonic_str,
            params.passphrase,
            params.mnemonic_check,
        )?;

        let mut primary_entries = Vec::with_capacity(missing_indices.len());
        for idx in &missing_indices {
            let (entry, _, _) = Self::derive_single_bip39_account_entry(
                &mnemonic_seed_secret,
                *idx,
                params.primary_chain,
            )?;
            primary_entries.push(entry);
        }

        let first_fallback = primary_entries
            .iter()
            .find(|entry| entry.index == 0)
            .cloned();

        let fetch_res = Self::fetch_multi_chain_recovery_batch(
            &mnemonic_seed_secret,
            params.primary_chain,
            &effective_chains,
            &missing_indices,
            primary_entries,
        )
        .await;

        match fetch_res {
            Ok(fetched_entries) => {
                let accounts = {
                    let _guard = RECOVERY_CACHE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    let mut latest_cache =
                        self.load_recovery_scan_cache(&cache_key).unwrap_or_default();
                    for entry in fetched_entries {
                        latest_cache.scanned_accounts.insert(entry.index, entry);
                    }
                    latest_cache.updated_at = Self::now_unix_secs();
                    let _ = self.storage.set_versioned(&cache_key, &latest_cache);
                    let _ = self.storage.flush();

                    (start..end)
                        .filter_map(|idx| latest_cache.scanned_accounts.get(&idx))
                        .filter(|entry| entry.index == 0 || entry.has_activity)
                        .cloned()
                        .collect()
                };

                Ok(Bip39ScanChunkResult {
                    accounts,
                    scanned_from: start,
                    scanned_to: end,
                    total_target: params.total_target,
                    cached_count,
                    network_error: None,
                })
            }
            Err(err) => {
                let mut accounts: Vec<Bip39DiscoveredAccount> = (start..end)
                    .filter_map(|idx| initial_cache.scanned_accounts.get(&idx))
                    .filter(|entry| entry.index == 0 || entry.has_activity)
                    .cloned()
                    .collect();

                if start == 0 && !accounts.iter().any(|a| a.index == 0) {
                    if let Some(first) = first_fallback {
                        accounts.insert(0, first);
                    }
                }

                Ok(Bip39ScanChunkResult {
                    accounts,
                    scanned_from: start,
                    scanned_to: end,
                    total_target: params.total_target,
                    cached_count,
                    network_error: Some(err.to_string()),
                })
            }
        }
    }
}

impl Background {
    /// Derive accounts for all known chains after unlock.
    /// Ensures every chain has accounts before any switch,
    /// making select_accounts_chain a pointer-only operation.
    pub(crate) async fn sync_chain_accounts(
        &self,
        wallet_index: usize,
        seed: &Argon2Seed,
    ) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let providers = self.get_providers();

        let mut seen_slip44 = std::collections::HashSet::new();
        for provider in &providers {
            let slip44 = provider.config.slip_44;
            if !seen_slip44.insert(slip44) {
                continue;
            }
            match wallet.ensure_chain_accounts(
                &mut data,
                slip44,
                provider.config.bitcoin_network(),
                seed,
                &wallet::empty_passphrase(),
            ) {
                Ok(()) => {}
                Err(errors::wallet::WalletErrors::InvalidAccountType) => continue,
                Err(e) => return Err(e.into()),
            }
        }

        wallet.save_wallet_data(&data)?;

        // BTC address chains: generate for EVERY BTC provider's chain_hash
        // (not deduped by slip44 — mainnet and testnet have the same slip44
        // but different chain_hashes with isolated address storage)
        for provider in &providers {
            if provider.config.slip_44 == crypto::slip44::BITCOIN {
                if let Some(network) = provider.config.bitcoin_network() {
                    let chain_hash = provider.config.hash();
                    let btc_bip = DerivationPath::default_bip(crypto::slip44::BITCOIN);
                    let account_count = data
                        .slip44_accounts
                        .get(&crypto::slip44::BITCOIN)
                        .and_then(|m| m.get(&btc_bip))
                        .map_or(0, |v| v.len());

                    for idx in 0..account_count {
                        if wallet.get_btc_addresses(idx, chain_hash).is_err() {
                            match wallet
                                .generate_btc_chains_offline(&data, seed, idx, chain_hash, network)
                                .await
                            {
                                Ok(()) => {}
                                Err(errors::wallet::WalletErrors::InvalidAccountType) => continue,
                                Err(e) => return Err(e.into()),
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn resolve_mnemonic_seed(
        mnemonic_str: &SecretString,
        passphrase: &SecretString,
        mnemonic_check: bool,
    ) -> Result<SecretBox<[u8; 64]>> {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let mut engine = sha256::Hash::engine();
        engine.input(mnemonic_str.expose_secret().trim().as_bytes());
        engine.input(b":");
        engine.input(passphrase.expose_secret().as_bytes());
        engine.input(&[mnemonic_check as u8]);
        let key_hash = sha256::Hash::from_engine(engine).to_byte_array();

        if let Ok(guard) = RECOVERY_SEED_CACHE.lock() {
            if let Some((cached_key, cached_seed)) = &*guard {
                if *cached_key == key_hash {
                    return Ok(SecretBox::new(Box::new(*cached_seed)));
                }
            }
        }

        let mnemonic = if mnemonic_check {
            Mnemonic::parse_str(&EN_WORDS, mnemonic_str)?
        } else {
            Mnemonic::parse_str_without_checksum(&EN_WORDS, mnemonic_str)?
        };
        let seed = mnemonic.to_seed(passphrase)?;
        if let Ok(mut guard) = RECOVERY_SEED_CACHE.lock() {
            *guard = Some((key_hash, *seed.expose_secret()));
        }
        Ok(seed)
    }

    pub(crate) fn build_effective_chains(
        primary_chain: &ChainConfig,
        chains: &[ChainConfig],
    ) -> Vec<ChainConfig> {
        let mut seen = HashSet::new();
        let mut out = Vec::with_capacity(chains.len() + 1);
        seen.insert(primary_chain.hash());
        out.push(primary_chain.clone());
        for c in chains {
            if seen.insert(c.hash()) {
                out.push(c.clone());
            }
        }
        out
    }

    pub(crate) fn recovery_scan_cache_key(
        mnemonic_str: &SecretString,
        passphrase: &SecretString,
        chains: &[ChainConfig],
    ) -> Vec<u8> {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let mut engine = sha256::Hash::engine();
        engine.input(b"bearby_bip39_recovery_scan_v2:");
        engine.input(mnemonic_str.expose_secret().trim().as_bytes());
        engine.input(b":");
        engine.input(passphrase.expose_secret().as_bytes());
        let mut hashes: Vec<u64> = chains.iter().map(|c| c.hash()).collect();
        hashes.sort_unstable();
        hashes.dedup();
        for h in hashes {
            engine.input(b":");
            engine.input(&h.to_le_bytes());
        }
        let digest = sha256::Hash::from_engine(engine);
        format!("recovery_scan::{}", digest).into_bytes()
    }

    fn load_recovery_scan_cache(&self, cache_key: &[u8]) -> Option<Bip39RecoveryScanCache> {
        let cache = self
            .storage
            .get_versioned::<Bip39RecoveryScanCache>(cache_key)
            .ok()?;
        let now = Self::now_unix_secs();
        if cache.updated_at > 0 && now.saturating_sub(cache.updated_at) > RECOVERY_CACHE_TTL_SECS {
            return None;
        }
        Some(cache)
    }

    fn derive_single_bip39_account_entry(
        seed: &SecretBox<[u8; 64]>,
        idx: u32,
        chain: &ChainConfig,
    ) -> Result<(Bip39DiscoveredAccount, Address, Option<Address>)> {
        let native_token = chain.ftokens.iter().find(|t| t.native).or_else(|| chain.ftokens.first());
        let symbol = native_token
            .map(|t| t.symbol.clone())
            .unwrap_or_else(|| chain.chain.clone());
        let decimals = native_token.map(|t| t.decimals).unwrap_or(0);

        let network = chain.bitcoin_network();
        let name = format!("Account {}", idx);

        if chain.slip_44 == crypto::slip44::BITCOIN {
            let path = DerivationPath::with_index(crypto::slip44::BITCOIN, (idx as usize, 0, 0));
            let acc = AccountV2::from_hd(seed, name, &path, network)?;
            let addr_str = acc.addr.auto_format();
            Ok((
                Bip39DiscoveredAccount {
                    index: idx,
                    addr: addr_str,
                    legacy_addr: None,
                    balance: "0".to_string(),
                    decimals,
                    symbol,
                    tx_count: 0,
                    has_activity: false,
                    chain_balances: Vec::new(),
                },
                acc.addr,
                None,
            ))
        } else if chain.slip_44 == crypto::slip44::ZILLIQA {
            let path =
                DerivationPath::with_index(crypto::slip44::ZILLIQA, (0, 0, idx as usize));
            let acc = AccountV2::from_hd(seed, name, &path, network)?;
            let (zil_addr, eth_addr) = acc.get_zilliqa_addr_pair()?;
            Ok((
                Bip39DiscoveredAccount {
                    index: idx,
                    addr: eth_addr.auto_format(),
                    legacy_addr: Some(zil_addr.auto_format()),
                    balance: "0".to_string(),
                    decimals,
                    symbol,
                    tx_count: 0,
                    has_activity: false,
                    chain_balances: Vec::new(),
                },
                eth_addr,
                Some(zil_addr),
            ))
        } else {
            let path = DerivationPath::with_index(chain.slip_44, (0, 0, idx as usize));
            let acc = AccountV2::from_hd(seed, name, &path, network)?;
            let addr_str = acc.addr.auto_format();
            Ok((
                Bip39DiscoveredAccount {
                    index: idx,
                    addr: addr_str,
                    legacy_addr: None,
                    balance: "0".to_string(),
                    decimals,
                    symbol,
                    tx_count: 0,
                    has_activity: false,
                    chain_balances: Vec::new(),
                },
                acc.addr,
                None,
            ))
        }
    }

    async fn fetch_multi_chain_recovery_batch(
        seed: &SecretBox<[u8; 64]>,
        primary_chain: &ChainConfig,
        chains: &[ChainConfig],
        indices: &[u32],
        mut primary_entries: Vec<Bip39DiscoveredAccount>,
    ) -> Result<Vec<Bip39DiscoveredAccount>> {
        // Group derived addresses by slip_44 so we only derive each slip_44 once per index
        let mut derived_by_slip44: HashMap<
            u32,
            Arc<Vec<(Bip39DiscoveredAccount, Address, Option<Address>)>>,
        > = HashMap::new();

        for chain in chains {
            if chain.slip_44 == crypto::slip44::BITCOIN {
                continue;
            }
            if !derived_by_slip44.contains_key(&chain.slip_44) {
                let mut entries = Vec::with_capacity(indices.len());
                for idx in indices {
                    entries.push(Self::derive_single_bip39_account_entry(seed, *idx, chain)?);
                }
                derived_by_slip44.insert(chain.slip_44, Arc::new(entries));
            }
        }

        let mut join_set = tokio::task::JoinSet::new();

        for (chain_order, chain) in chains.iter().cloned().enumerate() {
            if chain.slip_44 == crypto::slip44::BITCOIN {
                let mut btc_entries = Vec::with_capacity(indices.len());
                for idx in indices {
                    btc_entries.push(Self::derive_single_bip39_account_entry(
                        seed, *idx, &chain,
                    )?);
                }
                let seed_bytes = *seed.expose_secret();
                join_set.spawn(async move {
                    let seed_box = SecretBox::new(Box::new(seed_bytes));
                    let fetched =
                        Self::fetch_btc_recovery_batch(&seed_box, &chain, btc_entries).await?;
                    Ok::<(usize, ChainConfig, Vec<Bip39DiscoveredAccount>), BackgroundError>((
                        chain_order,
                        chain,
                        fetched,
                    ))
                });
            } else if let Some(derived_arc) = derived_by_slip44.get(&chain.slip_44).cloned() {
                join_set.spawn(async move {
                    let native_token = chain
                        .ftokens
                        .iter()
                        .find(|t| t.native)
                        .or_else(|| chain.ftokens.first());
                    let symbol = native_token
                        .map(|t| t.symbol.clone())
                        .unwrap_or_else(|| chain.chain.clone());
                    let decimals = native_token.map(|t| t.decimals).unwrap_or(0);

                    let mut chain_entries: Vec<(
                        Bip39DiscoveredAccount,
                        Address,
                        Option<Address>,
                    )> = derived_arc
                        .iter()
                        .cloned()
                        .map(|(mut e, p, s)| {
                            e.symbol = symbol.clone();
                            e.decimals = decimals;
                            (e, p, s)
                        })
                        .collect();

                    chain_entries =
                        Self::fetch_account_balances_batch(&chain, chain_entries)
                            .await?
                            .into_iter()
                            .zip(derived_arc.iter())
                            .map(|(e, (_, p, s))| (e, p.clone(), s.clone()))
                            .collect();

                    let out: Vec<Bip39DiscoveredAccount> =
                        chain_entries.into_iter().map(|(e, _, _)| e).collect();
                    Ok::<(usize, ChainConfig, Vec<Bip39DiscoveredAccount>), BackgroundError>((
                        chain_order,
                        chain,
                        out,
                    ))
                });
            }
        }

        let mut provider_results: Vec<(usize, ChainConfig, Vec<Bip39DiscoveredAccount>)> =
            Vec::new();
        let mut last_err: Option<BackgroundError> = None;

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(ok_tuple)) => provider_results.push(ok_tuple),
                Ok(Err(e)) => last_err = Some(e),
                Err(join_err) => {
                    last_err = Some(BackgroundError::WorkerError(join_err.to_string()));
                }
            }
        }

        if provider_results.is_empty() {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        provider_results.sort_by_key(|(order, _, _)| *order);

        let primary_hash = primary_chain.hash();
        let mut entry_by_index: BTreeMap<u32, Bip39DiscoveredAccount> = primary_entries
            .drain(..)
            .map(|e| (e.index, e))
            .collect();

        for (_, chain, accounts) in provider_results {
            let c_hash = chain.hash();
            for acc in accounts {
                if let Some(target) = entry_by_index.get_mut(&acc.index) {
                    if c_hash == primary_hash {
                        target.balance = acc.balance.clone();
                        target.tx_count = acc.tx_count;
                    }
                    if acc.has_activity {
                        target.has_activity = true;
                        target.chain_balances.push(Bip39ChainBalance {
                            chain_name: chain.name.clone(),
                            chain_hash: c_hash,
                            slip44: chain.slip_44,
                            addr: acc.addr,
                            symbol: acc.symbol,
                            balance: acc.balance,
                            decimals: acc.decimals,
                            tx_count: acc.tx_count,
                        });
                    }
                }
            }
        }

        Ok(entry_by_index.into_values().collect())
    }

    async fn fetch_account_balances_batch(
        chain: &ChainConfig,
        derived_entries: Vec<(Bip39DiscoveredAccount, Address, Option<Address>)>,
    ) -> Result<Vec<Bip39DiscoveredAccount>> {
        let base_native_tokens: Vec<FToken> = chain
            .ftokens
            .iter()
            .filter(|t| t.native)
            .cloned()
            .collect();

        if base_native_tokens.is_empty() {
            return Ok(derived_entries.into_iter().map(|(e, _, _)| e).collect());
        }

        let sub_batches: Vec<Vec<(Bip39DiscoveredAccount, Address, Option<Address>)>> =
            derived_entries
                .chunks(RECOVERY_SUB_BATCH_SIZE)
                .map(|c| c.to_vec())
                .collect();

        let mut join_set = tokio::task::JoinSet::new();
        for sub_batch in sub_batches {
            let chain_clone = chain.clone();
            let mut native_tokens = base_native_tokens.clone();
            join_set.spawn(async move {
                let provider = NetworkProvider::new(chain_clone.clone());
                let mut query_addrs: Vec<Address> = Vec::with_capacity(sub_batch.len() * 2);
                for (_, primary, secondary) in &sub_batch {
                    query_addrs.push(primary.clone());
                    if let Some(sec) = secondary {
                        query_addrs.push(sec.clone());
                    }
                }
                let addr_refs: Vec<&Address> = query_addrs.iter().collect();
                let token_refs: Vec<&mut FToken> = native_tokens.iter_mut().collect();
                provider.update_balances(token_refs, &addr_refs).await?;

                let mut out = Vec::with_capacity(sub_batch.len());
                for (mut entry, primary, secondary) in sub_batch {
                    if chain_clone.slip_44 == crypto::slip44::ZILLIQA {
                        let mut total_bal = U256::ZERO;
                        for tok in &native_tokens {
                            if matches!(tok.addr, Address::Secp256k1Keccak256(_)) {
                                if let Some(b) = tok.balances.get(&primary.to_hash()) {
                                    total_bal = total_bal.saturating_add(*b);
                                }
                            } else if matches!(tok.addr, Address::Secp256k1Sha256(_)) {
                                if let Some(sec_addr) = &secondary {
                                    if let Some(b) = tok.balances.get(&sec_addr.to_hash()) {
                                        let scale = if tok.decimals < entry.decimals {
                                            U256::from(10u64.pow((entry.decimals - tok.decimals) as u32))
                                        } else {
                                            U256::from(1u64)
                                        };
                                        total_bal =
                                            total_bal.saturating_add(b.saturating_mul(scale));
                                    }
                                }
                            }
                        }
                        entry.balance = total_bal.to_string();
                        entry.has_activity = total_bal > U256::ZERO;
                    } else if let Some(tok) = native_tokens.first() {
                        let bal = tok
                            .balances
                            .get(&primary.to_hash())
                            .copied()
                            .unwrap_or(U256::ZERO);
                        entry.balance = bal.to_string();
                        entry.has_activity = bal > U256::ZERO;
                    }
                    out.push(entry);
                }
                Ok::<Vec<Bip39DiscoveredAccount>, BackgroundError>(out)
            });
        }

        let mut all_accounts = Vec::new();
        while let Some(res) = join_set.join_next().await {
            let batch_res = res.map_err(|e| BackgroundError::WorkerError(e.to_string()))??;
            all_accounts.extend(batch_res);
        }
        all_accounts.sort_by_key(|a| a.index);
        Ok(all_accounts)
    }

    async fn fetch_btc_recovery_batch(
        seed: &SecretBox<[u8; 64]>,
        chain: &ChainConfig,
        derived_entries: Vec<(Bip39DiscoveredAccount, Address, Option<Address>)>,
    ) -> Result<Vec<Bip39DiscoveredAccount>> {
        let network = chain.bitcoin_network();
        let sub_batches: Vec<Vec<(Bip39DiscoveredAccount, Address, Option<Address>)>> =
            derived_entries
                .chunks(RECOVERY_SUB_BATCH_SIZE)
                .map(|c| c.to_vec())
                .collect();

        let mut join_set = tokio::task::JoinSet::new();
        for sub_batch in sub_batches {
            let chain_clone = chain.clone();
            let seed_bytes = *seed.expose_secret();
            join_set.spawn(async move {
                let seed_box = SecretBox::new(Box::new(seed_bytes));
                let provider = NetworkProvider::new(chain_clone);
                let mut combined_chains: HashMap<bitcoin::AddressType, AddressChain> =
                    HashMap::new();

                for (entry, _, _) in &sub_batch {
                    for (purpose, addr_type) in [
                        (
                            DerivationPath::BIP84_PURPOSE,
                            bitcoin::AddressType::P2wpkh,
                        ),
                        (
                            DerivationPath::BIP86_PURPOSE,
                            bitcoin::AddressType::P2tr,
                        ),
                        (
                            DerivationPath::BIP49_PURPOSE,
                            bitcoin::AddressType::P2sh,
                        ),
                        (
                            DerivationPath::BIP44_PURPOSE,
                            bitcoin::AddressType::P2pkh,
                        ),
                    ] {
                        let chain_bucket =
                            combined_chains
                                .entry(addr_type)
                                .or_insert_with(|| AddressChain {
                                    external: Vec::new(),
                                    internal: Vec::new(),
                                });
                        let path = DerivationPath::new(
                            crypto::slip44::BITCOIN,
                            DerivationType::AddressIndex(entry.index as usize, 0, 0),
                            purpose,
                        );
                        let acc = AccountV2::from_hd(&seed_box, String::new(), &path, network)?;
                        chain_bucket.external.push(BtcAddressEntry {
                            address: acc.addr,
                            path,
                            history: Vec::new(),
                            utxos: Vec::new(),
                        });
                    }
                }

                provider
                    .batch_script_get_history(&mut combined_chains)
                    .await?;

                let mut tx_hashes_by_account: HashMap<u32, HashSet<bitcoin::Txid>> = HashMap::new();
                for addr_chain in combined_chains.values() {
                    for addr_entry in addr_chain.external.iter().chain(addr_chain.internal.iter()) {
                        let acc_idx = addr_entry.path.get_account_index() as u32;
                        if !addr_entry.history.is_empty() {
                            tx_hashes_by_account
                                .entry(acc_idx)
                                .or_default()
                                .extend(addr_entry.history.iter().copied());
                        }
                    }
                }

                let mut out = Vec::with_capacity(sub_batch.len());
                for (mut entry, _, _) in sub_batch {
                    let tx_count = tx_hashes_by_account
                        .get(&entry.index)
                        .map_or(0, |s| s.len() as u32);
                    entry.tx_count = tx_count;
                    entry.has_activity = tx_count > 0;
                    out.push(entry);
                }
                Ok::<Vec<Bip39DiscoveredAccount>, BackgroundError>(out)
            });
        }

        let mut all_entries = Vec::with_capacity(derived_entries.len());
        while let Some(res) = join_set.join_next().await {
            let batch_res = res.map_err(|e| BackgroundError::WorkerError(e.to_string()))??;
            all_entries.extend(batch_res);
        }
        all_entries.sort_by_key(|a| a.index);
        Ok(all_entries)
    }
}

#[cfg(test)]
mod tests_background_wallet {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement, bg_token::TokensManagement,
    };

    use proto::address::Address;
    use rand::RngExt;

    use test_data::{
        anvil_accounts::PRIVATE_KEY_0, empty_passphrase, gen_btc_regtest_conf,
        gen_zil_testnet_conf, TEST_PASSWORD,
    };
    use wallet::wallet_account::AccountManagement;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_generate_zilliqa_legacy_accounts() {
        let (mut bg, _dir) = setup_test_background();
        let net_conf = gen_zil_testnet_conf();
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
        } else {
            panic!("address should convert to legacy mode");
        }

        let chains: Vec<_> = bg.get_providers().into_iter().map(|p| p.config).collect();

        for i in 1..20 {
            wallet
                .add_next_bip39_account(
                    format!("Zilliqa account {}", i),
                    i,
                    &empty_passphrase(),
                    &argon_seed,
                    &chains,
                )
                .await
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
    async fn test_add_sk_btc_wallet_syncs_chains_and_balance() {
        use proto::secret_key::SecretKey;
        use wallet::bitcoin_wallet::BitcoinWallet;
        use wallet::wallet_storage::StorageOperations;

        let (mut bg, _dir) = setup_test_background();
        let net_conf = gen_btc_regtest_conf();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        bg.add_provider(net_conf.clone()).unwrap();

        let sk_hex = PRIVATE_KEY_0.trim_start_matches("0x");
        let sk_bytes: [u8; 32] = hex::decode(sk_hex).unwrap().try_into().unwrap();
        let network = net_conf
            .bitcoin_network()
            .unwrap_or(bitcoin::Network::Bitcoin);
        let sk = SecretKey::Secp256k1Bitcoin((sk_bytes, network, bitcoin::AddressType::P2wpkh));

        bg.add_sk_wallet(BackgroundSKParams {
            password: &password,
            secret_key: sk,
            wallet_name: "BTC SK wallet".to_string(),
            biometric_type: AuthMethod::None,
            wallet_settings: Default::default(),
            chain_hash: net_conf.hash(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.get_selected_account().unwrap();

        let addr_str = account.addr.auto_format();
        assert!(
            addr_str.starts_with("bcrt1q"),
            "expected default P2WPKH regtest address, got: {}",
            addr_str
        );

        let chains = wallet.get_btc_addresses(0, net_conf.hash()).unwrap();
        dbg!(&chains);
        assert_eq!(chains.len(), 4);
        for addr_type in [
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2sh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2tr,
        ] {
            let chain = chains
                .get(&addr_type)
                .unwrap_or_else(|| panic!("missing chain for {:?}", addr_type));
            assert_eq!(chain.external.len(), 1, "{:?} external", addr_type);
            assert!(chain.internal.is_empty(), "{:?} internal", addr_type);
        }
        let p2wpkh = chains.get(&bitcoin::AddressType::P2wpkh).unwrap();
        assert_eq!(p2wpkh.external[0].address, account.addr);

        bg.sync_ftokens_balances(0).await.unwrap();

        let ftokens = wallet.get_ftokens().unwrap();
        let btc_token = ftokens
            .iter()
            .find(|t| t.native && t.chain_hash == net_conf.hash())
            .expect("BTC native token must be present");
        assert!(btc_token.balances.contains_key(&account.addr.to_hash()));
    }

    #[tokio::test]
    async fn test_derive_first_account_and_emergency_cache_resume() {
        let (bg, _dir) = setup_test_background();
        let net_conf = gen_zil_testnet_conf();
        let chains = vec![net_conf.clone()];
        let words = Background::gen_bip39(12).unwrap();
        let passphrase = empty_passphrase();

        let first = bg
            .derive_bip39_first_account(&words, &passphrase, true, &net_conf, &chains)
            .unwrap();
        assert_eq!(first.index, 0);
        assert!(first.addr.starts_with("0x"));
        assert!(first
            .legacy_addr
            .as_deref()
            .unwrap_or_default()
            .starts_with("zil1"));

        let effective = Background::build_effective_chains(&net_conf, &chains);
        let cache_key = Background::recovery_scan_cache_key(&words, &passphrase, &effective);
        let mut cache = Bip39RecoveryScanCache {
            updated_at: Background::now_unix_secs(),
            scanned_accounts: BTreeMap::new(),
        };
        for idx in 0..50u32 {
            let mut entry = first.clone();
            entry.index = idx;
            if idx == 3 || idx == 17 {
                entry.balance = "1500000000000000000".to_string();
                entry.has_activity = true;
                entry.chain_balances = vec![Bip39ChainBalance {
                    chain_name: net_conf.name.clone(),
                    chain_hash: net_conf.hash(),
                    slip44: net_conf.slip_44,
                    addr: entry.addr.clone(),
                    symbol: entry.symbol.clone(),
                    balance: entry.balance.clone(),
                    decimals: entry.decimals,
                    tx_count: 0,
                }];
            }
            cache.scanned_accounts.insert(idx, entry);
        }
        bg.storage().set_versioned(&cache_key, &cache).unwrap();

        let res = bg
            .scan_bip39_accounts_chunk(Bip39ScanChunkParams {
                mnemonic_str: &words,
                passphrase: &passphrase,
                mnemonic_check: true,
                primary_chain: &net_conf,
                chains: &chains,
                start_index: 0,
                count: 50,
                total_target: 250,
            })
            .await
            .unwrap();

        assert_eq!(res.cached_count, 50);
        assert!(res.network_error.is_none());
        let indices: Vec<u32> = res.accounts.iter().map(|a| a.index).collect();
        assert_eq!(indices, vec![0, 3, 17]);
        assert_eq!(res.accounts[1].chain_balances.len(), 1);
    }

    #[tokio::test]
    async fn test_scan_bip39_accounts_chunk_offline_returns_first_account() {
        let (bg, _dir) = setup_test_background();
        let mut net_conf = gen_zil_testnet_conf();
        net_conf.ftokens = vec![test_data::gen_zil_token()];
        net_conf.rpc = vec!["http://127.0.0.1:1".to_string()];
        let chains = vec![net_conf.clone()];
        let words = Background::gen_bip39(12).unwrap();
        let passphrase = empty_passphrase();

        let res = bg
            .scan_bip39_accounts_chunk(Bip39ScanChunkParams {
                mnemonic_str: &words,
                passphrase: &passphrase,
                mnemonic_check: true,
                primary_chain: &net_conf,
                chains: &chains,
                start_index: 0,
                count: 25,
                total_target: 250,
            })
            .await
            .unwrap();

        assert!(res.network_error.is_some());
        assert_eq!(res.accounts.len(), 1);
        assert_eq!(res.accounts[0].index, 0);

        let effective = Background::build_effective_chains(&net_conf, &chains);
        let cache_key = Background::recovery_scan_cache_key(&words, &passphrase, &effective);
        assert!(bg
            .storage()
            .get_versioned::<Bip39RecoveryScanCache>(&cache_key)
            .is_err());
    }
}
