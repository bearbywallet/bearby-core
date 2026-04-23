pub use pqbip39::mnemonic::Mnemonic;

use config::session::AuthMethod;
use errors::background::BackgroundError;
use proto::{address::Address, pubkey::PubKey, secret_key::SecretKey};
use secrecy::SecretString;
use settings::wallet_settings::WalletSettings;
use std::sync::Arc;
use storage::LocalStorage;
use token::ft::FToken;
use wallet::Wallet;

pub type Result<T> = std::result::Result<T, BackgroundError>;

#[derive(Debug)]
pub struct BackgroundBip39Params<'a> {
    pub password: &'a SecretString,
    pub mnemonic_str: &'a SecretString,
    pub mnemonic_check: bool,
    pub passphrase: &'a SecretString,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub wallet_settings: WalletSettings,
    pub accounts: &'a [(usize, String)],
    pub chain_hash: u64,
    pub ftokens: Vec<FToken>,
}

#[derive(Debug)]
pub struct BackgroundSKParams<'a> {
    pub password: &'a SecretString,
    pub secret_key: SecretKey,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub wallet_settings: WalletSettings,
    pub chain_hash: u64,
    pub ftokens: Vec<FToken>,
}

#[derive(Debug)]
pub struct BackgroundLedgerParams {
    pub ledger_id: Vec<u8>,
    pub accounts: Vec<(u8, Option<PubKey>, Address)>,
    pub wallet_name: String,
    pub account_names: Vec<String>,
    pub wallet_index: usize,
    pub biometric_type: AuthMethod,
    pub wallet_settings: WalletSettings,
    pub chain_hash: u64,
    pub ftokens: Vec<FToken>,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
}

pub mod bg_book;
pub mod bg_connections;
pub mod bg_crypto;
pub mod bg_provider;
pub mod bg_settings;
pub mod bg_storage;
pub mod bg_token;
pub mod bg_tx;
pub mod bg_wallet;
pub mod bg_worker;
pub mod book;
pub mod connections;
pub mod device_indicators;
