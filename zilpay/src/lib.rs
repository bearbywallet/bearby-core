pub use alloy;
pub use bitcoin;
pub use hex;
pub use rand;
pub use rand_chacha;
pub use reqwest;
pub use secrecy;
pub use serde;
pub use serde_json;
pub use sha2;
pub use solana_hash;
pub use solana_instruction;
pub use solana_message;
pub use solana_pubkey;
pub use solana_system_interface;
pub use spl_associated_token_account;
pub use spl_token;
pub use thiserror;
pub use tokio;
pub use zeroize;

pub use background;
pub use cache;
pub use cipher;
pub use config;
pub use crypto;
pub use errors;
pub use history;
pub use intl;
pub use network;
pub use proto;
pub use qrcodes;
pub use rpc;
pub use session;
pub use settings;
pub use storage;
pub use token;
pub use wallet;

pub fn init() -> Result<(), String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Failed to install crypto provider".to_string())?;

    Ok(())
}
