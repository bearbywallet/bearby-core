use errors::network::NetworkErrors;

pub type Result<T> = std::result::Result<T, NetworkErrors>;

pub mod btc;
pub mod common;
pub mod evm;
pub mod provider;
pub mod solana;
pub mod tron;
