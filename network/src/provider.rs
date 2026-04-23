use std::sync::Arc;

use crate::btc::BtcOperations;
use crate::common::Provider;
use crate::evm::{EvmOperations, RequiredTxParams};
use crate::solana::SolanaOperations;
use crate::tron::TronOperations;
use crate::Result;
use alloy::primitives::U256;
use config::storage::NETWORK_DB_KEY_V1;
use crypto::slip44;
use errors::network::NetworkErrors;
use errors::rpc::RpcError;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tron_tx::TronTransaction;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::common::JsonRPC;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use serde_json::Value;
use storage::LocalStorage;
use token::ft::FToken;

#[derive(Debug, PartialEq)]
pub struct NetworkProvider {
    pub config: ChainConfig,
}

impl Provider for NetworkProvider {
    fn load_network_configs(storage: Arc<LocalStorage>) -> Vec<Self> {
        match storage.get_versioned::<Vec<ChainConfig>>(NETWORK_DB_KEY_V1) {
            Ok(configs) => configs.into_iter().map(NetworkProvider::new).collect(),
            Err(_) => Vec::with_capacity(1),
        }
    }

    fn save_network_configs(providers: &[Self], storage: Arc<LocalStorage>) -> Result<()> {
        let as_vec: Vec<_> = providers.iter().map(|v| &v.config).collect();

        storage.set_versioned(NETWORK_DB_KEY_V1, &as_vec)?;
        storage.flush()?;

        Ok(())
    }
}

impl NetworkProvider {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    pub async fn proxy_req(&self, payload_str: String) -> Result<Value> {
        let payload =
            serde_json::from_str(&payload_str).map_err(|e| RpcError::InvalidJson(e.to_string()))?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        let response = provider
            .req::<Value>(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        Ok(response)
    }

    pub async fn get_current_block_number(&self) -> Result<u64> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_get_current_block_number().await,
            slip44::BITCOIN => self.btc_get_current_block_number().await,
            slip44::TRON => self.tron_get_current_block_number().await,
            slip44::SOLANA => self.solana_get_current_block_number().await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn estimate_block_time(&self, address: &Address) -> Result<u64> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_estimate_block_time(address).await,
            slip44::BITCOIN => self.btc_estimate_block_time().await,
            slip44::TRON => self.tron_estimate_block_time().await,
            slip44::SOLANA => self.solana_estimate_block_time().await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA | slip44::TRON => {
                self.evm_update_transactions_receipt(txns).await
            }
            slip44::BITCOIN => self.btc_update_transactions_receipt(txns).await,
            slip44::SOLANA => self.solana_update_transactions_receipt(txns).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                self.evm_estimate_params_batch(tx, sender, block_count, percentiles)
                    .await
            }
            slip44::BITCOIN => self.btc_estimate_params_batch(tx).await,
            slip44::TRON => self.tron_estimate_params_batch(tx, sender).await,
            slip44::SOLANA => self.solana_estimate_params_batch(tx, sender).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.slip_44
            ))),
        }
    }

    pub async fn broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                self.evm_broadcast_signed_transactions(txns).await
            }
            slip44::BITCOIN => self.btc_broadcast_signed_transactions(txns).await,
            slip44::TRON => self.tron_broadcast_signed_transactions(txns).await,
            slip44::SOLANA => self.solana_broadcast_signed_transactions(txns).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA | slip44::TRON => {
                self.evm_update_balances(tokens, accounts).await
            }
            slip44::BITCOIN => self.btc_update_balances(tokens, accounts).await,
            slip44::SOLANA => self.solana_update_balances(tokens, accounts).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA | slip44::TRON => {
                self.evm_ftoken_meta(contract, accounts).await
            }
            slip44::BITCOIN => Err(NetworkErrors::RPCError(
                "Bitcoin does not support tokens".to_string(),
            )),
            slip44::SOLANA => self.solana_ftoken_meta(contract, accounts).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn solana_get_latest_blockhash(&self) -> Result<String> {
        SolanaOperations::solana_get_latest_blockhash(self).await
    }

    pub async fn tron_fill_block_ref(&self, tx: &mut TronTransaction) -> Result<()> {
        TronOperations::tron_fill_block_ref(self, tx).await
    }

    #[inline]
    pub(crate) fn parse_str_to_u256(value: &str) -> Option<U256> {
        if value.starts_with("0x") {
            U256::from_str_radix(value.trim_start_matches("0x"), 16).ok()
        } else {
            U256::from_str_radix(value, 10).ok()
        }
    }
}

#[cfg(test)]
mod tests_network {
    use crate::evm::generate_erc20_transfer_data;

    use super::*;
    use alloy::{primitives::U256, rpc::types::TransactionInput};
    use config::address::ADDR_LEN;
    use history::status::TransactionStatus;
    use proto::{tx::ETHTransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::RngExt;
    use test_data::{
        gen_anvil_net_conf, gen_bsc_testnet_conf, gen_eth_mainnet_conf, gen_zil_mainnet_conf,
        gen_zil_testnet_conf,
    };
    use tokio;

    fn setup_temp_storage() -> Arc<LocalStorage> {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());

        let storage = LocalStorage::from(&dir).unwrap();
        Arc::new(storage)
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_bsc() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_eth_address("0xFa60D973F7642B748046464e165A65B7323b0DEE").unwrap();
        let account = [
            &Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap(),
            &Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&account[0].to_hash()).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&account[1].to_hash()).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "PancakeSwap Token");
        assert_eq!(&ftoken.symbol, "Cake");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_zil_legacy() {
        let net_conf = gen_zil_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap();
        let account = [
            &Address::from_zil_bech32("zil1gkwt95a67lnpe774lcmz72y6ay4jh2asmmjw6u").unwrap(),
            &Address::Secp256k1Sha256([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&account[0].to_hash()).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&account[1].to_hash()).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "ZilPay wallet");
        assert_eq!(&ftoken.symbol, "ZLP");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[test]
    fn test_empty_storage() {
        let storage = setup_temp_storage();
        let providers = NetworkProvider::load_network_configs(storage);
        assert!(providers.is_empty());
    }

    #[test]
    fn test_save_and_load_single_network() {
        let storage = setup_temp_storage();
        let config = gen_zil_testnet_conf();
        let providers = vec![NetworkProvider::new(config)];

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "Zilliqa(testnet)"));
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.chain_id() == 33101));
    }

    #[test]
    fn test_save_and_load_multiple_networks() {
        let storage = setup_temp_storage();

        let base_config = gen_zil_testnet_conf();
        let configs = [
            ChainConfig {
                name: "Test Network 1".to_string(),
                chain_ids: [1, 0],
                ..base_config.clone()
            },
            ChainConfig {
                name: "Test Network 2".to_string(),
                chain_ids: [2, 0],
                ..base_config.clone()
            },
            ChainConfig {
                name: "Test Network 3".to_string(),
                chain_ids: [3, 0],
                ..base_config.clone()
            },
        ];

        let providers: Vec<NetworkProvider> = configs
            .iter()
            .map(|conf| NetworkProvider::new(conf.clone()))
            .collect();

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert_eq!(loaded_providers.len(), 3);

        for provider in &loaded_providers {
            assert!(providers.contains(provider));
        }
    }

    #[test]
    fn test_update_networks() {
        let storage = setup_temp_storage();
        let base_config = gen_zil_testnet_conf();

        let mut providers = vec![NetworkProvider::new(ChainConfig {
            name: "Initial Network".to_string(),
            chain_ids: [1, 0],
            ..base_config.clone()
        })];

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        providers.push(NetworkProvider::new(ChainConfig {
            name: "New Network".to_string(),
            chain_ids: [2, 0],
            ..base_config.clone()
        }));

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));
        assert_eq!(loaded_providers.len(), 2);
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "Initial Network"));
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "New Network"));
    }

    #[tokio::test]
    async fn test_get_nonce_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let accounts = [
            Address::from_eth_address("0x2d09c57cB8EAf970dEEaf30546ec4dc3781c63cf").unwrap(),
            Address::from_eth_address("0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8").unwrap(),
            Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
        ];

        let payment_request = ETHTransactionRequest {
            to: Some(accounts[0].to_alloy_addr().into()),
            value: Some(U256::from(0u128)),
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((payment_request, Default::default()));

        let mut nonces = Vec::new();
        for account in &accounts {
            let params = provider
                .estimate_params_batch(&tx_request, account, 1, None)
                .await
                .unwrap();
            nonces.push(params.nonce);
        }

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &0);
    }

    #[tokio::test]
    async fn test_get_nonce_scilla() {
        let net_conf = gen_zil_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let accounts = [
            Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap(),
            Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap(),
            Address::Secp256k1Sha256([0u8; ADDR_LEN]),
        ];

        let zil_tx = ZILTransactionRequest {
            chain_id: provider.config.chain_id() as u16,
            nonce: 1,
            gas_price: 2000 * 10u128.pow(6),
            gas_limit: 100000,
            to_addr: accounts[0].clone(),
            amount: 0,
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let tx_req = TransactionRequest::Zilliqa((zil_tx, Default::default()));

        let mut nonces = Vec::new();
        for account in &accounts {
            let params = provider
                .estimate_params_batch(&tx_req, account, 1, None)
                .await
                .unwrap();
            nonces.push(params.nonce);
        }

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &12);
    }

    #[tokio::test]
    async fn test_estimate_gas_payment_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let sender =
            Address::from_eth_address("0x2d09c57cB8EAf970dEEaf30546ec4dc3781c63cf").unwrap();
        let payment_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((payment_request, Default::default()));
        let params = provider
            .estimate_params_batch(&tx_request, &sender, 1, None)
            .await
            .unwrap();

        assert_eq!("21000", params.tx_estimate_gas.to_string());
    }

    #[tokio::test]
    async fn test_estimate_gas_token_transfer() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let token_address =
            Address::from_eth_address("0x524bC91Dc82d6b90EF29F76A3ECAaBAffFD490Bc").unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let transfer_data = generate_erc20_transfer_data(&recipient, amount).unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(token_address.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            input: TransactionInput::new(transfer_data.into()),
            ..Default::default()
        };

        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));
        let params = provider
            .estimate_params_batch(&tx_request, &from, 1, None)
            .await
            .unwrap();

        assert!(params.tx_estimate_gas > U256::from(0));
    }

    #[tokio::test]
    async fn test_calc_fee_eth_batch() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let token_address =
            Address::from_eth_address("0x524bC91Dc82d6b90EF29F76A3ECAaBAffFD490Bc").unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let transfer_data = generate_erc20_transfer_data(&recipient, amount).unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(token_address.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            input: TransactionInput::new(transfer_data.into()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));
        assert_ne!(fee.max_priority_fee, U256::from(0));
        assert_ne!(fee.tx_estimate_gas, U256::from(0));
        assert_ne!(fee.blob_base_fee, U256::from(0));
        assert_ne!(fee.fee_history.max_fee, U256::from(0));
        assert_ne!(fee.fee_history.priority_fee, U256::from(0));
    }

    #[tokio::test]
    async fn test_get_tx_params_payment() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let recipient =
            Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(amount),
            chain_id: Some(provider.config.chain_id()),
            gas: None,
            nonce: None,
            transaction_type: Some(0x02),
            input: TransactionInput::default(),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            sidecar: None,
            access_list: None,
            authorization_list: None,
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));
        assert_ne!(fee.max_priority_fee, U256::from(0));
        assert_eq!(fee.tx_estimate_gas, U256::from(21000));
        assert_ne!(fee.blob_base_fee, U256::from(0));
        assert_ne!(fee.fee_history.max_fee, U256::from(0));
        assert_ne!(fee.fee_history.priority_fee, U256::from(0));

        let block_diff_time = provider.estimate_block_time(&recipient).await.unwrap();
        assert!(block_diff_time > 10 && block_diff_time < 18);
    }

    #[tokio::test]
    async fn test_calc_fee_bsc_batch() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x7b501c7944185130DD4aD73293e8Aa84eFfDcee7").unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));

        let block_diff_time = provider.estimate_block_time(&recipient).await.unwrap();
        assert!(block_diff_time >= 1 && block_diff_time < 5);
    }

    #[tokio::test]
    async fn test_get_tx_prams_scilla() {
        let net_conf = gen_zil_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let to = Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap();
        let from = Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap();
        let zil_tx = ZILTransactionRequest {
            chain_id: provider.config.chain_id() as u16,
            nonce: 1,
            gas_price: 2000 * 10u128.pow(6),
            gas_limit: 100000,
            to_addr: to,
            amount: 10u128.pow(12),
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let tx_req = TransactionRequest::Zilliqa((zil_tx, Default::default()));
        let params = provider
            .estimate_params_batch(&tx_req, &from, 4, None)
            .await
            .unwrap();

        assert_eq!(params.gas_price, U256::from(2000000016));
        assert!(params.nonce > 74310);

        let block_diff_time = provider.estimate_block_time(&from).await.unwrap();
        assert!(block_diff_time > 1 && block_diff_time < 18);
    }

    #[tokio::test]
    async fn test_tx_receipt_evm() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let tx_hash = "0xbee2eb00d77c45be11e037efe8459ae5b61f36af1483d705ee89e9d40a1f3715";
        let mut tx_history = HistoricalTransaction {
            metadata: proto::tx::TransactionMetadata {
                chain_hash: provider.config.hash(),
                hash: Some(tx_hash.to_string()),
                ..Default::default()
            },
            evm: Some(
                serde_json::json!({
                    "transactionHash": tx_hash,
                })
                .to_string(),
            ),
            ..Default::default()
        };
        assert!(tx_history.metadata.broadcast);
        let mut list_txns = vec![&mut tx_history];

        provider
            .update_transactions_receipt(&mut list_txns)
            .await
            .unwrap();

        let evm = list_txns.first().unwrap().get_evm().unwrap();
        let gas_used = evm
            .get("gasUsed")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        assert_eq!(gas_used, Some(21000));
        let block_number = evm
            .get("blockNumber")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        assert_eq!(block_number, Some(21855983));
        assert_eq!(
            evm.get("transactionHash").and_then(|v| v.as_str()),
            Some(tx_hash)
        );
        assert_eq!(
            list_txns.first().unwrap().status,
            TransactionStatus::Success
        );
    }

    #[tokio::test]
    async fn test_get_block_number_scilla() {
        let net_conf = gen_zil_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let block_number = provider.get_current_block_number().await.unwrap();
        assert!(block_number != 0);
    }

    #[tokio::test]
    async fn test_get_block_number_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let _block_number = provider.get_current_block_number().await.unwrap();
    }
}
