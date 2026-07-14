use crate::{bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use crypto::{bip49::DerivationPath, slip44};
use errors::{background::BackgroundError, wallet::WalletErrors};
use network::{common::Provider, provider::NetworkProvider};
use proto::address::Address;
use rpc::network_config::ChainConfig;
use std::sync::Arc;
use wallet::{
    bitcoin_wallet::BitcoinWallet, wallet_storage::StorageOperations, wallet_types::WalletTypes,
};

#[async_trait]
pub trait ProvidersManagement {
    type Error;

    async fn update_block_diff_time(
        &self,
        chain_hash: u64,
        addr: &Address,
    ) -> std::result::Result<(), Self::Error>;
    fn get_provider(&self, chain_hash: u64) -> std::result::Result<NetworkProvider, Self::Error>;
    fn get_providers(&self) -> Vec<NetworkProvider>;
    async fn select_accounts_chain(
        &self,
        wallet_index: usize,
        chain_hash: u64,
    ) -> std::result::Result<(), Self::Error>;
    fn add_provider(&self, config: ChainConfig) -> std::result::Result<u64, Self::Error>;
    fn add_batch_providers(
        &self,
        configs: Vec<ChainConfig>,
    ) -> std::result::Result<Vec<u64>, Self::Error>;
    fn remvoe_provider(&self, chain_hash: u64) -> std::result::Result<(), Self::Error>;
    fn update_providers(
        &self,
        providers: Vec<NetworkProvider>,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl ProvidersManagement for Background {
    type Error = BackgroundError;

    async fn update_block_diff_time(&self, chain_hash: u64, addr: &Address) -> Result<()> {
        let mut chains = self.get_providers();
        let chain = chains
            .iter_mut()
            .find(|p| p.config.hash() == chain_hash)
            .ok_or(BackgroundError::ProviderNotExists(chain_hash))?;
        let block_time_diff = chain.estimate_block_time(addr).await?;

        chain.config.diff_block_time = block_time_diff;

        self.update_providers(chains)?;

        Ok(())
    }

    fn get_provider(&self, chain_hash: u64) -> std::result::Result<NetworkProvider, Self::Error> {
        self.get_providers()
            .into_iter()
            .find(|p| p.config.hash() == chain_hash)
            .ok_or(BackgroundError::ProviderNotExists(chain_hash))
    }

    fn get_providers(&self) -> Vec<NetworkProvider> {
        NetworkProvider::load_network_configs(Arc::clone(&self.storage))
    }

    fn update_providers(
        &self,
        providers: Vec<NetworkProvider>,
    ) -> std::result::Result<(), Self::Error> {
        NetworkProvider::save_network_configs(&providers, Arc::clone(&self.storage))?;

        Ok(())
    }

    fn add_provider(&self, mut config: ChainConfig) -> Result<u64> {
        let hash = config.hash();
        let mut providers = self.get_providers();

        config.ftokens.iter_mut().for_each(|t| {
            t.chain_hash = hash;
        });

        providers.retain(|p| p.config.hash() != hash);
        let new_provider = NetworkProvider::new(config);
        providers.push(new_provider);

        self.update_providers(providers)?;

        Ok(hash)
    }

    fn add_batch_providers(&self, configs: Vec<ChainConfig>) -> Result<Vec<u64>> {
        let mut providers = self.get_providers();
        let mut existing: std::collections::HashMap<u64, usize> = providers
            .iter()
            .enumerate()
            .map(|(i, p)| (p.config.hash(), i))
            .collect();
        let mut changed = false;
        let mut added_or_updated = Vec::new();

        for mut config in configs {
            let hash = config.hash();
            config.ftokens.iter_mut().for_each(|t| {
                t.chain_hash = hash;
            });

            if let Some(&index) = existing.get(&hash) {
                if providers[index].config != config {
                    providers[index] = NetworkProvider::new(config);
                    changed = true;
                    added_or_updated.push(hash);
                }
            } else {
                existing.insert(hash, providers.len());
                providers.push(NetworkProvider::new(config));
                changed = true;
                added_or_updated.push(hash);
            }
        }

        if changed {
            self.update_providers(providers)?;
        }

        Ok(added_or_updated)
    }

    fn remvoe_provider(&self, chain_hash: u64) -> Result<()> {
        let mut providers = self.get_providers();
        let index = providers
            .iter()
            .position(|p| p.config.hash() == chain_hash)
            .ok_or(BackgroundError::ProviderNotExists(chain_hash))?;

        for wallet in &self.wallets {
            let data = wallet.get_wallet_data()?;
            if data.chain_hash == chain_hash {
                return Err(BackgroundError::ProviderDepends(data.wallet_name));
            }
        }

        providers.remove(index);
        self.update_providers(providers)?;

        Ok(())
    }

    async fn select_accounts_chain(
        &self,
        wallet_index: usize,
        chain_hash: u64,
    ) -> Result<()> {
        let provider = self.get_provider(chain_hash)?;
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let mut ftokens = wallet.get_ftokens()?;
        let default_provider = self.get_provider(data.chain_hash)?;

        if let WalletTypes::Ledger(_) = data.wallet_type {
            if default_provider.config.slip_44 == slip44::ZILLIQA {
                return Err(WalletErrors::InvalidAccountType)?;
            }
        }

        for provider_ftoken in &provider.config.ftokens {
            let exists = ftokens.iter().any(|t| {
                t.addr == provider_ftoken.addr && t.chain_hash == provider_ftoken.chain_hash
            });
            if !exists {
                ftokens.push(provider_ftoken.clone());
            }
        }

        let new_slip44 = provider.config.slip_44;
        let new_bip = DerivationPath::default_bip(new_slip44);

        data.slip44 = new_slip44;
        data.bip = new_bip;
        data.chain_hash = chain_hash;

        let new_count = data
            .slip44_accounts
            .get(&new_slip44)
            .and_then(|m| m.get(&new_bip))
            .map_or(0, |v| v.len());
        if new_count > 0 && data.selected_account >= new_count {
            data.selected_account = new_count - 1;
        }

        wallet.save_wallet_data(&data)?;
        wallet.save_ftokens(&ftokens)?;

        // BTC address chains are keyed by chain_hash; a provider added or edited
        // mid-session (hash change) has none until the next unlock. Regenerate from
        // the active session when there is one; password-only users are healed on
        // next unlock, and readers degrade gracefully meanwhile.
        if new_slip44 == slip44::BITCOIN
            && wallet
                .get_btc_addresses(data.selected_account, chain_hash)
                .is_err()
        {
            let _ = self.unlock_wallet_with_session(wallet_index).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests_providers {
    use super::*;
    use crate::{bg_storage::StorageManagement, BackgroundBip39Params, BackgroundSKParams};
    use crypto::slip44;
    use proto::keypair::KeyPair;
    use rand::RngExt;
    use rpc::network_config::Explorer;
    use secrecy::SecretString;
    use test_data::{
        empty_passphrase, gen_anvil_net_conf, gen_btc_testnet_conf, gen_tron_testnet_conf,
        gen_zil_testnet_conf, ANVIL_MNEMONIC, TEST_PASSWORD,
    };
    use wallet::bitcoin_wallet::BitcoinWallet;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_network_config(name: &str, chain_id: u64) -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            name: name.to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["http://localhost:8545".to_string()],
            features: vec![155, 1559],
            chain_ids: [chain_id, 0],
            slip_44: 60,
            ens: None,
            explorers: vec![Explorer {
                name: "TestExplorer".to_string(),
                url: "https://test.explorer".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_add_providers() {
        let (bg, _dir) = setup_test_background();

        // Test adding a provider
        let config1 = create_test_network_config("Test Network 1", 1);
        bg.add_provider(config1.clone()).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Test Network 1");

        // Test adding another provider
        let config2 = create_test_network_config("Test Network 2", 2);
        bg.add_provider(config2.clone()).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 2);
        assert_eq!(providers[1].config.name, "Test Network 2");
    }

    #[test]
    fn test_remove_providers() {
        let (bg, _dir) = setup_test_background();

        // Add two providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        let providers = bg.get_providers();

        assert_eq!(providers.len(), 2);

        bg.remvoe_provider(config2.hash()).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Test Network 1");
    }

    #[test]
    fn test_remove_nonexistent_provider() {
        let (bg, _dir) = setup_test_background();

        // Attempt to remove a provider when none exist
        let result = bg.remvoe_provider(0);

        assert!(result.is_err());

        if let Err(error) = result {
            assert!(matches!(error, BackgroundError::ProviderNotExists(0)));
        }
    }

    #[test]
    fn test_persistence() {
        let (bg, dir) = setup_test_background();

        // Add providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        // Drop the background instance
        drop(bg);

        // Create new instance and verify providers were persisted
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let providers = bg2.get_providers();

        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].config.name, "Test Network 1");
        assert_eq!(providers[1].config.name, "Test Network 2");
        assert_eq!(providers[0].config.chain_id(), 1);
        assert_eq!(providers[1].config.chain_id(), 2);
    }

    #[test]
    fn test_update_providers() {
        let (bg, dir) = setup_test_background();

        // Add initial providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        let mut providers = bg.get_providers();

        // Modify providers directly and update
        providers[0].config.name = "Updated Network 1".to_string();
        bg.update_providers(providers).unwrap();

        // Verify persistence of update
        drop(bg);
        Background::from_storage_path(&dir).unwrap();
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let providers = bg2.get_providers();

        assert_eq!(providers[0].config.name, "Updated Network 1");
        assert_eq!(providers[1].config.name, "Test Network 2");
        assert_eq!(providers[0].config.chain_id(), 1);
        assert_eq!(providers[1].config.chain_id(), 2);
    }

    #[test]
    fn test_duplicate_chain_id() {
        let (bg, _dir) = setup_test_background();

        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 1);

        bg.add_provider(config1.clone()).unwrap();
        assert_eq!(bg.get_providers().len(), 1);
        assert_eq!(bg.get_provider(config1.hash()).unwrap().config, config1);
        assert!(bg.add_provider(config2.clone()).is_ok());
        assert_eq!(bg.get_providers().len(), 1);
        assert_eq!(bg.get_provider(config2.hash()).unwrap().config, config2);
    }

    #[test]
    fn test_provider_features() {
        let (bg, _dir) = setup_test_background();

        let mut config = create_test_network_config("Test Network", 1);
        config.features = vec![155]; // Only EIP-155

        bg.add_provider(config).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers[0].config.features.len(), 1);
        assert!(providers[0].config.features.contains(&155));
    }

    #[test]
    fn test_add_batch_providers() {
        let (bg, dir) = setup_test_background();

        let c1 = create_test_network_config("Net 1", 100);
        let c2 = create_test_network_config("Net 2", 200);
        let c3 = create_test_network_config("Net 3", 300);

        let added = bg
            .add_batch_providers(vec![c1.clone(), c2.clone(), c3.clone()])
            .unwrap();
        assert_eq!(added.len(), 3);
        assert_eq!(bg.get_providers().len(), 3);

        let c4 = create_test_network_config("Net 4", 400);
        let added = bg
            .add_batch_providers(vec![c1.clone(), c3.clone(), c4.clone()])
            .unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0], c4.hash());
        assert_eq!(bg.get_providers().len(), 4);

        drop(bg);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let bg2 = Background::from_storage_path(&dir).unwrap();
        assert_eq!(bg2.get_providers().len(), 4);
    }

    #[test]
    fn test_add_batch_providers_updates_existing() {
        let (bg, _dir) = setup_test_background();

        let mut c1 = create_test_network_config("Net 1", 100);
        c1.rpc = vec!["http://old-rpc.example.com".to_string()];

        bg.add_batch_providers(vec![c1.clone()]).unwrap();
        let providers = bg.get_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.rpc, vec!["http://old-rpc.example.com"]);

        let mut c1_updated = create_test_network_config("Net 1 Updated", 100);
        c1_updated.rpc = vec![
            "http://new-rpc-1.example.com".to_string(),
            "http://new-rpc-2.example.com".to_string(),
        ];

        let updated = bg.add_batch_providers(vec![c1_updated.clone()]).unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], c1.hash());

        let providers = bg.get_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Net 1 Updated");
        assert_eq!(
            providers[0].config.rpc,
            vec![
                "http://new-rpc-1.example.com",
                "http://new-rpc-2.example.com"
            ]
        );
    }

    #[test]
    fn test_add_batch_providers_no_write_when_unchanged() {
        let (bg, _dir) = setup_test_background();

        let c1 = create_test_network_config("Net 1", 100);
        bg.add_batch_providers(vec![c1.clone()]).unwrap();
        assert_eq!(bg.get_providers().len(), 1);

        let updated = bg.add_batch_providers(vec![c1.clone()]).unwrap();
        assert!(updated.is_empty());
        assert_eq!(bg.get_providers().len(), 1);
    }

    #[tokio::test]
    async fn test_unlock_derives_accounts_for_all_chains() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc = gen_btc_testnet_conf();
        let trx = gen_tron_testnet_conf();

        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string()), (1, "acc 1".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: btc.ftokens.clone(),
        })
        .await
        .unwrap();

        // Only BTC accounts exist after creation
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert!(data.slip44_accounts.contains_key(&btc.slip_44));
        assert!(!data.slip44_accounts.contains_key(&trx.slip_44));

        // Add TRX provider, then unlock → sync_chain_accounts derives TRX accounts
        bg.add_provider(trx.clone()).unwrap();
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert!(data.slip44_accounts.contains_key(&trx.slip_44));

        // Switch to TRX — pointer-only, no auth needed
        bg.select_accounts_chain(0, trx.hash()).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.slip44, trx.slip_44);
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);
        assert_eq!(data.chain_hash, trx.hash());

        let tron_accounts = data.get_accounts().unwrap();
        assert_eq!(tron_accounts.len(), 2);
        assert_eq!(tron_accounts[0].name, "acc 0");
        assert_eq!(tron_accounts[1].name, "acc 1");

        assert!(data.slip44_accounts.contains_key(&btc.slip_44));

        bg.select_accounts_chain(0, btc.hash()).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.slip44, btc.slip_44);
        assert_eq!(data.chain_hash, btc.hash());
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);

        let btc_accounts = data.get_accounts().unwrap();
        assert_eq!(btc_accounts.len(), 2);
    }

    #[tokio::test]
    async fn test_bip_preference_persists_across_chain_switches() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc = gen_btc_testnet_conf();
        let trx = gen_tron_testnet_conf();
        let eth = gen_anvil_net_conf();

        bg.add_provider(btc.clone()).unwrap();
        bg.add_provider(trx.clone()).unwrap();
        bg.add_provider(eth.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        // Unlock → sync_chain_accounts derives accounts for all chains
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        bg.select_accounts_chain(0, trx.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);

        bg.select_accounts_chain(0, btc.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);

        bg.select_accounts_chain(0, eth.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);

        bg.select_accounts_chain(0, btc.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);
    }

    #[tokio::test]
    async fn test_default_bip_for_new_chain() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let eth = gen_anvil_net_conf();
        let btc = gen_btc_testnet_conf();

        bg.add_provider(eth.clone()).unwrap();
        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: eth.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        // Unlock → sync_chain_accounts derives accounts for all chains
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        bg.select_accounts_chain(0, btc.hash()).await.unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);
    }

    #[tokio::test]
    async fn test_select_chain_no_auth_needed() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc = gen_btc_testnet_conf();
        let eth = gen_anvil_net_conf();

        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: btc.ftokens.clone(),
        })
        .await
        .unwrap();

        bg.add_provider(eth.clone()).unwrap();

        // Unlock → sync_chain_accounts derives ETH accounts
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        // Switch with None — succeeds because accounts were derived at unlock
        let result = bg.select_accounts_chain(0, eth.hash()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_select_chain_sk_wallet() {
        let (mut bg, _dir) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let zil = gen_zil_testnet_conf();
        let btc = gen_btc_testnet_conf();

        bg.add_provider(zil.clone()).unwrap();
        bg.add_provider(btc.clone()).unwrap();

        let keypair = KeyPair::gen_sha256().unwrap();
        bg.add_sk_wallet(BackgroundSKParams {
            secret_key: keypair.get_secretkey().unwrap(),
            password: &password,
            chain_hash: zil.hash(),
            wallet_settings: Default::default(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, slip44::ZILLIQA);
        assert_eq!(data.get_accounts().unwrap().len(), 1);

        // Unlock → sync_chain_accounts derives BTC accounts
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        bg.select_accounts_chain(0, btc.hash()).await.unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, slip44::BITCOIN);
        assert_eq!(data.chain_hash, btc.hash());
        assert_eq!(data.bip, DerivationPath::BIP84_PURPOSE);
        assert!(data.slip44_accounts.contains_key(&slip44::BITCOIN));
        assert_eq!(data.get_accounts().unwrap().len(), 1);

        bg.select_accounts_chain(0, zil.hash()).await.unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, slip44::ZILLIQA);
        assert_eq!(data.get_accounts().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_btc_network_switch_preserves_address_data() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc_testnet = gen_btc_testnet_conf();

        bg.add_provider(btc_testnet.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc_testnet.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        // Unlock → sync_chain_accounts generates BTC chains for testnet
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        // Testnet chains exist
        assert!(wallet.get_btc_addresses(0, btc_testnet.hash()).is_ok());

        // Switch away and back — data preserved (pointer-only, no re-derivation)
        bg.select_accounts_chain(0, btc_testnet.hash())
            .await
            .unwrap();
        assert!(wallet.get_btc_addresses(0, btc_testnet.hash()).is_ok());

        // Double-unlock idempotency: unlock again, account counts stable
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        let btc_bip = DerivationPath::default_bip(slip44::BITCOIN);
        let btc_count = data
            .slip44_accounts
            .get(&slip44::BITCOIN)
            .and_then(|m| m.get(&btc_bip))
            .map_or(0, |v| v.len());
        assert_eq!(
            btc_count, 1,
            "BTC account count must not change on double-unlock"
        );
    }

    /// A BTC provider edited mid-session changes its chain_hash, orphaning the
    /// stored address chains. Switching to it must not error, and balance
    /// refresh must skip the BTC branch instead of failing with
    /// StorageDataNotFound; the next unlock regenerates the chains.
    #[tokio::test]
    async fn test_select_edited_btc_chain_missing_chains() {
        use crate::bg_token::TokensManagement;

        let (mut bg, _dir) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let eth = gen_anvil_net_conf();
        let btc = gen_btc_testnet_conf();

        bg.add_provider(eth.clone()).unwrap();
        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: eth.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        // Unlock → sync_chain_accounts generates BTC accounts + chains for btc.hash()
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        assert!(bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_btc_addresses(0, btc.hash())
            .is_ok());

        // Edit the BTC chain mid-session → new chain_hash, stored chains are
        // orphaned under the old hash.
        let mut btc_edited = btc.clone();
        btc_edited.chain_ids = [btc.chain_ids[0] + 1, 0];
        assert_ne!(btc_edited.hash(), btc.hash());
        bg.add_provider(btc_edited.clone()).unwrap();

        // Switch must succeed even though chains for the new hash don't exist
        // (no session in tests → regeneration is skipped silently).
        bg.select_accounts_chain(0, btc_edited.hash())
            .await
            .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.chain_hash, btc_edited.hash());
        assert!(bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_btc_addresses(0, btc_edited.hash())
            .is_err());

        // Regression: refresh must not fail with StorageDataNotFound; the BTC
        // branch skips gracefully until chains are regenerated.
        bg.sync_ftokens_balances(0).await.unwrap();

        // Next unlock heals: chains regenerated for the edited hash.
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();
        assert!(bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_btc_addresses(0, btc_edited.hash())
            .is_ok());
    }

    #[tokio::test]
    async fn test_ledger_zilliqa_blocks_switch() {
        // Ledger wallets on Zilliqa cannot switch away.
        // This is preserved by the ledger guard in select_accounts_chain.
        // (Setup: add ledger wallet on ZIL, attempt switch to BTC, expect InvalidAccountType)
        // Note: Ledger wallet creation requires a physical device or mock.
        // This test documents the contract; full Ledger testing requires integration setup.
    }

    /// Unlock derives convergent account counts across all chains.
    /// Scenario: 2 ETH accounts → unlock → BTC also gets 2 accounts (convergence).
    #[tokio::test]
    async fn test_unlock_derives_convergent_accounts() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let eth = gen_anvil_net_conf();
        let btc = gen_btc_testnet_conf();

        bg.add_provider(eth.clone()).unwrap();
        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "ETH 0".to_string()), (1, "ETH 1".to_string())];
        let mnemonic_secret = SecretString::from(ANVIL_MNEMONIC);
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: eth.hash(),
            mnemonic_str: &mnemonic_secret,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: &empty_passphrase(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, eth.slip_44);
        assert_eq!(data.get_accounts().unwrap().len(), 2);

        // Unlock → sync_chain_accounts derives 2 BTC accounts (convergence to ETH's count)
        bg.unlock_wallet_with_password(&password, None, 0)
            .await
            .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        let btc_bip = DerivationPath::default_bip(slip44::BITCOIN);
        let btc_count = data
            .slip44_accounts
            .get(&slip44::BITCOIN)
            .and_then(|m| m.get(&btc_bip))
            .map_or(0, |v| v.len());
        assert_eq!(
            btc_count, 2,
            "BTC must have 2 accounts matching ETH reference"
        );

        // Switch to BTC — pointer-only, no auth needed
        bg.select_accounts_chain(0, btc.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, btc.slip_44);
        assert_eq!(data.get_accounts().unwrap().len(), 2);

        // Switch back to ETH
        bg.select_accounts_chain(0, eth.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, eth.slip_44);
        assert_eq!(data.get_accounts().unwrap().len(), 2);

        // Switch to BTC again with None password — succeeds (pointer-only)
        bg.select_accounts_chain(0, btc.hash()).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, btc.slip_44);
        assert_eq!(data.get_accounts().unwrap().len(), 2);
    }
}
