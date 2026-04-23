use crate::{bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use config::session::AuthMethod;
use crypto::{bip49::DerivationPath, slip44};
use errors::{background::BackgroundError, wallet::WalletErrors};
use network::{common::Provider, provider::NetworkProvider};
use proto::address::Address;
use rpc::network_config::ChainConfig;
use secrecy::SecretString;
use std::sync::Arc;
use wallet::{
    wallet_account::AccountManagement, wallet_storage::StorageOperations, wallet_types::WalletTypes,
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
        password: Option<&SecretString>,
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
        let mut existing: std::collections::HashSet<u64> =
            providers.iter().map(|p| p.config.hash()).collect();
        let mut added = Vec::new();

        for mut config in configs {
            let hash = config.hash();
            if !existing.insert(hash) {
                continue;
            }
            config.ftokens.iter_mut().for_each(|t| {
                t.chain_hash = hash;
            });
            providers.push(NetworkProvider::new(config));
            added.push(hash);
        }

        if !added.is_empty() {
            self.update_providers(providers)?;
        }

        Ok(added)
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
        password: Option<&SecretString>,
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
            let exists = ftokens
                .iter()
                .any(|t| t.addr == provider_ftoken.addr && t.chain_hash == provider_ftoken.chain_hash);
            if !exists {
                ftokens.insert(0, provider_ftoken.clone());
            }
        }

        let new_slip44 = provider.config.slip_44;
        data.bip_preferences.insert(data.slip44, data.bip);

        let new_bip = if let Some(&saved) = data.bip_preferences.get(&new_slip44) {
            saved
        } else {
            DerivationPath::default_bip(new_slip44)
        };

        data.slip44 = new_slip44;
        data.bip = new_bip;
        data.chain_hash = chain_hash;

        let has_accounts = data
            .slip44_accounts
            .get(&new_slip44)
            .and_then(|bip_map| bip_map.get(&new_bip))
            .is_some_and(|accounts| !accounts.is_empty());

        if !has_accounts {
            let seed = if data.biometric_type != AuthMethod::None {
                self.unlock_wallet_with_session(wallet_index).await?
            } else if let Some(pass) = password {
                self.unlock_wallet_with_password(pass, None, wallet_index)
                    .await?
            } else {
                return Err(BackgroundError::AuthenticationRequired);
            };

            wallet.ensure_chain_accounts(
                &mut data,
                new_slip44,
                provider.config.bitcoin_network(),
                &seed,
                "",
            )?;
        }

        if new_slip44 == slip44::BITCOIN {
            if let Some(new_network) = provider.config.bitcoin_network() {
                if let Some(bip_map) = data.slip44_accounts.get_mut(&new_slip44) {
                    for accounts in bip_map.values_mut() {
                        for account in accounts.iter_mut() {
                            if let Address::Secp256k1Bitcoin(_) = &account.addr {
                                if let Ok(current_network) = account.addr.get_bitcoin_network() {
                                    if current_network != new_network {
                                        account.addr =
                                            account.addr.re_encode_btc_network(new_network)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

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
        gen_anvil_net_conf, gen_btc_testnet_conf, gen_tron_testnet_conf, gen_zil_testnet_conf,
        ANVIL_MNEMONIC, TEST_PASSWORD,
    };

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

    #[tokio::test]
    async fn test_select_chain_derive_missing() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc = gen_btc_testnet_conf();
        let trx = gen_tron_testnet_conf();

        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string()), (1, "acc 1".to_string())];
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: btc.ftokens.clone(),
            bip: DerivationPath::BIP86_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert!(data.slip44_accounts.contains_key(&btc.slip_44));
        assert!(!data.slip44_accounts.contains_key(&trx.slip_44));

        bg.add_provider(trx.clone()).unwrap();

        bg.select_accounts_chain(0, trx.hash(), Some(&password))
            .await
            .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.slip44, trx.slip_44);
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);
        assert_eq!(data.chain_hash, trx.hash());
        assert!(data.slip44_accounts.contains_key(&trx.slip_44));
        assert_eq!(
            data.bip_preferences.get(&btc.slip_44),
            Some(&DerivationPath::BIP86_PURPOSE)
        );

        let tron_accounts = data.get_accounts().unwrap();
        assert_eq!(tron_accounts.len(), 2);
        assert_eq!(tron_accounts[0].name, "acc 0");
        assert_eq!(tron_accounts[1].name, "acc 1");

        assert!(data.slip44_accounts.contains_key(&btc.slip_44));

        bg.select_accounts_chain(0, btc.hash(), None).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.slip44, btc.slip_44);
        assert_eq!(data.chain_hash, btc.hash());
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);

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
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP86_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        bg.select_accounts_chain(0, trx.hash(), Some(&password))
            .await
            .unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);

        bg.select_accounts_chain(0, btc.hash(), None).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);

        bg.select_accounts_chain(0, eth.hash(), Some(&password))
            .await
            .unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP44_PURPOSE);

        bg.select_accounts_chain(0, btc.hash(), None).await.unwrap();
        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
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
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: eth.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: vec![],
            bip: DerivationPath::BIP44_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        bg.select_accounts_chain(0, btc.hash(), Some(&password))
            .await
            .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
    }

    #[tokio::test]
    async fn test_select_chain_no_password_returns_auth_required() {
        let (mut bg, _) = setup_test_background();
        let password: SecretString = SecretString::new(TEST_PASSWORD.into());
        let btc = gen_btc_testnet_conf();
        let eth = gen_anvil_net_conf();

        bg.add_provider(btc.clone()).unwrap();

        let accounts = [(0, "acc 0".to_string())];
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: &password,
            chain_hash: btc.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            ftokens: btc.ftokens.clone(),
            bip: DerivationPath::BIP86_PURPOSE,
            derivation_type: crypto::bip49::default_derivation_type(),
        })
        .await
        .unwrap();

        bg.add_provider(eth.clone()).unwrap();

        let result = bg.select_accounts_chain(0, eth.hash(), None).await;

        assert!(matches!(
            result,
            Err(BackgroundError::AuthenticationRequired)
        ));
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
            bip: DerivationPath::BIP44_PURPOSE,
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

        bg.select_accounts_chain(0, btc.hash(), Some(&password))
            .await
            .unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, slip44::BITCOIN);
        assert_eq!(data.chain_hash, btc.hash());
        assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
        assert!(data.slip44_accounts.contains_key(&slip44::BITCOIN));
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            data.bip_preferences.get(&slip44::ZILLIQA),
            Some(&DerivationPath::BIP44_PURPOSE)
        );

        bg.select_accounts_chain(0, zil.hash(), None).await.unwrap();

        let data = bg
            .get_wallet_by_index(0)
            .unwrap()
            .get_wallet_data()
            .unwrap();
        assert_eq!(data.slip44, slip44::ZILLIQA);
        assert_eq!(data.get_accounts().unwrap().len(), 1);
        assert_eq!(
            data.bip_preferences.get(&slip44::BITCOIN),
            Some(&DerivationPath::BIP86_PURPOSE)
        );
    }
}
