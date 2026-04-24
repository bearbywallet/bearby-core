use crate::{wallet_storage::StorageOperations, Result, Wallet, WalletAddrType};
use config::storage::FTOKENS_DB_KEY_V1;
use errors::wallet::WalletErrors;
use token::ft::FToken;

/// Token handling operations
pub trait TokenManagement {
    type Error;

    fn add_ftoken(&self, token: FToken) -> std::result::Result<(), Self::Error>;
    fn remove_ftoken(&self, index: usize) -> std::result::Result<(), Self::Error>;
    fn get_token_db_key(key: &WalletAddrType) -> Vec<u8>;
}

impl TokenManagement for Wallet {
    type Error = WalletErrors;

    fn add_ftoken(&self, token: FToken) -> Result<()> {
        let mut ftokens = self.get_ftokens()?;

        if ftokens.iter().any(|t| t.addr == token.addr) {
            return Err(WalletErrors::TokenAlreadyExists(token.addr.auto_format()));
        }

        ftokens.push(token);
        self.save_ftokens(&ftokens)?;

        Ok(())
    }

    fn remove_ftoken(&self, index: usize) -> Result<()> {
        let mut ftokens = self.get_ftokens()?;
        let mb_token = ftokens.get(index);

        if mb_token.is_none() {
            return Err(WalletErrors::TokenNotExists(index));
        }

        if let Some(token) = mb_token {
            if token.default {
                return Err(WalletErrors::DefaultTokenRemove(index));
            }
        }

        ftokens.remove(index);
        self.save_ftokens(&ftokens)?;

        Ok(())
    }

    #[inline]
    fn get_token_db_key(key: &WalletAddrType) -> Vec<u8> {
        [key, FTOKENS_DB_KEY_V1].concat()
    }
}

#[cfg(test)]
mod tests_wallet_tokens {
    use std::sync::Arc;

    use alloy::primitives::map::HashMap;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use config::{
        address::ADDR_LEN,
        cipher::{PROOF_SALT, PROOF_SIZE},
        session::AuthMethod,
    };
    use errors::wallet::WalletErrors;
    use proto::{address::Address, keypair::KeyPair};
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use settings::wallet_settings::WalletSettings;
    use storage::LocalStorage;
    use test_data::TEST_PASSWORD;
    use token::ft::FToken;

    use crate::{
        wallet_init::WalletInit, wallet_security::WalletSecurity,
        wallet_storage::StorageOperations, wallet_token::TokenManagement, SecretKeyParams, Wallet,
        WalletConfig,
    };

    fn gen_bsc_token() -> FToken {
        FToken {
            rate: 0f64,
            chain_hash: 0,
            default: true,
            name: "Binance Smart Chain".to_string(),
            symbol: "BSC".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[test]
    fn test_add_and_load_tokens() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();

        // Generate ETH keypair for test wallet
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };
        let chain_config = ChainConfig::default();

        // Create wallet
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: "Test Token Account".to_string(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![gen_bsc_token()],
        )
        .unwrap();
        let ftokens = wallet.get_ftokens().unwrap();

        // Verify initial state - should only have default ETH token
        assert_eq!(ftokens.len(), 1);
        assert!(ftokens[0].default);
        assert_eq!(ftokens[0].symbol, "BSC");

        // Create custom token
        let custom_token = FToken {
            rate: 0f64,
            name: "Test Token".to_string(),
            symbol: "TST".to_string(),
            decimals: 18,
            addr: Address::from_zil_base16("e876b112a62f945484ede1f3ccdd6b0ac6f39382").unwrap(),
            logo: None,
            default: false,
            native: false,
            balances: HashMap::new(),
            chain_hash: 0,
        };

        // Add custom token
        wallet.add_ftoken(custom_token.clone()).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();

        // Verify token was added
        assert_eq!(ftokens.len(), 2);
        assert_eq!(ftokens[1].symbol, "TST");
        assert!(!ftokens[1].default);

        // Save wallet state
        let wallet_addr = wallet.wallet_address;

        // Create new wallet instance from storage
        let loaded_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();
        let ftokens = loaded_wallet.get_ftokens().unwrap();

        // Unlock wallet - should restore tokens
        loaded_wallet.unlock(&argon_seed).unwrap();

        // Verify tokens were restored correctly
        assert_eq!(ftokens.len(), 2);

        // Verify default token
        assert!(ftokens[0].default);
        assert_eq!(ftokens[0].symbol, "BSC");

        // Verify custom token
        assert!(!ftokens[1].default);
        assert_eq!(ftokens[1].symbol, "TST");
        assert_eq!(ftokens[1].addr, custom_token.addr);
        assert_eq!(ftokens[1].decimals, custom_token.decimals);
    }

    #[test]
    fn test_multiple_custom_tokens() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };

        // Add multiple custom tokens
        let tokens = vec![
            gen_bsc_token(),
            FToken {
                rate: 0f64,
                name: "Token 1".to_string(),
                symbol: "TK1".to_string(),
                decimals: 18,
                addr: Address::from_zil_base16("1111111111111111111111111111111111111111").unwrap(),
                native: true,
                logo: None,
                default: false,
                balances: HashMap::new(),
                chain_hash: 0,
            },
            FToken {
                rate: 0f64,
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                native: true,
                logo: None,
                default: false,
                balances: HashMap::new(),
                chain_hash: 0,
            },
            FToken {
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                native: true,
                addr: Address::from_zil_base16("3333333333333333333333333333333333333333").unwrap(),
                logo: None,
                default: false,
                rate: 0f64,
                balances: HashMap::new(),
                chain_hash: 0,
            },
        ];

        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: "Test Token Account".to_string(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
            },
            wallet_config,
            tokens.clone(),
        )
        .unwrap();
        let ftokens = wallet.get_ftokens().unwrap();

        // Verify all tokens were added (1 default + 3 custom)
        assert_eq!(ftokens.len(), 4);

        // Save and reload wallet
        let wallet_addr = wallet.wallet_address;

        drop(wallet);

        let loaded_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();

        loaded_wallet.unlock(&argon_seed).unwrap();

        let ftokens = loaded_wallet.get_ftokens().unwrap();

        // Verify all tokens were restored
        assert_eq!(ftokens.len(), 4);

        // Verify default token
        assert!(ftokens[0].default);
        assert_eq!(ftokens[0].symbol, "BSC");

        // Verify custom tokens
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(ftokens[i].name, token.name);
            assert_eq!(ftokens[i].symbol, token.symbol);
            assert_eq!(ftokens[i].decimals, token.decimals);
            assert_eq!(ftokens[i].addr, token.addr);

            if i == 0 {
                assert!(ftokens[i].default);
            } else {
                assert!(!ftokens[i].default);
            }
        }
    }

    #[test]
    fn test_remove_tokens() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(
            TEST_PASSWORD.as_bytes(),
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };

        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: "Test Token Account".to_string(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        // Add multiple custom tokens
        let tokens = vec![
            gen_bsc_token(),
            FToken {
                rate: 0f64,
                name: "Token 1".to_string(),
                symbol: "TK1".to_string(),
                decimals: 18,
                addr: Address::from_zil_base16("1111111111111111111111111111111111111111").unwrap(),
                logo: None,
                default: false,
                native: true,
                balances: HashMap::new(),
                chain_hash: 0,
            },
            FToken {
                rate: 0f64,
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                logo: None,
                default: false,
                native: true,
                balances: HashMap::new(),
                chain_hash: 0,
            },
            FToken {
                rate: 0f64,
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                addr: Address::from_zil_base16("3333333333333333333333333333333333333333").unwrap(),
                logo: None,
                native: true,
                default: false,
                balances: HashMap::new(),
                chain_hash: 0,
            },
        ];

        // Add all tokens
        for token in tokens.iter() {
            wallet.add_ftoken(token.clone()).unwrap();
        }

        let ftokens = wallet.get_ftokens().unwrap();

        // Initial state should have 4 tokens (1 default + 3 custom)
        assert_eq!(ftokens.len(), tokens.len());
        assert!(ftokens[0].default); // Default ETH token
        assert_eq!(ftokens[1].symbol, "TK1");
        assert_eq!(ftokens[2].symbol, "TK2");
        assert_eq!(ftokens[3].symbol, "TK3");

        // Try to remove a custom token (Token 2)
        wallet.remove_ftoken(2).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();

        // Should now have 3 tokens (1 default + 2 custom)
        assert_eq!(ftokens.len(), 3);
        assert!(ftokens[0].default); // Default ETH token should still be first
        assert_eq!(ftokens[1].symbol, "TK1");
        assert_eq!(ftokens[2].symbol, "TK3"); // TK2 should be gone

        // Save and reload wallet to verify persistence
        let wallet_addr = wallet.wallet_address;

        let loaded_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();

        loaded_wallet.unlock(&argon_seed).unwrap();

        let ftokens = loaded_wallet.get_ftokens().unwrap();

        assert_eq!(ftokens.len(), 3);
        assert!(ftokens[0].default);
        assert_eq!(ftokens[1].symbol, "TK1");
        assert_eq!(ftokens[2].symbol, "TK3");

        // Try to remove default token (should still work but token will be restored on reload)
        assert_eq!(
            loaded_wallet.remove_ftoken(0),
            Err(WalletErrors::DefaultTokenRemove(0))
        );

        let loaded_wallet2 = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();
        loaded_wallet2.unlock(&argon_seed).unwrap();

        let ftokens = loaded_wallet.get_ftokens().unwrap();

        // Default token should be restored
        assert_eq!(ftokens.len(), 3);
        assert!(ftokens[0].default);
        assert_eq!(ftokens[0].symbol, "BSC");
        assert_eq!(ftokens[1].symbol, "TK1");
        assert_eq!(ftokens[2].symbol, "TK3");
    }
}
