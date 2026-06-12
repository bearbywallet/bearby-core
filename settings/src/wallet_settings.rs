use cipher::options::CipherOrders;
use serde::{Deserialize, Serialize};

use crate::argon2::ArgonParams;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Default)]
pub enum TokenQuotesAPIOptions {
    None,
    #[default]
    BearbyRates,
    Coingecko,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(default)]
pub struct WalletSettings {
    pub cipher_orders: Vec<CipherOrders>,

    #[serde(default)]
    pub argon_params: ArgonParams,

    #[serde(default)]
    pub features: WalletFeatures,

    #[serde(default)]
    pub network: NetworkSettings,

    #[serde(default)]
    pub rates_api_options: TokenQuotesAPIOptions,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct WalletFeatures {
    pub currency_convert: String,
    pub ens_enabled: bool,
    pub ipfs_node: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct NetworkSettings {
    pub tokens_list_fetcher: bool,
    pub node_ranking_enabled: bool,
    pub max_connections: u8,
    pub request_timeout_secs: u32,
}

impl NetworkSettings {
    const DEFAULT_MAX_CONNECTIONS: u8 = 5;
    const DEFAULT_TIMEOUT: u32 = 30;
}

impl WalletFeatures {
    const DEFAULT_IPFS_NODE: &str = "dweb.link";
    const DEFUALT_CURRENCY_CONVERT: &str = "BTC";
}

impl TokenQuotesAPIOptions {
    pub fn from_code(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::BearbyRates,
            2 => Self::Coingecko,
            _ => Self::None,
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::BearbyRates => 1,
            Self::Coingecko => 1,
        }
    }
}

impl std::fmt::Display for TokenQuotesAPIOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenQuotesAPIOptions::None => write!(f, "None"),
            TokenQuotesAPIOptions::Coingecko => write!(f, "Coingecko"),
            TokenQuotesAPIOptions::BearbyRates => write!(f, "CryptoCompare"),
        }
    }
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            cipher_orders: vec![CipherOrders::AESGCM256],
            features: WalletFeatures::default(),
            network: NetworkSettings::default(),
            argon_params: ArgonParams::default(),
            rates_api_options: Default::default(),
        }
    }
}

impl Default for WalletFeatures {
    fn default() -> Self {
        Self {
            currency_convert: Self::DEFUALT_CURRENCY_CONVERT.to_string(),
            ens_enabled: true,
            ipfs_node: Some(Self::DEFAULT_IPFS_NODE.to_string()),
        }
    }
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            tokens_list_fetcher: true,
            node_ranking_enabled: true,
            max_connections: Self::DEFAULT_MAX_CONNECTIONS,
            request_timeout_secs: Self::DEFAULT_TIMEOUT,
        }
    }
}

#[cfg(test)]
mod wallet_settings_tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = WalletSettings::default();

        // Test default cipher orders
        assert_eq!(settings.cipher_orders, vec![CipherOrders::AESGCM256,]);

        // Test default wallet features
        assert_eq!(
            settings.features.currency_convert,
            WalletFeatures::DEFUALT_CURRENCY_CONVERT.to_string()
        );
        assert!(settings.features.ens_enabled);
        assert_eq!(
            settings.features.ipfs_node,
            Some(WalletFeatures::DEFAULT_IPFS_NODE.to_string())
        );

        // Test default network settings
        assert!(settings.network.tokens_list_fetcher);
        assert!(settings.network.node_ranking_enabled);
        assert_eq!(
            settings.network.max_connections,
            NetworkSettings::DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            settings.network.request_timeout_secs,
            NetworkSettings::DEFAULT_TIMEOUT
        );

        // Test default Argon2 parameters (should be secure settings)
        assert_eq!(settings.argon_params, ArgonParams::default());
    }

    #[test]
    fn test_wallet_features_customization() {
        let mut features = WalletFeatures::default();

        // Test currency conversion modification
        let usd = "USD";
        features.currency_convert = usd.to_string();
        assert_eq!(features.currency_convert, usd.to_string());

        // Test ENS disabling
        features.ens_enabled = false;
        assert!(!features.ens_enabled);

        // Test IPFS node customization
        features.ipfs_node = Some("ipfs.io".to_string());
        assert_eq!(features.ipfs_node, Some("ipfs.io".to_string()));
    }

    #[test]
    fn test_network_settings_customization() {
        let mut network = NetworkSettings::default();

        // Test gas control modification
        // network.gas_control_enabled = false;
        assert!(network.tokens_list_fetcher);

        // Test node ranking modification
        network.node_ranking_enabled = false;
        assert!(!network.node_ranking_enabled);

        // Test connection limits
        network.max_connections = 10;
        assert_eq!(network.max_connections, 10);

        // Test timeout modification
        network.request_timeout_secs = 60;
        assert_eq!(network.request_timeout_secs, 60);
    }

    #[test]
    fn test_wallet_settings_clone() {
        let original = WalletSettings::default();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_wallet_settings_partial_eq() {
        let settings1 = WalletSettings::default();
        let settings2 = WalletSettings::default();
        let mut settings3 = WalletSettings::default();

        assert_eq!(settings1, settings2);

        settings3.network.max_connections = 10;
        assert_ne!(settings1, settings3);
    }

    #[test]
    fn test_custom_wallet_settings() {
        let custom_settings = WalletSettings {
            cipher_orders: vec![CipherOrders::NTRUP1277],
            argon_params: ArgonParams::low_memory(),
            features: WalletFeatures {
                currency_convert: "EUR".to_string(),
                ens_enabled: false,
                ipfs_node: None,
            },
            rates_api_options: Default::default(),
            network: NetworkSettings {
                tokens_list_fetcher: false,
                node_ranking_enabled: true,
                max_connections: 3,
                request_timeout_secs: 15,
            },
        };

        // Verify custom cipher orders
        assert_eq!(custom_settings.cipher_orders, vec![CipherOrders::NTRUP1277]);

        // Verify custom features
        assert_eq!(custom_settings.features.currency_convert, "EUR".to_string());
        assert!(!custom_settings.features.ens_enabled);
        assert!(custom_settings.features.ipfs_node.is_none());

        // Verify custom network settings
        assert!(!custom_settings.network.tokens_list_fetcher);
        assert!(custom_settings.network.node_ranking_enabled);
        assert_eq!(custom_settings.network.max_connections, 3);
        assert_eq!(custom_settings.network.request_timeout_secs, 15);

        // Verify custom Argon2 parameters
        assert_eq!(custom_settings.argon_params, ArgonParams::low_memory());
    }
}
