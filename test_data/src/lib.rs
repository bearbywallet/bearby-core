use config::address::ADDR_LEN;
use crypto::slip44;
use proto::address::Address;
use rpc::network_config::{ChainConfig, Explorer};
use secrecy::SecretString;
use std::collections::HashMap;
use token::ft::FToken;

pub const TEST_PASSWORD: &str = "TEst password";
pub const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";

pub fn empty_passphrase() -> SecretString {
    SecretString::new(Box::from(""))
}

pub fn gen_anvil_net_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [31337, 0],
        name: "Anvil Local Network".to_string(),
        chain: "ETH".to_string(),
        short_name: "anvil".to_string(),
        rpc: vec!["http://127.0.0.1:8545".to_string()],
        features: vec![155, 1559],
        slip_44: slip44::ETHEREUM,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_anvil_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Anvil ETH".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: gen_anvil_net_conf().hash(),
    }
}

pub fn gen_zil_testnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [33101, 333],
        name: "Zilliqa(testnet)".to_string(),
        chain: "ZIL".to_string(),
        short_name: "zil".to_string(),
        rpc: vec!["https://api.testnet.zilliqa.com".to_string()],
        features: vec![],
        slip_44: slip44::ZILLIQA,
        ens: None,
        explorers: vec![],
        fallback_enabled: true,
    }
}

pub fn gen_zil_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Zilliqa".to_string(),
        symbol: "ZIL".to_string(),
        decimals: 12,
        addr: Address::Secp256k1Sha256(Address::ZERO),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: gen_zil_testnet_conf().hash(),
    }
}

pub fn gen_eth_account(index: u32, name: &str) -> (usize, String) {
    (index as usize, name.to_string())
}

pub fn gen_zil_account(index: u32, name: &str) -> (usize, String) {
    (index as usize, name.to_string())
}

pub fn gen_tron_account(index: u32, name: &str) -> (usize, String) {
    (index as usize, name.to_string())
}

pub fn gen_device_indicators(device_name: &str) -> [String; 2] {
    [device_name.to_string(), "0000".to_string()]
}

pub fn gen_zil_mainnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [1, 0],
        name: "Zilliqa".to_string(),
        chain: "ZIL".to_string(),
        short_name: String::new(),
        rpc: vec![
            "https://ssn.zilpay.io".to_string(),
            "https://api.zilliqa.com".to_string(),
        ],
        features: vec![155],
        slip_44: slip44::ZILLIQA,
        ens: None,
        explorers: vec![Explorer {
            name: "ViewBlock".to_string(),
            url: "https://viewblock.io/zilliqa".to_string(),
            icon: None,
            standard: 3091,
        }],
        fallback_enabled: true,
    }
}

pub fn gen_bsc_testnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [97, 0],
        name: "Binance-smart-chain".to_string(),
        chain: "BSC".to_string(),
        short_name: String::new(),
        rpc: vec!["https://bsc-testnet-dataseed.bnbchain.org".to_string()],
        features: vec![155],
        slip_44: slip44::ETHEREUM,
        ens: None,
        explorers: vec![Explorer {
            name: "BscScan".to_string(),
            url: "https://bscscan.com".to_string(),
            icon: None,
            standard: 3091,
        }],
        fallback_enabled: true,
    }
}

pub fn gen_eth_mainnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [1, 0],
        name: "Ethereum".to_string(),
        chain: "ETH".to_string(),
        short_name: String::new(),
        rpc: vec!["https://rpc.mevblocker.io".to_string()],
        features: vec![155, 1559, 4844],
        slip_44: slip44::ETHEREUM,
        ens: None,
        explorers: vec![],
        fallback_enabled: true,
    }
}

pub fn gen_btc_testnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![gen_btc_token()],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [1, 0],
        name: "Bitcoin(testnet)".to_string(),
        chain: "BTC".to_string(),
        short_name: "btc".to_string(),
        rpc: vec!["ssl://btc-testnet.zilpay.io:60402".to_string()],
        features: vec![1],
        slip_44: slip44::BITCOIN,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_btc_mainnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![gen_btc_mainnet_token()],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [1, 0],
        name: "Bitcoin".to_string(),
        chain: "BTC".to_string(),
        short_name: "btc".to_string(),
        rpc: vec!["ssl://btc.zilpay.io:50002".to_string()],
        features: vec![],
        slip_44: slip44::BITCOIN,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_btc_regtest_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![gen_btc_regtest_token()],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [1, 0],
        name: "Bitcoin(regtest)".to_string(),
        chain: "BTC".to_string(),
        short_name: "btc".to_string(),
        rpc: vec!["ssl://btc-testnet.zilpay.io:60402".to_string()],
        features: vec![],
        slip_44: slip44::BITCOIN,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_btc_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Bitcoin".to_string(),
        symbol: "tBTC".to_string(),
        decimals: 8,
        addr: Address::from_str_hex(
            "tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2",
        )
        .unwrap(),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: 0,
    }
}

pub fn gen_btc_mainnet_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Bitcoin".to_string(),
        symbol: "BTC".to_string(),
        decimals: 8,
        addr: Address::from_str_hex(
            "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
        )
        .unwrap(),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: 0,
    }
}

pub fn gen_btc_regtest_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Bitcoin".to_string(),
        symbol: "BTC".to_string(),
        decimals: 8,
        addr: Address::from_str_hex(
            "bcrt1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssm803es",
        )
        .unwrap(),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: 0,
    }
}

#[allow(dead_code)]
pub mod anvil_accounts {
    pub const ACCOUNT_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    pub const ACCOUNT_1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    pub const ACCOUNT_2: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
    pub const ACCOUNT_3: &str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
    pub const ACCOUNT_4: &str = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
    pub const ACCOUNT_5: &str = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
    pub const ACCOUNT_6: &str = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";
    pub const ACCOUNT_7: &str = "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955";
    pub const ACCOUNT_8: &str = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f";
    pub const ACCOUNT_9: &str = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";

    pub const PRIVATE_KEY_0: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    pub const PRIVATE_KEY_1: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    pub const PRIVATE_KEY_2: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    pub const PRIVATE_KEY_3: &str =
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
    pub const PRIVATE_KEY_4: &str =
        "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";
    pub const PRIVATE_KEY_5: &str =
        "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
    pub const PRIVATE_KEY_6: &str =
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e";
    pub const PRIVATE_KEY_7: &str =
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";
    pub const PRIVATE_KEY_8: &str =
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
    pub const PRIVATE_KEY_9: &str =
        "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
}

pub fn gen_tron_testnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [2494104990, 0],
        name: "Tron(testnet)".to_string(),
        chain: "TRX".to_string(),
        short_name: "tron".to_string(),
        rpc: vec!["https://nile.trongrid.io".to_string()],
        features: vec![],
        slip_44: slip44::TRON,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_tron_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Tron".to_string(),
        symbol: "TRX".to_string(),
        decimals: 6,
        addr: Address::Secp256k1Tron([0u8; ADDR_LEN]),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: gen_tron_testnet_conf().hash(),
    }
}

#[allow(dead_code)]
pub mod tron_addresses {
    pub const ADDR_0: &str = "TWer2Ygk5TEheHp3TPuYeqxmB6SsGZmaL6";
    pub const ADDR_1: &str = "TPjjvMwjPoDC32V2dGDYTkLH4E5LAtBZ6C";
    pub const ADDR_2: &str = "TB7mhtkvfhsRBRhe5FuRa4tFXSEyGDe4eA";
    pub const ADDR_3: &str = "TEb822rMZ5QkYReuqdqK61zkheaan97PZZ";
    pub const ADDR_4: &str = "TYc2iBENTQ7kwx5jbjW3JDqugR7kogQZn3";
    pub const ADDR_5: &str = "TNWtoufpsNepTJdNzbcimHrPEUSHLDCJE1";
    pub const ADDR_6: &str = "TYMprjNZ1Lhc2zAsmRbGuBzY6iQ4FB4amn";
    pub const ADDR_7: &str = "TDmEWPYotmrXW4X49WMJTMostcezCiksPw";
    pub const ADDR_8: &str = "TPoh8thAmjTXgxPwtFT9oYVyJXPVqLJHhh";
    pub const ADDR_9: &str = "TJtuRzHcZ12gHZA8gKjqq589S7h4fYW8N1";

    pub const ALL: [&str; 10] = [
        ADDR_0, ADDR_1, ADDR_2, ADDR_3, ADDR_4, ADDR_5, ADDR_6, ADDR_7, ADDR_8, ADDR_9,
    ];
}

pub fn gen_sol_devnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: Some(true),
        chain_ids: [501, 0],
        name: "Solana(devnet)".to_string(),
        chain: "SOL".to_string(),
        short_name: "sol-devnet".to_string(),
        rpc: vec!["https://api.devnet.solana.com".to_string()],
        features: vec![],
        slip_44: slip44::SOLANA,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_sol_mainnet_conf() -> ChainConfig {
    ChainConfig {
        ftokens: vec![],
        logo: String::new(),
        diff_block_time: 0,
        testnet: None,
        chain_ids: [501, 0],
        name: "Solana".to_string(),
        chain: "SOL".to_string(),
        short_name: "sol".to_string(),
        rpc: vec![
            "https://api.mainnet-beta.solana.com".to_string(),
            "https://solana-rpc.publicnode.com".to_string(),
            "https://solana.drpc.org".to_string(),
            "https://1rpc.io/sol".to_string(),
        ],
        features: vec![],
        slip_44: slip44::SOLANA,
        ens: None,
        explorers: vec![],
        fallback_enabled: false,
    }
}

pub fn gen_sol_token() -> FToken {
    FToken {
        rate: 0f64,
        name: "Solana".to_string(),
        symbol: "SOL".to_string(),
        decimals: 9,
        addr: Address::Ed25519Solana([0u8; 32].into()),
        logo: None,
        balances: HashMap::new(),
        default: true,
        native: true,
        chain_hash: gen_sol_devnet_conf().hash(),
    }
}

pub fn gen_sol_spl_token(mint: [u8; 32], chain_hash: u64) -> FToken {
    FToken {
        rate: 0f64,
        name: String::new(),
        symbol: String::new(),
        decimals: 0,
        addr: Address::Ed25519Solana(mint.into()),
        logo: None,
        balances: HashMap::new(),
        default: false,
        native: false,
        chain_hash,
    }
}

#[allow(dead_code)]
pub mod solana_addresses {
    pub const ADDR_0: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    pub const ADDR_1: &str = "4fYNw3dojWmQ4dXtSGE9epjRGy9GHeo5UCCbg6NbyNjF";
}
