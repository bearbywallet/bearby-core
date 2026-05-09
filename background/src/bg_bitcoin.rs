use crate::{bg_provider::ProvidersManagement, Background, Result};
use async_trait::async_trait;
use proto::btc_utils::{AddressChain, BtcAccountXpubsInput};
use std::collections::HashMap;
use wallet::bitcoin_wallet::scan_btc_chains_for_xpubs;

#[async_trait]
pub trait BitcoinManagement {
    type Error;

    async fn scan_btc_account_history(
        &self,
        xpubs: &BtcAccountXpubsInput,
        ledger_index: u8,
        chain_hash: u64,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;
}

#[async_trait]
impl BitcoinManagement for Background {
    type Error = errors::background::BackgroundError;

    async fn scan_btc_account_history(
        &self,
        xpubs: &BtcAccountXpubsInput,
        ledger_index: u8,
        chain_hash: u64,
    ) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let provider = self.get_provider(chain_hash)?;
        let chains = scan_btc_chains_for_xpubs(xpubs, ledger_index as usize, &provider.config)
            .await?;
        Ok(chains)
    }
}

#[cfg(test)]
mod tests_bg_bitcoin {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement,
        bg_storage::StorageManagement, bg_wallet::WalletManagement, BackgroundLedgerParams,
    };
    use config::bip39::EN_WORDS;
    use config::session::AuthMethod;
    use pqbip39::mnemonic::Mnemonic;
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use settings::wallet_settings::WalletSettings;
    use test_data::{empty_passphrase, gen_btc_regtest_conf};
    use wallet::bitcoin_wallet::{pick_primary_btc_entry, BitcoinWallet};
    use wallet::wallet_storage::StorageOperations;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_scan_btc_account_history_offline_returns_all_four_chains() {
        let (mut bg, _dir) = setup_test_background();

        let offline_btc_conf = ChainConfig {
            rpc: vec!["ssl://localhost:1".to_string()],
            slip_44: crypto::slip44::BITCOIN,
            testnet: Some(true),
            ..gen_btc_regtest_conf()
        };
        bg.add_provider(offline_btc_conf.clone()).unwrap();

        let random_words = Background::gen_bip39(24).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &random_words).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let network = offline_btc_conf
            .bitcoin_network()
            .unwrap_or(bitcoin::Network::Bitcoin);

        let ledger_indexes: [u8; 3] = [0, 2, 5];
        let mut accounts = Vec::new();
        let mut account_names = Vec::new();
        let mut btc_chains: HashMap<u8, HashMap<bitcoin::AddressType, AddressChain>> =
            HashMap::new();

        for &li in &ledger_indexes {
            let xpubs = BtcAccountXpubsInput::from_seed(&seed, li as u32, network).unwrap();

            let chains = bg
                .scan_btc_account_history(&xpubs, li, offline_btc_conf.hash())
                .await
                .unwrap();

            for addr_type in [
                bitcoin::AddressType::P2pkh,
                bitcoin::AddressType::P2sh,
                bitcoin::AddressType::P2wpkh,
                bitcoin::AddressType::P2tr,
            ] {
                let chain = chains
                    .get(&addr_type)
                    .unwrap_or_else(|| panic!("missing chain for {:?}", addr_type));
                assert!(
                    !chain.external.is_empty(),
                    "{:?} external chain must not be empty (offline fallback)",
                    addr_type,
                );
            }

            let entry = pick_primary_btc_entry(&chains).unwrap();
            let addr_str = entry.address.auto_format();
            assert!(
                addr_str.starts_with("bcrt1p") || addr_str.starts_with("tb1p"),
                "expected P2TR address for ledger_index {}, got: {}",
                li,
                addr_str,
            );

            btc_chains.insert(li, chains);

            let dummy_addr = proto::address::Address::Secp256k1Bitcoin(
                proto::btc_utils::create_btc_address(
                    &xpubs.bip86_xpub.public_key.serialize(),
                    network,
                    bitcoin::AddressType::P2tr,
                )
                .unwrap()
                .to_string()
                .into_bytes(),
            );
            accounts.push((li, None, dummy_addr));
            account_names.push(format!("BTC Ledger {}", li));
        }

        bg.add_ledger_wallet(
            BackgroundLedgerParams {
                ledger_id: vec![1],
                accounts,
                wallet_name: "Ledger BTC".to_string(),
                account_names,
                wallet_index: 0,
                biometric_type: AuthMethod::None,
                wallet_settings: WalletSettings::default(),
                chain_hash: offline_btc_conf.hash(),
                ftokens: vec![],
                btc_chains,
            },
            WalletSettings::default(),
        )
        .await
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let all_accounts = data.get_accounts().unwrap();
        assert_eq!(all_accounts.len(), 3);

        for (pos, &li) in ledger_indexes.iter().enumerate() {
            let acc = &all_accounts[pos];
            assert_eq!(
                acc.account_type.value(),
                li as usize,
                "pos={}: account_type must match ledger_index",
                pos,
            );

            let addr_str = acc.addr.auto_format();
            assert!(
                addr_str.starts_with("bcrt1p") || addr_str.starts_with("tb1p"),
                "pos={}: expected P2TR addr, got {}",
                pos,
                addr_str,
            );

            let stored_chains = wallet
                .get_btc_addresses(pos as usize, offline_btc_conf.hash())
                .unwrap();
            assert_eq!(
                stored_chains.len(),
                4,
                "pos={} should have 4 address types (offline fallback)",
                pos,
            );

            let p2tr = stored_chains.get(&bitcoin::AddressType::P2tr).unwrap();
            assert!(
                !p2tr.external.is_empty(),
                "pos={} P2TR external chain must not be empty",
                pos,
            );

            assert_eq!(
                acc.addr, p2tr.external[0].address,
                "pos={}: account addr must match first P2TR external entry",
                pos,
            );

            for entry in p2tr.external.iter().chain(p2tr.internal.iter()) {
                let path_account = entry.path.get_account_index();
                assert_eq!(
                    path_account, li as usize,
                    "pos={}: path account index must be ledger_index {} but got {}",
                    pos, li, path_account,
                );
            }
        }
    }
}
