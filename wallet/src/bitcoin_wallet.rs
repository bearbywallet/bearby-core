use crate::{account::AccountV2, wallet_crypto::WalletCrypto, wallet_storage::StorageOperations, Result, Wallet, WalletAddrType};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::sha::SHA512_SIZE;
use config::storage::BTC_ADDRESSES_DB_KEY_V1;
use crypto::bip49::DerivationPath;
use errors::wallet::WalletErrors;
use network::btc::BtcOperations;
use network::provider::NetworkProvider;
use proto::{
    address::Address,
    btc_tx,
    btc_utils::{generate_btc_addresses, AddressChain, ByteCodec, GAP_LIMIT},
    tx::{TransactionMetadata, TransactionReceipt},
};
use rpc::network_config::ChainConfig;
use secrecy::SecretBox;
use secrecy::SecretString;
use std::collections::HashMap;

const MAX_GAP_EXTENSIONS: u32 = 3;

pub fn get_dust_limit(addr: &Address) -> u64 {
    match addr.get_bitcoin_address_type() {
        Ok(bitcoin::AddressType::P2wpkh) => 294,
        Ok(bitcoin::AddressType::P2tr) => 330,
        _ => 546,
    }
}

fn input_vsize_for(addr_type: bitcoin::AddressType) -> usize {
    match addr_type {
        bitcoin::AddressType::P2wpkh => 68,
        bitcoin::AddressType::P2tr => 58,
        _ => 148,
    }
}

fn output_vsize_for(addr_type: bitcoin::AddressType) -> usize {
    match addr_type {
        bitcoin::AddressType::P2wpkh => 31,
        bitcoin::AddressType::P2tr => 43,
        _ => 34,
    }
}

pub fn build_unsigned_btc_transaction(
    chains: &HashMap<bitcoin::AddressType, AddressChain>,
    destinations: Vec<(Address, u64)>,
    fee_rate_sat_per_vbyte: Option<u64>,
) -> Result<(
    bitcoin::Transaction,
    Vec<bitcoin::TxOut>,
    Vec<(bitcoin::AddressType, DerivationPath)>,
)> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };

    const TX_OVERHEAD_VSIZE: usize = 10;
    const DEFAULT_FEE_RATE: u64 = 10;

    let mut sorted_keys: Vec<bitcoin::AddressType> = chains.keys().copied().collect();
    sorted_keys.sort_by_key(|k| k.to_byte());

    let mut inputs: Vec<TxIn> = Vec::new();
    let mut witness_utxos: Vec<TxOut> = Vec::new();
    let mut input_meta: Vec<(bitcoin::AddressType, DerivationPath)> = Vec::new();
    let mut total_input: u64 = 0;
    let mut input_vsize_sum: usize = 0;

    for addr_type in &sorted_keys {
        let chain = chains.get(addr_type).expect("seeded above");
        for entry in chain.external.iter().chain(chain.internal.iter()) {
            if entry.utxos.is_empty() {
                continue;
            }
            let script_pubkey = entry
                .address
                .to_bitcoin_addr()
                .map_err(|e| WalletErrors::BincodeError(e.to_string()))?
                .script_pubkey();
            let in_vs = input_vsize_for(*addr_type);
            for utxo in &entry.utxos {
                inputs.push(TxIn {
                    previous_output: OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                });
                witness_utxos.push(TxOut {
                    value: Amount::from_sat(utxo.value),
                    script_pubkey: script_pubkey.clone(),
                });
                input_meta.push((*addr_type, entry.path.clone()));
                total_input = total_input.saturating_add(utxo.value);
                input_vsize_sum = input_vsize_sum.saturating_add(in_vs);
            }
        }
    }

    if inputs.is_empty() {
        return Err(WalletErrors::BincodeError(
            "No UTXOs available across address chains".to_string(),
        ));
    }

    let change_entry = chains
        .get(&bitcoin::AddressType::P2tr)
        .ok_or_else(|| WalletErrors::BincodeError("P2TR chain missing".to_string()))?
        .get_internal()
        .map_err(|e| WalletErrors::BincodeError(format!("No unused internal P2TR: {:?}", e)))?;
    let change_address = change_entry.address.clone();
    let change_script = change_address
        .to_bitcoin_addr()
        .map_err(|e| WalletErrors::BincodeError(e.to_string()))?
        .script_pubkey();
    let change_dust = get_dust_limit(&change_address);

    let original_total_output: u64 = destinations.iter().map(|(_, a)| a).sum();

    let mut dest_output_vsize_sum: usize = 0;
    for (dest, _) in &destinations {
        let at = dest.get_bitcoin_address_type().unwrap_or(bitcoin::AddressType::P2wpkh);
        dest_output_vsize_sum = dest_output_vsize_sum.saturating_add(output_vsize_for(at));
    }

    let change_output_vsize = output_vsize_for(bitcoin::AddressType::P2tr);
    let estimated_vsize_with_change =
        (input_vsize_sum + dest_output_vsize_sum + change_output_vsize + TX_OVERHEAD_VSIZE) as u64;
    let fee_rate = fee_rate_sat_per_vbyte.unwrap_or(DEFAULT_FEE_RATE);
    let estimated_fee = estimated_vsize_with_change * fee_rate;

    let (adjusted_destinations, total_output) =
        if total_input < original_total_output + estimated_fee {
            let max_threshold = estimated_fee.saturating_mul(3).max(10000);
            let is_max_transfer = destinations.len() == 1
                && original_total_output <= total_input
                && original_total_output + estimated_fee > total_input
                && (original_total_output + estimated_fee).saturating_sub(total_input)
                    < max_threshold;

            if is_max_transfer {
                let adjusted_amount = total_input.saturating_sub(estimated_fee);
                let dust_limit = get_dust_limit(&destinations[0].0);

                if adjusted_amount < dust_limit {
                    return Err(WalletErrors::BincodeError(format!(
                        "Insufficient funds: balance too low after fee (have: {}, fee: {})",
                        total_input, estimated_fee
                    )));
                }
                let adjusted_dests = vec![(destinations[0].0.clone(), adjusted_amount)];
                (adjusted_dests, adjusted_amount)
            } else {
                return Err(WalletErrors::BincodeError(format!(
                    "Insufficient funds: have {}, need {} (output: {}, fee: {})",
                    total_input,
                    original_total_output + estimated_fee,
                    original_total_output,
                    estimated_fee
                )));
            }
        } else {
            (destinations.clone(), original_total_output)
        };

    let mut outputs: Vec<TxOut> = Vec::with_capacity(adjusted_destinations.len() + 1);
    for (dest_addr, amount) in adjusted_destinations {
        let btc_addr = dest_addr
            .to_bitcoin_addr()
            .map_err(|e| WalletErrors::BincodeError(e.to_string()))?;
        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: btc_addr.script_pubkey(),
        });
    }

    let change = total_input.saturating_sub(total_output).saturating_sub(estimated_fee);
    if change > change_dust {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: change_script,
        });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    Ok((tx, witness_utxos, input_meta))
}

#[async_trait]
pub trait BitcoinWallet {
    type Error;

    async fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        name: String,
        chain: &ChainConfig,
    ) -> std::result::Result<AccountV2, Self::Error>;

    fn get_btc_addresses(
        &self,
        account_index: usize,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;

    fn save_btc_addresses(
        &self,
        account_index: usize,
        chains: &HashMap<bitcoin::AddressType, AddressChain>,
    ) -> std::result::Result<(), Self::Error>;

    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize) -> Vec<u8>;

    async fn prepare_and_sign_btc_transaction(
        &self,
        provider: &NetworkProvider,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

    async fn rotate_account(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl BitcoinWallet for Wallet {
    type Error = WalletErrors;

    async fn generate_wallet(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        name: String,
        chain: &ChainConfig,
    ) -> Result<AccountV2> {
        let network = chain.bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin);
        let provider = NetworkProvider::new(chain.clone());
        let preferred_type = bitcoin::AddressType::P2tr;

        let mut master: HashMap<bitcoin::AddressType, AddressChain> = HashMap::new();
        let mut next_start: u32 = 0;
        let mut scan_succeeded = false;
        let mut last_scan_view: Option<HashMap<bitcoin::AddressType, AddressChain>> = None;

        for _ in 0..MAX_GAP_EXTENSIONS {
            let batch =
                generate_btc_addresses(seed, account_index, network, next_start, GAP_LIMIT)?;

            for (addr_type, batch_chain) in batch {
                let target = master.entry(addr_type).or_insert_with(|| AddressChain {
                    external: Vec::new(),
                    internal: Vec::new(),
                });
                target.external.extend(batch_chain.external);
                target.internal.extend(batch_chain.internal);
            }
            next_start = next_start.saturating_add(GAP_LIMIT);

            let mut scan_view = master.clone();
            match provider.batch_script_get_history(&mut scan_view).await {
                Ok(()) => {
                    scan_succeeded = true;
                    let preferred = scan_view.get(&preferred_type).expect("seeded above");
                    let done =
                        preferred.get_external().is_ok() && preferred.get_internal().is_ok();
                    last_scan_view = Some(scan_view);
                    if done {
                        break;
                    }
                }
                Err(e) => {
                    println!("[generate_wallet] scan failed (offline?): {:?}", e);
                    break;
                }
            }
        }

        let to_persist = last_scan_view.as_ref().unwrap_or(&master);
        let stored: Vec<(u8, AddressChain)> = to_persist
            .iter()
            .map(|(addr_type, chain)| (addr_type.to_byte(), chain.clone()))
            .collect();
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index);
        self.storage.set_versioned(&key, &stored)?;

        let entry = if scan_succeeded {
            let view = last_scan_view.as_ref().expect("set on Ok branch");
            let preferred = view.get(&preferred_type).expect("seeded above");
            match preferred.get_external() {
                Ok(e) => e.clone(),
                Err(_) => {
                    println!(
                        "[generate_wallet] gap limit ({}) exceeded for account {} - wallet may have unscanned activity beyond this window",
                        MAX_GAP_EXTENSIONS * GAP_LIMIT,
                        account_index
                    );
                    master
                        .get(&preferred_type)
                        .expect("seeded above")
                        .external
                        .first()
                        .expect("non-empty after generation")
                        .clone()
                }
            }
        } else {
            master
                .get(&preferred_type)
                .expect("seeded above")
                .external
                .first()
                .expect("non-empty after generation")
                .clone()
        };

        let account = AccountV2::from_hd(seed, name, &entry.path, Some(network))?;
        Ok(account)
    }

    fn get_btc_addresses(
        &self,
        account_index: usize,
    ) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index);
        let stored: Vec<(u8, AddressChain)> = self.storage.get_versioned(&key)?;

        let mut map = HashMap::with_capacity(stored.len());
        for (byte, chain) in stored {
            let addr_type = bitcoin::AddressType::from_byte(byte).map_err(|_| {
                WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!(
                    "invalid address type byte: {}",
                    byte
                )))
            })?;
            map.insert(addr_type, chain);
        }

        Ok(map)
    }

    fn save_btc_addresses(
        &self,
        account_index: usize,
        chains: &HashMap<bitcoin::AddressType, AddressChain>,
    ) -> Result<()> {
        let stored: Vec<(u8, AddressChain)> = chains
            .iter()
            .map(|(addr_type, chain)| (addr_type.to_byte(), chain.clone()))
            .collect();
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index);
        self.storage.set_versioned(&key, &stored)?;
        Ok(())
    }

    #[inline]
    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize) -> Vec<u8> {
        let idx_bytes = account_index.to_le_bytes();
        [key.as_slice(), BTC_ADDRESSES_DB_KEY_V1, idx_bytes.as_slice()].concat()
    }

    async fn prepare_and_sign_btc_transaction(
        &self,
        provider: &NetworkProvider,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> Result<TransactionReceipt> {
        let data = self.get_wallet_data()?;
        let chains = self.get_btc_addresses(account_index)?;
        let network = provider
            .config
            .bitcoin_network()
            .unwrap_or(bitcoin::Network::Bitcoin);

        let (tx, witness_utxos, input_meta) =
            build_unsigned_btc_transaction(&chains, destinations, fee_rate_sat_per_vbyte)?;

        let mnemonic = self.reveal_mnemonic(seed_bytes)?;
        let seed_secret = mnemonic
            .to_seed(&SecretString::from(passphrase.unwrap_or("")))
            .map_err(|e| WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!("{:?}", e))))?;

        let mut psbt = btc_tx::build_psbt(tx, &witness_utxos)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let prevouts: Vec<bitcoin::TxOut> = witness_utxos.clone();

        for i in 0..psbt.inputs.len() {
            let (addr_type, path) = &input_meta[i];
            let sk = proto::bip32::derive_private_key(&seed_secret, &path.get_path())
                .map_err(WalletErrors::Bip329Error)?;
            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&sk.to_bytes())
                .map_err(|e| WalletErrors::BincodeError(e.to_string()))?;
            let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

            btc_tx::sign_psbt_input(&mut psbt, i, &secret_key, &public_key, network, *addr_type, &prevouts)
                .map_err(|e| WalletErrors::BincodeError(format!("sign input {}: {:?}", i, e)))?;
        }

        for i in 0..psbt.inputs.len() {
            let (addr_type, _) = &input_meta[i];
            btc_tx::finalize_psbt_input(&mut psbt, i, *addr_type)
                .map_err(|e| WalletErrors::BincodeError(format!("finalize input {}: {:?}", i, e)))?;
        }

        let signed_tx = psbt.extract_tx_unchecked_fee_rate();

        let metadata = TransactionMetadata {
            chain_hash: data.chain_hash,
            ..Default::default()
        };

        Ok(TransactionReceipt::Bitcoin((signed_tx, metadata)))
    }

    async fn rotate_account(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> Result<()> {
        let mut chains = self.get_btc_addresses(account_index)?;
        let p2tr = chains
            .get_mut(&bitcoin::AddressType::P2tr)
            .ok_or_else(|| WalletErrors::BincodeError("P2TR chain missing".to_string()))?;
        let next_index = p2tr.external.len() as u32;
        let network = chain.bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin);

        let mut batch = generate_btc_addresses(seed, account_index, network, next_index, 1)?;
        let mut new_chain = batch
            .remove(&bitcoin::AddressType::P2tr)
            .ok_or_else(|| WalletErrors::BincodeError("P2TR not generated".to_string()))?;

        if let Some(ext) = new_chain.external.pop() {
            p2tr.external.push(ext);
        }
        if let Some(int) = new_chain.internal.pop() {
            p2tr.internal.push(int);
        }

        self.save_btc_addresses(account_index, &chains)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests_bitcoin_wallet {
    use super::*;
    use crate::{wallet_init::WalletInit, Bip39Params, WalletConfig};
    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};
    use pqbip39::mnemonic::Mnemonic;
    use rand::RngExt;
    use rpc::network_config::ChainConfig as RpcChainConfig;
    use secrecy::SecretString;
    use settings::wallet_settings::WalletSettings;
    use std::sync::Arc;
    use storage::LocalStorage;
    use test_data::{empty_passphrase, ANVIL_MNEMONIC, TEST_PASSWORD};

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[tokio::test]
    async fn test_generate_and_load_btc_addresses() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let indexes = [0].map(|i| (i, format!("BTC Account {i}")));
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings,
        };
        let chain_config = RpcChainConfig::default();

        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &indexes,
                wallet_name: "BTC Test Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let account = wallet
            .generate_wallet(&seed, 0, "BTC Account 0".to_string(), &chain_config)
            .await
            .unwrap();

        assert!(account.addr.auto_format().starts_with("bc1"));

        let loaded = wallet.get_btc_addresses(0).unwrap();
        assert!(loaded.contains_key(&bitcoin::AddressType::P2tr));
    }

    #[tokio::test]
    async fn test_rotate_account_appends_p2tr_pair() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = mnemonic.to_seed(&empty_passphrase()).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let indexes = [0].map(|i| (i, format!("BTC Account {i}")));
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings,
        };
        let chain_config = RpcChainConfig::default();

        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &indexes,
                wallet_name: "BTC Rotate Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        wallet
            .generate_wallet(&seed, 0, "BTC Account 0".to_string(), &chain_config)
            .await
            .unwrap();

        let before = wallet.get_btc_addresses(0).unwrap();
        let p2tr_before = before.get(&bitcoin::AddressType::P2tr).unwrap();
        let ext_len_before = p2tr_before.external.len();
        let int_len_before = p2tr_before.internal.len();
        let last_ext_addr = p2tr_before.external.last().unwrap().address.clone();
        let last_int_addr = p2tr_before.internal.last().unwrap().address.clone();

        wallet
            .rotate_account(&seed, 0, &chain_config)
            .await
            .unwrap();

        let after = wallet.get_btc_addresses(0).unwrap();
        let p2tr_after = after.get(&bitcoin::AddressType::P2tr).unwrap();
        assert_eq!(p2tr_after.external.len(), ext_len_before + 1);
        assert_eq!(p2tr_after.internal.len(), int_len_before + 1);

        let new_ext = p2tr_after.external.last().unwrap();
        let new_int = p2tr_after.internal.last().unwrap();
        assert_ne!(new_ext.address, last_ext_addr);
        assert_ne!(new_int.address, last_int_addr);
        assert!(new_ext.utxos.is_empty());
        assert!(new_int.history.is_empty());
    }
}
