use crate::{
    account::AccountV2, wallet_crypto::WalletCrypto, wallet_storage::StorageOperations,
    wallet_types::WalletTypes, Result, Wallet, WalletAddrType,
};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use cipher::keychain::KeyChain;
use config::sha::SHA512_SIZE;
use config::storage::BTC_ADDRESSES_DB_KEY_V1;
use crypto::bip49::DerivationPath;
use crypto::slip44;
use errors::wallet::WalletErrors;
use history::transaction::HistoricalTransaction;
use network::btc::BtcOperations;
use network::provider::NetworkProvider;
use proto::{
    address::Address,
    btc_tx::{self, BitcoinMetadata},
    btc_utils::{
        create_btc_address, generate_btc_addresses, AddressChain, BtcAddressEntry, ByteCodec,
        GAP_LIMIT,
    },
    secret_key::SecretKey,
    tx::{TransactionMetadata, TransactionReceipt},
};
use rpc::network_config::ChainConfig;
use secrecy::SecretBox;
use secrecy::SecretString;
use std::collections::{HashMap, HashSet};

const MAX_GAP_EXTENSIONS: u32 = 10;

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

pub fn derive_sk_btc_address_chains(
    sk_bytes: &[u8; config::key::SECRET_KEY_SIZE],
    network: bitcoin::Network,
) -> Result<(HashMap<bitcoin::AddressType, AddressChain>, Address)> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(sk_bytes)
        .map_err(|e| WalletErrors::BincodeError(e.to_string()))?;
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let pk_bytes = pk.serialize();

    const FORMATS: [(bitcoin::AddressType, u32); 4] = [
        (bitcoin::AddressType::P2pkh, DerivationPath::BIP44_PURPOSE),
        (bitcoin::AddressType::P2sh, DerivationPath::BIP49_PURPOSE),
        (bitcoin::AddressType::P2wpkh, DerivationPath::BIP84_PURPOSE),
        (bitcoin::AddressType::P2tr, DerivationPath::BIP86_PURPOSE),
    ];

    let mut chains: HashMap<bitcoin::AddressType, AddressChain> =
        HashMap::with_capacity(FORMATS.len());
    let mut p2tr_address: Option<Address> = None;

    for (addr_type, bip) in FORMATS {
        let btc_addr = create_btc_address(&pk_bytes, network, addr_type)
            .map_err(|e| WalletErrors::BincodeError(format!("{:?}", e)))?;
        let address = Address::Secp256k1Bitcoin(btc_addr.to_string().into_bytes());
        let path = DerivationPath::new(
            slip44::BITCOIN,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            bip,
        );
        if addr_type == bitcoin::AddressType::P2tr {
            p2tr_address = Some(address.clone());
        }
        chains.insert(
            addr_type,
            AddressChain {
                external: vec![BtcAddressEntry {
                    address,
                    path,
                    history: Vec::new(),
                    utxos: Vec::new(),
                }],
                internal: Vec::new(),
            },
        );
    }

    let p2tr_address = p2tr_address.ok_or_else(|| {
        WalletErrors::BincodeError("P2tr address missing after SK chain derivation".to_string())
    })?;
    Ok((chains, p2tr_address))
}

fn append_new_p2tr_address(
    chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    seed: &SecretBox<[u8; SHA512_SIZE]>,
    account_index: usize,
    network: bitcoin::Network,
) -> Result<()> {
    let p2tr = chains
        .get_mut(&bitcoin::AddressType::P2tr)
        .ok_or_else(|| WalletErrors::BincodeError("P2TR chain missing".to_string()))?;
    let next_index = p2tr.external.len() as u32;
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
    Ok(())
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

    println!(
        "[build_unsigned_btc_tx] chains={} dests={} fee_rate={:?}",
        sorted_keys.len(),
        destinations.len(),
        fee_rate_sat_per_vbyte
    );

    let mut inputs: Vec<TxIn> = Vec::new();
    let mut witness_utxos: Vec<TxOut> = Vec::new();
    let mut input_meta: Vec<(bitcoin::AddressType, DerivationPath)> = Vec::new();
    let mut total_input: u64 = 0;
    let mut input_vsize_sum: usize = 0;

    for addr_type in &sorted_keys {
        let chain = chains.get(addr_type).expect("seeded above");
        println!(
            "[build_unsigned_btc_tx] chain {:?}: ext={} int={}",
            addr_type,
            chain.external.len(),
            chain.internal.len()
        );
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
            let entry_utxo_count = entry.utxos.len();
            let entry_utxo_sum: u64 = entry.utxos.iter().map(|u| u.value).sum();
            println!(
                "[build_unsigned_btc_tx]   {:?} addr={} utxos={} sum={} sat ({:.8} BTC) path={}",
                addr_type,
                entry.address,
                entry_utxo_count,
                entry_utxo_sum,
                entry_utxo_sum as f64 / 1e8,
                entry.path.get_path()
            );
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
        .get_internal()?;
    let change_address = change_entry.address.clone();
    let change_script = change_address
        .to_bitcoin_addr()
        .map_err(|e| WalletErrors::BincodeError(e.to_string()))?
        .script_pubkey();
    let change_dust = get_dust_limit(&change_address);

    let original_total_output: u64 = destinations.iter().map(|(_, a)| a).sum();

    let mut dest_output_vsize_sum: usize = 0;
    for (dest, _) in &destinations {
        let at = dest
            .get_bitcoin_address_type()
            .unwrap_or(bitcoin::AddressType::P2wpkh);
        dest_output_vsize_sum = dest_output_vsize_sum.saturating_add(output_vsize_for(at));
    }

    let change_output_vsize = output_vsize_for(bitcoin::AddressType::P2tr);
    let estimated_vsize_with_change =
        (input_vsize_sum + dest_output_vsize_sum + change_output_vsize + TX_OVERHEAD_VSIZE) as u64;
    let fee_rate = fee_rate_sat_per_vbyte.unwrap_or(DEFAULT_FEE_RATE);
    let estimated_fee = estimated_vsize_with_change * fee_rate;

    let (adjusted_destinations, total_output) = if total_input
        < original_total_output + estimated_fee
    {
        let max_threshold = estimated_fee.saturating_mul(3).max(10000);
        let is_max_transfer = destinations.len() == 1
            && original_total_output <= total_input
            && original_total_output + estimated_fee > total_input
            && (original_total_output + estimated_fee).saturating_sub(total_input) < max_threshold;

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

    let change = total_input
        .saturating_sub(total_output)
        .saturating_sub(estimated_fee);
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

    async fn sign_btc_multi_input(
        &self,
        tx: bitcoin::Transaction,
        metadata: TransactionMetadata,
        btc_meta: BitcoinMetadata,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

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
        chain_hash: u64,
    ) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Self::Error>;

    fn save_btc_addresses(
        &self,
        account_index: usize,
        chains: &HashMap<bitcoin::AddressType, AddressChain>,
        chain_hash: u64,
    ) -> std::result::Result<(), Self::Error>;

    fn get_btc_addresses_db_key(
        key: &WalletAddrType,
        account_index: usize,
        chain_hash: u64,
    ) -> Vec<u8>;

    async fn prepare_and_sign_btc_transaction(
        &self,
        provider: &NetworkProvider,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

    async fn rotate_account(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;

    fn mark_btc_addresses_used(
        &self,
        account_index: usize,
        historical: &HistoricalTransaction,
    ) -> std::result::Result<(), Self::Error>;

    async fn migrate_btc_storage_if_needed(
        &self,
        seed_bytes: &Argon2Seed,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl BitcoinWallet for Wallet {
    type Error = WalletErrors;

    async fn sign_btc_multi_input(
        &self,
        tx: bitcoin::Transaction,
        metadata: TransactionMetadata,
        btc_meta: BitcoinMetadata,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
    ) -> Result<TransactionReceipt> {
        let btc_tx::BitcoinMetadata {
            witness_utxos,
            input_meta: input_meta_raw,
        } = btc_meta;

        if input_meta_raw.len() != tx.input.len() || witness_utxos.len() != tx.input.len() {
            return Err(WalletErrors::BincodeError(format!(
                "BTC input meta/utxos count mismatch: inputs={} meta={} utxos={}",
                tx.input.len(),
                input_meta_raw.len(),
                witness_utxos.len()
            )));
        }

        let mnemonic = self.reveal_mnemonic(seed_bytes)?;
        let seed_secret = mnemonic.to_seed(passphrase).map_err(|e| {
            WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!("{:?}", e)))
        })?;

        let mut psbt = btc_tx::build_psbt(tx, &witness_utxos)
            .map_err(|e| WalletErrors::BincodeError(format!("build_psbt: {:?}", e)))?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let prevouts = &witness_utxos;

        for i in 0..psbt.inputs.len() {
            let (addr_type_byte, path) = &input_meta_raw[i];
            let addr_type = bitcoin::AddressType::from_byte(*addr_type_byte).map_err(|_| {
                WalletErrors::BincodeError(format!(
                    "invalid btc address type byte: {}",
                    addr_type_byte
                ))
            })?;
            let sk = proto::bip32::derive_private_key(&seed_secret, &path.get_path())
                .map_err(WalletErrors::Bip329Error)?;
            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&sk.to_bytes())
                .map_err(|e| WalletErrors::BincodeError(e.to_string()))?;
            let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

            btc_tx::sign_psbt_input(&mut psbt, i, &secret_key, &public_key, addr_type, prevouts)
                .map_err(|e| WalletErrors::BincodeError(format!("sign input {}: {:?}", i, e)))?;
        }

        for i in 0..psbt.inputs.len() {
            let (addr_type_byte, _) = &input_meta_raw[i];
            let addr_type = bitcoin::AddressType::from_byte(*addr_type_byte).map_err(|_| {
                WalletErrors::BincodeError(format!(
                    "invalid btc address type byte: {}",
                    addr_type_byte
                ))
            })?;
            btc_tx::finalize_psbt_input(&mut psbt, i, addr_type).map_err(|e| {
                WalletErrors::BincodeError(format!("finalize input {}: {:?}", i, e))
            })?;
        }

        let signed_tx = psbt.extract_tx_unchecked_fee_rate();
        let btc_meta = btc_tx::BitcoinMetadata {
            witness_utxos,
            input_meta: input_meta_raw,
        };

        Ok(TransactionReceipt::Bitcoin((signed_tx, metadata, btc_meta)))
    }

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
                    let done = scan_view
                        .values()
                        .all(|chain| chain.get_external().is_ok() && chain.get_internal().is_ok());
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
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index, chain.hash());
        self.storage.set_versioned(&key, &stored)?;

        let p2tr_fallback = || {
            master
                .get(&preferred_type)
                .ok_or_else(|| {
                    WalletErrors::BincodeError("P2TR chain missing after generation".to_string())
                })?
                .external
                .first()
                .cloned()
                .ok_or_else(|| {
                    WalletErrors::BincodeError(
                        "P2TR external chain is empty after generation".to_string(),
                    )
                })
        };

        let entry = if scan_succeeded {
            let view = last_scan_view.as_ref().ok_or_else(|| {
                WalletErrors::BincodeError("scan_view missing after successful scan".to_string())
            })?;
            let preferred = view.get(&preferred_type).ok_or_else(|| {
                WalletErrors::BincodeError("P2TR chain missing in scan view".to_string())
            })?;
            match preferred.get_external() {
                Ok(e) => e.clone(),
                Err(_) => {
                    println!(
                        "[generate_wallet] gap limit ({}) exceeded for account {} - wallet may have unscanned activity beyond this window",
                        MAX_GAP_EXTENSIONS * GAP_LIMIT,
                        account_index
                    );
                    p2tr_fallback()?
                }
            }
        } else {
            p2tr_fallback()?
        };

        let account = AccountV2::from_hd(seed, name, &entry.path, Some(network))?;
        Ok(account)
    }

    fn get_btc_addresses(
        &self,
        account_index: usize,
        chain_hash: u64,
    ) -> Result<HashMap<bitcoin::AddressType, AddressChain>> {
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index, chain_hash);
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
        chain_hash: u64,
    ) -> Result<()> {
        let stored: Vec<(u8, AddressChain)> = chains
            .iter()
            .map(|(addr_type, chain)| (addr_type.to_byte(), chain.clone()))
            .collect();
        let key = Self::get_btc_addresses_db_key(&self.wallet_address, account_index, chain_hash);
        self.storage.set_versioned(&key, &stored)?;
        Ok(())
    }

    #[inline]
    fn get_btc_addresses_db_key(
        key: &WalletAddrType,
        account_index: usize,
        chain_hash: u64,
    ) -> Vec<u8> {
        let idx_bytes = account_index.to_le_bytes();
        let hash_bytes = chain_hash.to_le_bytes();
        [
            key.as_slice(),
            BTC_ADDRESSES_DB_KEY_V1,
            hash_bytes.as_slice(),
            idx_bytes.as_slice(),
        ]
        .concat()
    }

    async fn prepare_and_sign_btc_transaction(
        &self,
        provider: &NetworkProvider,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: &SecretString,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> Result<TransactionReceipt> {
        let data = self.get_wallet_data()?;
        let mut chains = self.get_btc_addresses(account_index, data.chain_hash)?;
        let network = provider
            .config
            .bitcoin_network()
            .unwrap_or(bitcoin::Network::Bitcoin);

        println!(
            "[prepare_and_sign_btc_tx] account={} chains={} destinations={} fee_rate={:?}",
            account_index,
            chains.len(),
            destinations.len(),
            fee_rate_sat_per_vbyte
        );

        let mnemonic = self.reveal_mnemonic(seed_bytes)?;
        let seed_secret = mnemonic.to_seed(passphrase).map_err(|e| {
            WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!("{:?}", e)))
        })?;

        let needs_new_change = chains
            .get(&bitcoin::AddressType::P2tr)
            .map(|c| c.get_internal().is_err())
            .unwrap_or(true);

        if needs_new_change {
            append_new_p2tr_address(&mut chains, &seed_secret, account_index, network)?;
            self.save_btc_addresses(account_index, &chains, data.chain_hash)?;
        }

        let (tx, witness_utxos, input_meta) =
            build_unsigned_btc_transaction(&chains, destinations, fee_rate_sat_per_vbyte)?;

        println!(
            "[prepare_and_sign_btc_tx] built tx: {} inputs {} outputs network={:?}",
            tx.input.len(),
            tx.output.len(),
            network
        );

        let mut psbt = btc_tx::build_psbt(tx, &witness_utxos)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let prevouts: Vec<bitcoin::TxOut> = witness_utxos.clone();

        println!(
            "[prepare_and_sign_btc_tx] >>> SIGN phase: signing {} inputs",
            psbt.inputs.len()
        );
        for i in 0..psbt.inputs.len() {
            let (addr_type, path) = &input_meta[i];
            println!(
                "[prepare_and_sign_btc_tx]   input[{}]: derive key for path={} addr_type={:?}",
                i,
                path.get_path(),
                addr_type
            );
            let sk = proto::bip32::derive_private_key(&seed_secret, &path.get_path())
                .map_err(WalletErrors::Bip329Error)?;
            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&sk.to_bytes())
                .map_err(|e| WalletErrors::BincodeError(e.to_string()))?;
            let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

            btc_tx::sign_psbt_input(
                &mut psbt,
                i,
                &secret_key,
                &public_key,
                *addr_type,
                &prevouts,
            )
            .map_err(|e| WalletErrors::BincodeError(format!("sign input {}: {:?}", i, e)))?;
        }

        println!(
            "[prepare_and_sign_btc_tx] <<< FINALIZE phase: finalizing {} inputs",
            psbt.inputs.len()
        );
        for i in 0..psbt.inputs.len() {
            let (addr_type, _) = &input_meta[i];
            btc_tx::finalize_psbt_input(&mut psbt, i, *addr_type).map_err(|e| {
                WalletErrors::BincodeError(format!("finalize input {}: {:?}", i, e))
            })?;
        }

        let signed_tx = psbt.extract_tx_unchecked_fee_rate();
        println!(
            "[prepare_and_sign_btc_tx] EXTRACTED signed tx: txid={} size={} inputs={} outputs={}",
            signed_tx.compute_txid(),
            signed_tx.total_size(),
            signed_tx.input.len(),
            signed_tx.output.len()
        );
        for (i, out) in signed_tx.output.iter().enumerate() {
            println!(
                "[prepare_and_sign_btc_tx]   output[{}]: value={} sat ({:.8} BTC) spk_len={}",
                i,
                out.value.to_sat(),
                out.value.to_sat() as f64 / 1e8,
                out.script_pubkey.len()
            );
        }

        let metadata = TransactionMetadata {
            chain_hash: data.chain_hash,
            ..Default::default()
        };

        let input_meta_raw: Vec<(u8, DerivationPath)> = input_meta
            .into_iter()
            .map(|(at, path)| (at.to_byte(), path))
            .collect();
        let btc_meta = btc_tx::BitcoinMetadata {
            witness_utxos,
            input_meta: input_meta_raw,
        };

        Ok(TransactionReceipt::Bitcoin((signed_tx, metadata, btc_meta)))
    }

    async fn rotate_account(
        &self,
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: usize,
        chain: &ChainConfig,
    ) -> Result<()> {
        let mut chains = self.get_btc_addresses(account_index, chain.hash())?;
        let network = chain.bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin);
        let ext_len_before = chains
            .get(&bitcoin::AddressType::P2tr)
            .map(|c| c.external.len())
            .unwrap_or(0);
        let int_len_before = chains
            .get(&bitcoin::AddressType::P2tr)
            .map(|c| c.internal.len())
            .unwrap_or(0);
        println!(
            "[rotate_account] account={} ext_len={} int_len={} network={:?}",
            account_index,
            ext_len_before,
            int_len_before,
            chain.bitcoin_network()
        );

        append_new_p2tr_address(&mut chains, seed, account_index, network)?;
        self.save_btc_addresses(account_index, &chains, chain.hash())?;

        let new_addr = chains
            .get(&bitcoin::AddressType::P2tr)
            .and_then(|c| c.external.last())
            .map(|e| e.address.clone())
            .ok_or_else(|| {
                WalletErrors::BincodeError("P2TR external address missing".to_string())
            })?;

        let mut data = self.get_wallet_data()?;
        data.get_mut_account(account_index)?.addr = new_addr;
        self.save_wallet_data(data)?;

        let ext_len_after = chains
            .get(&bitcoin::AddressType::P2tr)
            .map(|c| c.external.len())
            .unwrap_or(0);
        let int_len_after = chains
            .get(&bitcoin::AddressType::P2tr)
            .map(|c| c.internal.len())
            .unwrap_or(0);
        println!(
            "[rotate_account] saved, ext_len={}->{} int_len={}->{}",
            ext_len_before, ext_len_after, int_len_before, int_len_after
        );
        Ok(())
    }

    fn mark_btc_addresses_used(
        &self,
        account_index: usize,
        historical: &HistoricalTransaction,
    ) -> Result<()> {
        let Some((signed_tx, _)) = historical.get_btc() else {
            return Ok(());
        };
        let chain_hash = historical.metadata.chain_hash;
        let broadcast_txid = signed_tx.compute_txid();
        let mut chains = self.get_btc_addresses(account_index, chain_hash)?;

        let spent: HashSet<(bitcoin::Txid, u32)> = signed_tx
            .input
            .iter()
            .map(|i| (i.previous_output.txid, i.previous_output.vout))
            .collect();

        for chain in chains.values_mut() {
            for entry in chain.external.iter_mut().chain(chain.internal.iter_mut()) {
                let consumed = entry
                    .utxos
                    .iter()
                    .any(|u| spent.contains(&(u.txid, u.vout)));
                if consumed {
                    if !entry.history.contains(&broadcast_txid) {
                        entry.history.push(broadcast_txid);
                    }
                    entry.utxos.retain(|u| !spent.contains(&(u.txid, u.vout)));
                }
            }
        }

        if let Some(p2tr) = chains.get_mut(&bitcoin::AddressType::P2tr) {
            for output in &signed_tx.output {
                for entry in p2tr.internal.iter_mut() {
                    let entry_script = entry
                        .address
                        .to_bitcoin_addr()
                        .map_err(|e| WalletErrors::BincodeError(e.to_string()))?
                        .script_pubkey();
                    if entry_script == output.script_pubkey
                        && !entry.history.contains(&broadcast_txid)
                    {
                        entry.history.push(broadcast_txid);
                    }
                }
            }
        }

        self.save_btc_addresses(account_index, &chains, chain_hash)?;
        Ok(())
    }

    async fn migrate_btc_storage_if_needed(
        &self,
        seed_bytes: &Argon2Seed,
        chain: &ChainConfig,
    ) -> Result<()> {
        if chain.slip_44 != slip44::BITCOIN {
            return Ok(());
        }

        let mut data = self.get_wallet_data()?;

        match &data.wallet_type {
            WalletTypes::SecretPhrase((_, has_passphrase)) => {
                if *has_passphrase {
                    return Ok(());
                }

                let legacy_name = match data.slip44_accounts.get(&slip44::BITCOIN) {
                    Some(btc_map) if !btc_map.is_empty() => btc_map
                        .values()
                        .filter_map(|accs| accs.first())
                        .map(|a| a.name.clone())
                        .next()
                        .unwrap_or_else(|| "Bitcoin Account 0".to_string()),
                    _ => return Ok(()),
                };

                if self.get_btc_addresses(0, chain.hash()).is_ok() {
                    return Ok(());
                }

                let mnemonic = self.reveal_mnemonic(seed_bytes)?;
                let seed = mnemonic.to_seed(&crate::empty_passphrase())?;

                let account = self.generate_wallet(&seed, 0, legacy_name, chain).await?;

                let mut new_btc: HashMap<u32, Vec<AccountV2>> = HashMap::new();
                new_btc.insert(DerivationPath::BIP86_PURPOSE, vec![account]);
                data.slip44_accounts.insert(slip44::BITCOIN, new_btc);

                if data.slip44 == slip44::BITCOIN {
                    data.bip = DerivationPath::BIP86_PURPOSE;
                    if data.selected_account > 0 {
                        data.selected_account = 0;
                    }
                }

                self.save_wallet_data(data)?;
                self.storage.flush()?;

                Ok(())
            }
            WalletTypes::SecretKey => {
                if self.get_btc_addresses(0, chain.hash()).is_ok() {
                    return Ok(());
                }

                let storage_key = {
                    let account = data.get_account(0)?;
                    usize::to_le_bytes(account.account_type.value())
                };
                let cipher_sk = self.storage.get(&storage_key)?;
                let keychain = KeyChain::from_seed(seed_bytes)?;
                let sk_bytes_vec = keychain.decrypt(cipher_sk, &data.settings.cipher_orders)?;
                let sk = SecretKey::from_bytes(sk_bytes_vec.into())?;

                let (sk_bytes, network) = match sk {
                    SecretKey::Secp256k1Bitcoin((bytes, network, _)) => (bytes, network),
                    _ => return Ok(()),
                };

                let (mut chains, p2tr_addr) = derive_sk_btc_address_chains(&sk_bytes, network)?;

                let provider = NetworkProvider::new(chain.clone());
                if let Err(e) = provider.batch_script_get_history(&mut chains).await {
                    println!(
                        "[migrate_btc_storage_if_needed] sk btc history scan failed (offline?): {:?}",
                        e
                    );
                }

                self.save_btc_addresses(0, &chains, chain.hash())?;
                data.get_mut_account(0)?.addr = p2tr_addr;
                self.save_wallet_data(data)?;
                self.storage.flush()?;

                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests_btc_wallet {
    use std::sync::Arc;

    use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, Witness};
    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{bip39::EN_WORDS, cipher::PROOF_SIZE, session::AuthMethod};
    use history::{status::TransactionStatus, transaction::HistoricalTransaction};
    use pqbip39::mnemonic::Mnemonic;
    use proto::{btc_tx::BitcoinMetadata, btc_utils::Utxo, tx::TransactionMetadata};
    use rand::RngExt;
    use rpc::network_config::ChainConfig;
    use secrecy::SecretString;
    use storage::LocalStorage;
    use test_data::{empty_passphrase, ANVIL_MNEMONIC, TEST_PASSWORD};

    use crate::{
        bitcoin_wallet::BitcoinWallet, wallet_init::WalletInit, Bip39Params, Wallet, WalletConfig,
    };

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let storage = LocalStorage::from(&dir).unwrap();
        (Arc::new(storage), dir)
    }

    #[tokio::test]
    async fn test_mark_btc_addresses_used_marks_inputs_and_change() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &[(0, "Bitcoin Account 0".to_string())],
                wallet_name: "Bitcoin Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let chain_hash = chain_config.hash();
        let mut chains = wallet.get_btc_addresses(0, chain_hash).unwrap();
        let p2tr = chains.get_mut(&bitcoin::AddressType::P2tr).unwrap();
        assert!(p2tr.external.len() >= 2);
        assert!(p2tr.internal.len() >= 2);

        let planted_txid = "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f"
            .parse::<bitcoin::Txid>()
            .unwrap();
        let planted = Utxo {
            txid: planted_txid,
            vout: 0,
            value: 100_000,
            height: 800_000,
        };
        p2tr.external[0].utxos.push(planted.clone());
        let input_script = p2tr.external[0]
            .address
            .to_bitcoin_addr()
            .unwrap()
            .script_pubkey();
        let change_script = p2tr.internal[0]
            .address
            .to_bitcoin_addr()
            .unwrap()
            .script_pubkey();
        let other_ext_script = p2tr.external[1]
            .address
            .to_bitcoin_addr()
            .unwrap()
            .script_pubkey();
        let other_int_script = p2tr.internal[1]
            .address
            .to_bitcoin_addr()
            .unwrap()
            .script_pubkey();
        wallet.save_btc_addresses(0, &chains, chain_hash).unwrap();

        let signed_tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: planted.txid,
                    vout: planted.vout,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: change_script.clone(),
            }],
        };
        let broadcast_txid = signed_tx.compute_txid();

        let historical = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash,
                ..Default::default()
            },
            btc: Some((
                signed_tx,
                BitcoinMetadata {
                    witness_utxos: vec![bitcoin::TxOut {
                        value: Amount::from_sat(planted.value),
                        script_pubkey: input_script,
                    }],
                    input_meta: vec![],
                },
            )),
            ..Default::default()
        };

        wallet.mark_btc_addresses_used(0, &historical).unwrap();

        let chains = wallet.get_btc_addresses(0, chain_hash).unwrap();
        let p2tr = chains.get(&bitcoin::AddressType::P2tr).unwrap();

        assert_eq!(p2tr.external[0].history, vec![broadcast_txid]);
        assert!(p2tr.external[0].utxos.is_empty());
        assert_eq!(p2tr.internal[0].history, vec![broadcast_txid]);

        assert!(p2tr.external[1].history.is_empty());
        assert!(p2tr.internal[1].history.is_empty());
        let _ = (other_ext_script, other_int_script);
    }

    #[tokio::test]
    async fn test_mark_btc_addresses_used_skips_non_btc_history() {
        let (storage, _dir) = setup_test_storage();
        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: &empty_passphrase(),
                indexes: &[(0, "Bitcoin Account 0".to_string())],
                wallet_name: "Bitcoin Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chains: &[chain_config.clone()],
            },
            wallet_config,
            vec![],
        )
        .await
        .unwrap();

        let historical = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: chain_config.hash(),
                ..Default::default()
            },
            btc: None,
            ..Default::default()
        };

        wallet.mark_btc_addresses_used(0, &historical).unwrap();
    }
}
