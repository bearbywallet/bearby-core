use crate::{
    account::AccountV2, wallet_crypto::WalletCrypto, wallet_storage::StorageOperations, Result,
    Wallet, WalletAddrType,
};
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
    btc_tx::{self, BitcoinMetadata},
    btc_utils::{generate_btc_addresses, AddressChain, ByteCodec, GAP_LIMIT},
    tx::{TransactionMetadata, TransactionReceipt},
};
use rpc::network_config::ChainConfig;
use secrecy::SecretBox;
use secrecy::SecretString;
use std::collections::HashMap;

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

    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize, chain_hash: u64) -> Vec<u8>;

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
                    let done = scan_view.values().all(|chain| {
                        chain.get_external().is_ok() && chain.get_internal().is_ok()
                    });
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
    fn get_btc_addresses_db_key(key: &WalletAddrType, account_index: usize, chain_hash: u64) -> Vec<u8> {
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
}
