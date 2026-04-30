use crate::{wallet_storage::StorageOperations, Result, WalletAddrType};
use async_trait::async_trait;
use bitcoin::Transaction as BitcoinTransaction;
use cipher::argon2::Argon2Seed;
use config::storage::HISTORY_TXNS_DB_KEY_V1;
use errors::wallet::WalletErrors;
use proto::btc_tx;
use proto::btc_utils::ByteCodec;
use proto::tx::{TransactionMetadata, TransactionReceipt, TransactionRequest};
use secrecy::SecretString;

use crate::{wallet_crypto::WalletCrypto, Wallet};

#[async_trait]
pub trait WalletTransaction {
    type Error;

    async fn sign_transaction(
        &self,
        req_tx: TransactionRequest,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

    fn clear_history(&mut self) -> std::result::Result<(), Self::Error>;

    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8>;
}

#[async_trait]
impl WalletTransaction for Wallet {
    type Error = WalletErrors;

    fn clear_history(&mut self) -> Result<()> {
        let mut history = self.get_history()?;

        if history.is_empty() {
            return Ok(());
        }

        history = Vec::with_capacity(0);
        self.add_history(&history)?;

        Ok(())
    }

    async fn sign_transaction(
        &self,
        req_tx: TransactionRequest,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt> {
        let req_tx = match req_tx {
            TransactionRequest::Bitcoin((tx, metadata))
                if metadata.btc_input_meta.is_some() =>
            {
                return self
                    .sign_btc_multi_input(tx, metadata, seed_bytes, passphrase)
                    .await;
            }
            other => other,
        };

        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;

        Ok(req_tx.sign(&keypair).await?)
    }

    #[inline]
    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8> {
        [key, HISTORY_TXNS_DB_KEY_V1].concat()
    }
}

impl Wallet {
    async fn sign_btc_multi_input(
        &self,
        tx: BitcoinTransaction,
        mut metadata: TransactionMetadata,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt> {
        let witness_utxos = metadata
            .btc_witness_utxos
            .take()
            .ok_or_else(|| WalletErrors::BincodeError("Missing BTC witness UTXOs".to_string()))?;
        let input_meta_raw = metadata
            .btc_input_meta
            .take()
            .ok_or_else(|| WalletErrors::BincodeError("Missing BTC input meta".to_string()))?;

        if input_meta_raw.len() != tx.input.len() || witness_utxos.len() != tx.input.len() {
            return Err(WalletErrors::BincodeError(format!(
                "BTC input meta/utxos count mismatch: inputs={} meta={} utxos={}",
                tx.input.len(),
                input_meta_raw.len(),
                witness_utxos.len()
            )));
        }

        let mnemonic = self.reveal_mnemonic(seed_bytes)?;
        let seed_secret = mnemonic
            .to_seed(&SecretString::from(passphrase.unwrap_or("")))
            .map_err(|e| {
                WalletErrors::Bip329Error(errors::bip32::Bip329Errors::InvalidKey(format!(
                    "{:?}",
                    e
                )))
            })?;

        let mut psbt = btc_tx::build_psbt(tx, &witness_utxos)
            .map_err(|e| WalletErrors::BincodeError(format!("build_psbt: {:?}", e)))?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let prevouts: Vec<bitcoin::TxOut> = witness_utxos;
        let network = bitcoin::Network::Bitcoin;

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

            btc_tx::sign_psbt_input(
                &mut psbt,
                i,
                &secret_key,
                &public_key,
                network,
                addr_type,
                &prevouts,
            )
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
            btc_tx::finalize_psbt_input(&mut psbt, i, addr_type)
                .map_err(|e| WalletErrors::BincodeError(format!("finalize input {}: {:?}", i, e)))?;
        }

        let signed_tx = psbt.extract_tx_unchecked_fee_rate();

        Ok(TransactionReceipt::Bitcoin((signed_tx, metadata)))
    }
}
