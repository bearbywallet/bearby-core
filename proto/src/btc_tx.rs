use bitcoin::ecdsa::Signature as BitcoinEcdsaSignature;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    bip32, PrivateKey, PublicKey as BitcoinPublicKey, ScriptBuf, Transaction as BitcoinTransaction,
    Witness,
};
use errors::tx::TransactionErrors;
use std::collections::BTreeMap;

pub fn build_psbt(
    tx: BitcoinTransaction,
    witness_utxos: &[bitcoin::TxOut],
) -> Result<Psbt, TransactionErrors> {
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| TransactionErrors::PsbtCreationFailed)?;

    for (input, utxo) in psbt.inputs.iter_mut().zip(witness_utxos.iter()) {
        input.witness_utxo = Some(utxo.clone());
    }

    Ok(psbt)
}

pub fn sign_psbt(
    psbt: &mut Psbt,
    secret_key: &bitcoin::secp256k1::SecretKey,
    public_key: &bitcoin::secp256k1::PublicKey,
    network: bitcoin::Network,
    addr_type: bitcoin::AddressType,
) -> Result<(), TransactionErrors> {
    let secp = Secp256k1::new();
    let priv_key = PrivateKey::new(*secret_key, network);
    let dummy_origin = (
        bip32::Fingerprint::default(),
        bip32::DerivationPath::default(),
    );

    match addr_type {
        bitcoin::AddressType::P2tr => {
            let (xonly, _) = public_key.x_only_public_key();

            for input in &mut psbt.inputs {
                input.tap_internal_key = Some(xonly);
                input
                    .tap_key_origins
                    .insert(xonly, (vec![], dummy_origin.clone()));
            }

            let key_map = BTreeMap::from([(xonly, priv_key)]);
            psbt.sign(&key_map, &secp)
                .map_err(|_| TransactionErrors::PsbtSigningFailed)?;
        }
        bitcoin::AddressType::P2pkh => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);
            let prev_script = ScriptBuf::new_p2pkh(&btc_pubkey.pubkey_hash());
            let sighash_type = EcdsaSighashType::All;
            let tx = psbt.unsigned_tx.clone();
            let cache = SighashCache::new(&tx);

            for (index, input) in psbt.inputs.iter_mut().enumerate() {
                let sighash = cache
                    .legacy_signature_hash(index, &prev_script, sighash_type.to_u32())
                    .map_err(|_| TransactionErrors::SighashComputationFailed)?;

                let message = Message::from_digest(*sighash.as_ref());
                let sig = secp.sign_ecdsa(&message, secret_key);

                input.partial_sigs.insert(
                    btc_pubkey,
                    BitcoinEcdsaSignature {
                        signature: sig,
                        sighash_type,
                    },
                );
            }
        }
        _ => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);

            for input in &mut psbt.inputs {
                input
                    .bip32_derivation
                    .insert(*public_key, dummy_origin.clone());
            }

            let key_map = BTreeMap::from([(btc_pubkey, priv_key)]);
            psbt.sign(&key_map, &secp)
                .map_err(|_| TransactionErrors::PsbtSigningFailed)?;
        }
    }

    Ok(())
}

pub fn finalize_psbt(
    psbt: &mut Psbt,
    addr_type: bitcoin::AddressType,
) -> Result<(), TransactionErrors> {
    for input in &mut psbt.inputs {
        match addr_type {
            bitcoin::AddressType::P2tr => {
                if let Some(sig) = input.tap_key_sig.take() {
                    input.final_script_witness = Some(Witness::p2tr_key_spend(&sig));
                }
            }
            bitcoin::AddressType::P2pkh => {
                if let Some((&pubkey, sig)) = input.partial_sigs.iter().next() {
                    let sig_bytes = sig.serialize();
                    let pk_bytes = pubkey.to_bytes();
                    let sig_push =
                        <&bitcoin::script::PushBytes>::try_from(sig_bytes.as_ref() as &[u8])
                            .map_err(|_| TransactionErrors::PsbtFinalizeFailed)?;
                    let pk_push = <&bitcoin::script::PushBytes>::try_from(pk_bytes.as_slice())
                        .map_err(|_| TransactionErrors::PsbtFinalizeFailed)?;
                    let script_sig = Builder::new()
                        .push_slice(sig_push)
                        .push_slice(pk_push)
                        .into_script();
                    input.final_script_sig = Some(script_sig);
                }
                input.partial_sigs.clear();
            }
            _ => {
                if let Some((&pubkey, sig)) = input.partial_sigs.iter().next() {
                    let mut witness = Witness::new();
                    witness.push(sig.serialize());
                    witness.push(pubkey.to_bytes());
                    input.final_script_witness = Some(witness);
                }
                input.partial_sigs.clear();
            }
        }

        input.witness_utxo = None;
        input.sighash_type = None;
        input.bip32_derivation.clear();
        input.tap_key_origins.clear();
        input.tap_internal_key = None;
    }

    Ok(())
}
