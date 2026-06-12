use bitcoin::ecdsa::Signature as BitcoinEcdsaSignature;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, SECP256K1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{
    bip32, PrivateKey, PublicKey as BitcoinPublicKey, ScriptBuf, Transaction as BitcoinTransaction,
    TxOut, Witness,
};
use crypto::bip49::DerivationPath;
use errors::tx::TransactionErrors;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitcoinMetadata {
    pub witness_utxos: Vec<TxOut>,
    pub input_meta: Vec<(u8, DerivationPath)>,
}

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

pub fn sign_psbt_input(
    psbt: &mut Psbt,
    index: usize,
    secret_key: &bitcoin::secp256k1::SecretKey,
    public_key: &bitcoin::secp256k1::PublicKey,
    addr_type: bitcoin::AddressType,
    prevouts: &[TxOut],
) -> Result<(), TransactionErrors> {
    let secp = &SECP256K1;

    if index >= psbt.inputs.len() || index >= prevouts.len() {
        return Err(TransactionErrors::PsbtSigningFailed);
    }

    let value = prevouts[index].value;

    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);

    match addr_type {
        bitcoin::AddressType::P2tr => {
            let sighash_type = TapSighashType::Default;
            let prevouts_ref = Prevouts::All(prevouts);
            let sighash = cache
                .taproot_key_spend_signature_hash(index, &prevouts_ref, sighash_type)
                .map_err(|_| TransactionErrors::SighashComputationFailed)?;
            let message = Message::from_digest(*sighash.as_ref());

            let keypair = Keypair::from_secret_key(secp, secret_key);
            let tweaked = keypair.tap_tweak(secp, None);
            let sig = secp.sign_schnorr_no_aux_rand(&message, &tweaked.to_keypair());

            let input = &mut psbt.inputs[index];
            input.tap_key_sig = Some(TaprootSignature {
                signature: sig,
                sighash_type,
            });
        }
        bitcoin::AddressType::P2pkh => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);
            let prev_script = ScriptBuf::new_p2pkh(&btc_pubkey.pubkey_hash());
            let sighash_type = EcdsaSighashType::All;
            let sighash = cache
                .legacy_signature_hash(index, &prev_script, sighash_type.to_u32())
                .map_err(|_| TransactionErrors::SighashComputationFailed)?;
            let message = Message::from_digest(*sighash.as_ref());
            let sig = secp.sign_ecdsa(&message, secret_key);

            {
                let input = &mut psbt.inputs[index];
                input.partial_sigs.insert(
                    btc_pubkey,
                    BitcoinEcdsaSignature {
                        signature: sig,
                        sighash_type,
                    },
                );
            }
        }
        bitcoin::AddressType::P2wpkh => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);
            let wpkh_script = ScriptBuf::new_p2wpkh(
                &btc_pubkey
                    .wpubkey_hash()
                    .map_err(|_| TransactionErrors::SighashComputationFailed)?,
            );
            let sighash_type = EcdsaSighashType::All;
            let sighash = cache
                .p2wpkh_signature_hash(index, &wpkh_script, value, sighash_type)
                .map_err(|_| TransactionErrors::SighashComputationFailed)?;
            let message = Message::from_digest(*sighash.as_ref());
            let sig = secp.sign_ecdsa(&message, secret_key);

            {
                let input = &mut psbt.inputs[index];
                input.partial_sigs.insert(
                    btc_pubkey,
                    BitcoinEcdsaSignature {
                        signature: sig,
                        sighash_type,
                    },
                );
            }
        }
        bitcoin::AddressType::P2sh => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);
            let wpkh_hash = btc_pubkey
                .wpubkey_hash()
                .map_err(|_| TransactionErrors::SighashComputationFailed)?;
            let redeem_script = ScriptBuf::new_p2wpkh(&wpkh_hash);
            let sighash_type = EcdsaSighashType::All;
            let sighash = cache
                .p2wpkh_signature_hash(index, &redeem_script, value, sighash_type)
                .map_err(|_| TransactionErrors::SighashComputationFailed)?;
            let message = Message::from_digest(*sighash.as_ref());
            let sig = secp.sign_ecdsa(&message, secret_key);

            let input = &mut psbt.inputs[index];
            input.partial_sigs.insert(
                btc_pubkey,
                BitcoinEcdsaSignature {
                    signature: sig,
                    sighash_type,
                },
            );
            input.redeem_script = Some(redeem_script);
        }
        _ => {
            return Err(TransactionErrors::PsbtSigningFailed);
        }
    }

    Ok(())
}

pub fn finalize_psbt_input(
    psbt: &mut Psbt,
    index: usize,
    addr_type: bitcoin::AddressType,
) -> Result<(), TransactionErrors> {
    if index >= psbt.inputs.len() {
        return Err(TransactionErrors::PsbtFinalizeFailed);
    }
    let input = &mut psbt.inputs[index];
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
                let sig_push = <&bitcoin::script::PushBytes>::try_from(sig_bytes.as_ref() as &[u8])
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
        bitcoin::AddressType::P2sh => {
            if let Some(redeem) = input.redeem_script.take() {
                let push = <&bitcoin::script::PushBytes>::try_from(redeem.as_bytes())
                    .map_err(|_| TransactionErrors::PsbtFinalizeFailed)?;
                let script_sig = Builder::new().push_slice(push).into_script();
                input.final_script_sig = Some(script_sig);
            }
            if let Some((&pubkey, sig)) = input.partial_sigs.iter().next() {
                let mut witness = Witness::new();
                witness.push(sig.serialize());
                witness.push(pubkey.to_bytes());
                input.final_script_witness = Some(witness);
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

    Ok(())
}

pub fn sign_psbt(
    psbt: &mut Psbt,
    secret_key: &bitcoin::secp256k1::SecretKey,
    public_key: &bitcoin::secp256k1::PublicKey,
    network: bitcoin::Network,
    addr_type: bitcoin::AddressType,
) -> Result<(), TransactionErrors> {
    let secp = &SECP256K1;
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
            psbt.sign(&key_map, secp)
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
            psbt.sign(&key_map, secp)
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
