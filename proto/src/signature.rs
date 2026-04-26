use alloy::primitives::B256;
use alloy::signers::k256;
use alloy::signers::Signature as EthersSignature;
use config::key::ED25519_PUB_KEY_SIZE;
use config::sha::{ECDSAS_ECP256K1_KECCAK256_SIZE, SHA512_SIZE};
use crypto::schnorr;
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
use errors::crypto::SignatureError;
use k256::ecdsa::Signature as SchnorrSignature;
use k256::PublicKey as K256PublicKey;

use crate::pubkey::PubKey;

type Result<T> = std::result::Result<T, SignatureError>;

pub const ED25519_SIG_SIZE: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Signature {
    SchnorrSecp256k1Sha256([u8; SHA512_SIZE]), // Zilliqa
    ECDSASecp256k1Keccak256([u8; ECDSAS_ECP256K1_KECCAK256_SIZE]), // Ethereum
    Ed25519Solana([u8; ED25519_SIG_SIZE]),     // Solana
}

impl Signature {
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes =
            hex::decode(value).map_err(|_| SignatureError::InvalidHexString(value.to_string()))?;

        bytes.as_slice().try_into()
    }

    pub fn from_ed25519_bytes(bytes: [u8; ED25519_SIG_SIZE]) -> Self {
        Self::Ed25519Solana(bytes)
    }

    pub fn to_hex_prefixed(&self) -> String {
        match self {
            Self::SchnorrSecp256k1Sha256(bytes) => alloy::hex::encode_prefixed(bytes),
            Self::ECDSASecp256k1Keccak256(bytes) => alloy::hex::encode_prefixed(bytes),
            Self::Ed25519Solana(bytes) => alloy::hex::encode_prefixed(bytes),
        }
    }

    pub fn verify(&self, msg_bytes: &[u8], pk: &PubKey) -> Result<bool> {
        match self {
            Signature::SchnorrSecp256k1Sha256(sig) => {
                let sig = SchnorrSignature::from_slice(sig)
                    .or(Err(SignatureError::FailParseSignature))?;
                let pk: K256PublicKey = pk.try_into().map_err(SignatureError::FailIntoPubKey)?;
                let verify = schnorr::verify(msg_bytes, pk, sig);

                Ok(verify.is_some())
            }
            Signature::ECDSASecp256k1Keccak256(sig) => {
                let parity = sig[64] % 2 != 1;
                let signature = EthersSignature::from_bytes_and_parity(sig, parity);

                let signer_address = pk.get_addr().map_err(SignatureError::FailIntoPubKey)?;
                let recovered_address = signature
                    .recover_address_from_msg(msg_bytes)
                    .map_err(|e| SignatureError::FailParseRecover(e.to_string()))?;
                let signer_address = signer_address.to_alloy_addr();

                Ok(recovered_address == signer_address)
            }
            Signature::Ed25519Solana(sig_bytes) => {
                let pk_bytes: [u8; ED25519_PUB_KEY_SIZE] =
                    pk.as_ref().try_into().map_err(|_| {
                        SignatureError::FailIntoPubKey(errors::keypair::PubKeyError::InvalidLength)
                    })?;
                let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
                    .map_err(|_| SignatureError::FailParseSignature)?;
                let sig = Ed25519Sig::from_bytes(sig_bytes);
                Ok(verifying_key.verify(msg_bytes, &sig).is_ok())
            }
        }
    }

    pub fn verify_hash(&self, hash: &[u8; 32], pk: &PubKey) -> Result<bool> {
        match self {
            Signature::SchnorrSecp256k1Sha256(_) => Err(SignatureError::FailParseSignature),
            Signature::ECDSASecp256k1Keccak256(sig) => {
                let parity = sig[64] % 2 != 1;
                let signature = EthersSignature::from_bytes_and_parity(sig, parity);

                let signer_address = pk.get_addr().map_err(SignatureError::FailIntoPubKey)?;
                let hash = B256::from_slice(hash);
                let recovered_address = signature
                    .recover_address_from_prehash(&hash)
                    .map_err(|e| SignatureError::FailParseRecover(e.to_string()))?;
                let signer_address = signer_address.to_alloy_addr();

                Ok(recovered_address == signer_address)
            }
            Signature::Ed25519Solana(_) => Err(SignatureError::FailParseSignature),
        }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;

    fn try_from(sig_bytes: &[u8]) -> Result<Self> {
        if sig_bytes.len() == SHA512_SIZE {
            let buf: [u8; SHA512_SIZE] = sig_bytes
                .try_into()
                .or(Err(SignatureError::InvalidLength))?;

            Ok(Signature::SchnorrSecp256k1Sha256(buf))
        } else if sig_bytes.len() == ECDSAS_ECP256K1_KECCAK256_SIZE {
            let buf: [u8; ECDSAS_ECP256K1_KECCAK256_SIZE] = sig_bytes
                .try_into()
                .or(Err(SignatureError::InvalidLength))?;

            Ok(Signature::ECDSASecp256k1Keccak256(buf))
        } else {
            Err(SignatureError::InvalidLength)
        }
    }
}

impl TryFrom<EthersSignature> for Signature {
    type Error = SignatureError;

    fn try_from(eth_sig: EthersSignature) -> Result<Self> {
        let sig_bytes: [u8; ECDSAS_ECP256K1_KECCAK256_SIZE] = eth_sig.into();

        Ok(Signature::ECDSASecp256k1Keccak256(sig_bytes))
    }
}

impl TryFrom<SchnorrSignature> for Signature {
    type Error = SignatureError;

    fn try_from(sig: SchnorrSignature) -> Result<Self> {
        let sig_bytes: [u8; SHA512_SIZE] = sig.to_bytes().into();

        Ok(Signature::SchnorrSecp256k1Sha256(sig_bytes))
    }
}
