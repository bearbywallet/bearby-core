use crate::{
    address::AddressError,
    bip32::Bip329Errors,
    crypto::{SchorrError, SignatureError},
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum KeyPairError {
    #[error("Fail to sign transaction: {0}")]
    FailToSignTx(String),

    #[error("Extended private key derivation error: {0}")]
    ExtendedPrivKeyDeriveError(Bip329Errors),

    #[error("Schorr error: {0}")]
    SchorrError(#[from] SchorrError),

    #[error("Invalid length")]
    InvalidLength,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Invalid entropy")]
    InvalidEntropy,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid key type")]
    InvalidKeyType,

    #[error("Address parse error: {0}")]
    AddressParseError(#[from] AddressError),

    #[error("Ethers invalid secret key: {0}")]
    EthersInvalidSecretKey(String),

    #[error("Ethers invalid sign: {0}")]
    EthersInvalidSign(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(SignatureError),

    #[error("Secret Key error: {0}")]
    SecretKeyError(SecretKeyError),

    #[error("Transaction error: {0}")]
    TransactionErrors(String),

    #[error("secp256 sha256 is not supported eip712")]
    InvalidSecp256k1Sha256,

    #[error("Bitcoin keys do not support EIP712")]
    InvalidSecp256k1Bitcoin,

    #[error("Tron keys do not support EIP712")]
    InvalidSecp256k1Tron,

    #[error("eip712 error: {0}")]
    Eip712Error(String),

    #[error("Solana keys do not support EIP712 or hash signing")]
    InvalidEd25519Solana,
}

#[derive(Debug, Error, PartialEq)]
pub enum SecretKeyError {
    #[error("Secret key slice error")]
    SecretKeySliceError,

    #[error("Invalid hex")]
    InvalidHex,

    #[error("Invalid length")]
    InvalidLength,

    #[error("Invalid key type")]
    InvalidKeyType,

    #[error("Invalid WIF format: {0}")]
    InvalidWif(String),
}

#[derive(Debug, Error, PartialEq)]
pub enum PubKeyError {
    #[error("Invalid VerifyingKey {0}")]
    InvalidVerifyingKey(String),

    #[error("address error {0}")]
    AddressError(AddressError),

    #[error("Invalid length")]
    InvalidLength,

    #[error("Invalid key type")]
    InvalidKeyType,

    #[error("Invalid hex")]
    InvalidHex,

    #[error("Invalid verifying key")]
    InvalidPubKey,

    #[error("Failed to convert into public key")]
    FailIntoPubKey,

    #[error("Not implemented")]
    NotImpl,

    #[error("No unused address available")]
    NoUnusedAddress,
}

impl From<AddressError> for PubKeyError {
    fn from(error: AddressError) -> Self {
        PubKeyError::AddressError(error)
    }
}
