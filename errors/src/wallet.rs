use crate::{
    account::AccountErrors,
    address::AddressError,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, PubKeyError, SecretKeyError},
    storage::LocalStorageError,
    tx::TransactionErrors,
};
use bincode::ErrorKind;
use pqbip39::errors::Bip39Error;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum WalletErrors {
    #[error("No accounts available in wallet")]
    NoAccounts,

    #[error("Invalid account index: {0}. Selected index not found")]
    InvalidAccountIndex(usize),

    #[error("Invalid BIP Path slip44: {0}, bip: {1}")]
    InvalidBIPPath(u32, u32),

    #[error("Invalid BIP Path slip44: {0}, bip: {1}, index: {2}")]
    InvalidBIPPathIndex(u32, u32, usize),

    #[error("Account with index ({0}) already exists")]
    ExistsAccount(usize),

    #[error("Account with index ({0}) not exists")]
    NotExistsAccount(usize),

    #[error("fail create argon2: {0}")]
    ArgonCipherErrors(CipherErrors),

    #[error("Token doesn't extists: {0}")]
    TokenNotExists(usize),

    #[error("request tx doesn't extists: {0}")]
    TxNotExists(usize),

    #[error("Token is default flag: {0}")]
    DefaultTokenRemove(usize),

    #[error("This token already exists {0}")]
    TokenAlreadyExists(String),

    #[error("Try encrypt secret key error")]
    TryEncryptSecretKeyError,

    #[error("Invalid signature verify")]
    InvalidVerifySig,

    #[error("Fail to get SK bytes: {0}")]
    FailToGetSKBytes(SecretKeyError),

    #[error("BIP39 not valid: {0}")]
    Bip39NotValid(String),

    #[error("passphrase is None")]
    PassphraseIsNone,

    #[error("fail to load mnemonic from entropy: {0}")]
    FailLoadMnemonicFromEntropy(String),

    #[error("Fail to get account by index: {0}")]
    FailToGetAccount(usize),

    #[error("fail to find provider with hash: {0}")]
    ProviderNotExist(u64),

    #[error("Invalid account type")]
    InvalidAccountType,

    #[error("LocalStorage error: {0}")]
    LocalStorageError(LocalStorageError),

    #[error("Failed to get proof from storage: {0}")]
    FailToGetProofFromStorage(LocalStorageError),

    #[error("invalid hex wallet type")]
    InvalidHexToWalletType,

    #[error("WalletType serialize error: {0}")]
    WalletTypeSerialize(String),

    #[error("WalletType deserialize error: {0}")]
    WalletTypeDeserialize(String),

    #[error("Proof does not match")]
    ProofNotMatch,

    #[error("Transaction Error: {0}")]
    TransactionErrors(TransactionErrors),

    #[error("Bincode Error: {0}")]
    BincodeError(String),

    #[error("KeyChain Error: {0}")]
    KeyChainError(KeyChainErrors),

    #[error("Account Error: {0}")]
    AccountErrors(AccountErrors),

    #[error("SecretKey Error: {0}")]
    SecretKeyError(SecretKeyError),

    #[error("KeyPair Error: {0}")]
    KeyPairError(KeyPairError),

    #[error("Bip39 error: {0}")]
    Bip39Error(Bip39Error),

    #[error("address error: {0}")]
    AddressError(AddressError),

    #[error("Thread panicked during account generation")]
    ThreadPanic,

    #[error("Bip32/derivation error: {0}")]
    Bip329Error(crate::bip32::Bip329Errors),
}

impl From<LocalStorageError> for WalletErrors {
    fn from(error: LocalStorageError) -> Self {
        WalletErrors::LocalStorageError(error)
    }
}

impl From<KeyPairError> for WalletErrors {
    fn from(error: KeyPairError) -> Self {
        WalletErrors::KeyPairError(error)
    }
}

impl From<AccountErrors> for WalletErrors {
    fn from(error: AccountErrors) -> Self {
        WalletErrors::AccountErrors(error)
    }
}

impl From<SecretKeyError> for WalletErrors {
    fn from(error: SecretKeyError) -> Self {
        WalletErrors::SecretKeyError(error)
    }
}

impl From<KeyChainErrors> for WalletErrors {
    fn from(error: KeyChainErrors) -> Self {
        WalletErrors::KeyChainError(error)
    }
}

impl From<Box<ErrorKind>> for WalletErrors {
    fn from(error: Box<ErrorKind>) -> Self {
        WalletErrors::BincodeError(error.to_string())
    }
}

impl From<rmp_serde::encode::Error> for WalletErrors {
    fn from(error: rmp_serde::encode::Error) -> Self {
        WalletErrors::BincodeError(error.to_string())
    }
}

impl From<rmp_serde::decode::Error> for WalletErrors {
    fn from(error: rmp_serde::decode::Error) -> Self {
        WalletErrors::BincodeError(error.to_string())
    }
}

impl From<TransactionErrors> for WalletErrors {
    fn from(error: TransactionErrors) -> Self {
        WalletErrors::TransactionErrors(error)
    }
}

impl From<Bip39Error> for WalletErrors {
    fn from(error: Bip39Error) -> Self {
        WalletErrors::Bip39Error(error)
    }
}

impl From<AddressError> for WalletErrors {
    fn from(error: AddressError) -> Self {
        WalletErrors::AddressError(error)
    }
}

impl From<crate::bip32::Bip329Errors> for WalletErrors {
    fn from(error: crate::bip32::Bip329Errors) -> Self {
        WalletErrors::Bip329Error(error)
    }
}

impl From<PubKeyError> for WalletErrors {
    fn from(error: PubKeyError) -> Self {
        WalletErrors::AddressError(error.into())
    }
}
