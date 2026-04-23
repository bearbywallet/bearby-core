use alloy::dyn_abi::eip712::TypedData;
use alloy::signers::Signer;
use alloy::{
    network::EthereumWallet,
    signers::{local::PrivateKeySigner, SignerSync},
};
use config::key::{BIP39_SEED_SIZE, ED25519_PUB_KEY_SIZE, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use solana_pubkey::Pubkey;
use crypto::{bip49::DerivationPath, schnorr, slip44};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use k256::SecretKey as K256SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    address::Address,
    bip32::{derive_ed25519_key, derive_private_key},
    btc_utils::ByteCodec,
    pubkey::PubKey,
    signature::Signature,
    tx::{TransactionReceipt, TransactionRequest},
};

use super::secret_key::SecretKey;
use errors::{bip32::Bip329Errors, keypair::KeyPairError};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// One byte for enum type
pub const KEYPAIR_BYTES_SIZE: usize = PUB_KEY_SIZE + SECRET_KEY_SIZE + 1;

type Result<T> = std::result::Result<T, KeyPairError>;

#[derive(Debug, PartialEq, Clone)]
pub enum KeyPair {
    Secp256k1Sha256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
    Secp256k1Keccak256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
    Secp256k1Bitcoin(
        (
            [u8; PUB_KEY_SIZE],
            [u8; SECRET_KEY_SIZE],
            bitcoin::Network,
            bitcoin::AddressType,
        ),
    ),
    Secp256k1Tron(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
    Ed25519Solana(([u8; ED25519_PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        match self {
            KeyPair::Secp256k1Sha256((pk, sk)) => {
                pk.zeroize();
                sk.zeroize();
            }
            KeyPair::Secp256k1Keccak256((pk, sk)) => {
                pk.zeroize();
                sk.zeroize();
            }
            KeyPair::Secp256k1Bitcoin((pk, sk, _, _)) => {
                pk.zeroize();
                sk.zeroize();
            }
            KeyPair::Secp256k1Tron((pk, sk)) => {
                pk.zeroize();
                sk.zeroize();
            }
            KeyPair::Ed25519Solana((pk, sk)) => {
                pk.zeroize();
                sk.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for KeyPair {}

impl KeyPair {
    pub fn gen_sha256() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Sha256(keys))
    }

    pub fn gen_keccak256() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Keccak256(keys))
    }

    pub fn gen_bitcoin(network: bitcoin::Network, addr_type: bitcoin::AddressType) -> Result<Self> {
        let (pk, sk) = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Bitcoin((pk, sk, network, addr_type)))
    }

    pub fn gen_tron() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Tron(keys))
    }

    pub fn to_sha256(self) -> Self {
        match self {
            Self::Secp256k1Sha256(value) => Self::Secp256k1Sha256(value),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Sha256(value),
            Self::Secp256k1Bitcoin((pk, sk, _, _)) => Self::Secp256k1Sha256((pk, sk)),
            Self::Secp256k1Tron(value) => Self::Secp256k1Sha256(value),
            Self::Ed25519Solana(value) => Self::Ed25519Solana(value),
        }
    }

    pub fn to_keccak256(self) -> Self {
        match self {
            Self::Secp256k1Sha256(value) => Self::Secp256k1Keccak256(value),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Keccak256(value),
            Self::Secp256k1Bitcoin((pk, sk, _, _)) => Self::Secp256k1Keccak256((pk, sk)),
            Self::Secp256k1Tron(value) => Self::Secp256k1Keccak256(value),
            Self::Ed25519Solana(value) => Self::Ed25519Solana(value),
        }
    }

    pub fn to_bitcoin(self, network: bitcoin::Network, addr_type: bitcoin::AddressType) -> Self {
        match self {
            Self::Secp256k1Sha256((pk, sk)) => Self::Secp256k1Bitcoin((pk, sk, network, addr_type)),
            Self::Secp256k1Keccak256((pk, sk)) => {
                Self::Secp256k1Bitcoin((pk, sk, network, addr_type))
            }
            Self::Secp256k1Bitcoin((pk, sk, _, _)) => {
                Self::Secp256k1Bitcoin((pk, sk, network, addr_type))
            }
            Self::Secp256k1Tron((pk, sk)) => Self::Secp256k1Bitcoin((pk, sk, network, addr_type)),
            Self::Ed25519Solana(value) => Self::Ed25519Solana(value),
        }
    }

    pub fn to_tron(self) -> Self {
        match self {
            Self::Secp256k1Sha256(value) => Self::Secp256k1Tron(value),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Tron(value),
            Self::Secp256k1Bitcoin((pk, sk, _, _)) => Self::Secp256k1Tron((pk, sk)),
            Self::Secp256k1Tron(value) => Self::Secp256k1Tron(value),
            Self::Ed25519Solana(value) => Self::Ed25519Solana(value),
        }
    }

    pub fn from_sk_bytes(
        sk: [u8; SECRET_KEY_SIZE],
    ) -> Result<([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])> {
        let secret_key = K256SecretKey::from_slice(&sk).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok((pub_key, secret_key))
    }

    pub fn gen_keys_bytes() -> Result<([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut sk_bytes = [0u8; SECRET_KEY_SIZE];

        rng.fill_bytes(&mut sk_bytes);

        let secret_key =
            K256SecretKey::from_slice(&sk_bytes).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok((pub_key, secret_key))
    }

    pub fn gen_solana() -> Result<Self> {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut sk_bytes = [0u8; SECRET_KEY_SIZE];
        rng.fill_bytes(&mut sk_bytes);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let pk: [u8; ED25519_PUB_KEY_SIZE] = signing_key.verifying_key().to_bytes();
        Ok(Self::Ed25519Solana((pk, sk_bytes)))
    }

    pub fn from_secret_key(sk: SecretKey) -> Result<Self> {
        match sk {
            SecretKey::Ed25519Solana(sk_bytes) => {
                let signing_key = SigningKey::from_bytes(&sk_bytes);
                let pk: [u8; ED25519_PUB_KEY_SIZE] = signing_key.verifying_key().to_bytes();
                Ok(KeyPair::Ed25519Solana((pk, sk_bytes)))
            }
            SecretKey::Secp256k1Keccak256Ethereum(sk) => {
                let (pub_key, _) = Self::from_sk_bytes(sk)?;
                Ok(KeyPair::Secp256k1Keccak256((pub_key, sk)))
            }
            SecretKey::Secp256k1Sha256Zilliqa(sk) => {
                let (pub_key, _) = Self::from_sk_bytes(sk)?;
                Ok(KeyPair::Secp256k1Sha256((pub_key, sk)))
            }
            SecretKey::Secp256k1Bitcoin((sk, network, addr_type)) => {
                let (pub_key, _) = Self::from_sk_bytes(sk)?;
                Ok(KeyPair::Secp256k1Bitcoin((pub_key, sk, network, addr_type)))
            }
            SecretKey::Secp256k1Tron(sk) => {
                let (pub_key, _) = Self::from_sk_bytes(sk)?;
                Ok(KeyPair::Secp256k1Tron((pub_key, sk)))
            }
        }
    }

    pub fn from_bip39_seed(seed: &[u8; BIP39_SEED_SIZE], bip49: &DerivationPath) -> Result<Self> {
        let path = bip49.get_path();

        if bip49.slip44 == slip44::SOLANA {
            let signing_key = derive_ed25519_key(seed, &path)
                .map_err(KeyPairError::ExtendedPrivKeyDeriveError)?;
            let sk: [u8; SECRET_KEY_SIZE] = signing_key.to_bytes();
            let pk: [u8; ED25519_PUB_KEY_SIZE] = signing_key.verifying_key().to_bytes();
            return Ok(Self::Ed25519Solana((pk, sk)));
        }

        let secret_key =
            derive_private_key(seed, &path).map_err(KeyPairError::ExtendedPrivKeyDeriveError)?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        match bip49.slip44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                Ok(Self::Secp256k1Keccak256((pub_key, secret_key)))
            }
            slip44::BITCOIN => {
                let network = bip49
                    .network
                    .ok_or(KeyPairError::ExtendedPrivKeyDeriveError(
                        Bip329Errors::MissingBitcoinNetwork,
                    ))?;
                let addr_type = bip49.get_address_type();
                Ok(Self::Secp256k1Bitcoin((
                    pub_key, secret_key, network, addr_type,
                )))
            }
            slip44::TRON => Ok(Self::Secp256k1Tron((pub_key, secret_key))),
            _ => Err(KeyPairError::ExtendedPrivKeyDeriveError(
                Bip329Errors::InvalidSlip44(bip49.slip44),
            )),
        }
    }

    pub fn get_addr(&self) -> Result<Address> {
        let pk = self.get_pubkey()?;
        let addr = Address::from_pubkey(&pk).map_err(KeyPairError::AddressParseError)?;

        Ok(addr)
    }

    pub fn get_secretkey(&self) -> Result<SecretKey> {
        match self {
            KeyPair::Secp256k1Sha256((_, sk)) => Ok(SecretKey::Secp256k1Sha256Zilliqa(*sk)),
            KeyPair::Secp256k1Keccak256((_, sk)) => Ok(SecretKey::Secp256k1Keccak256Ethereum(*sk)),
            KeyPair::Secp256k1Bitcoin((_, sk, network, addr_type)) => {
                Ok(SecretKey::Secp256k1Bitcoin((*sk, *network, *addr_type)))
            }
            KeyPair::Secp256k1Tron((_, sk)) => Ok(SecretKey::Secp256k1Tron(*sk)),
            KeyPair::Ed25519Solana((_, sk)) => Ok(SecretKey::Ed25519Solana(*sk)),
        }
    }

    pub fn get_pubkey(&self) -> Result<PubKey> {
        match self {
            KeyPair::Secp256k1Sha256((pk, _)) => Ok(PubKey::Secp256k1Sha256(*pk)),
            KeyPair::Secp256k1Keccak256((pk, _)) => Ok(PubKey::Secp256k1Keccak256(*pk)),
            KeyPair::Secp256k1Bitcoin((pk, _, network, addr_type)) => {
                Ok(PubKey::Secp256k1Bitcoin((*pk, *network, *addr_type)))
            }
            KeyPair::Secp256k1Tron((pk, _)) => Ok(PubKey::Secp256k1Tron(*pk)),
            KeyPair::Ed25519Solana((pk, _)) => Ok(PubKey::Ed25519Solana(Pubkey::from(*pk))),
        }
    }

    pub fn get_pubkey_bytes(&self) -> &[u8] {
        match self {
            KeyPair::Secp256k1Sha256((pk, _)) => pk,
            KeyPair::Secp256k1Keccak256((pk, _)) => pk,
            KeyPair::Secp256k1Bitcoin((pk, _, _, _)) => pk,
            KeyPair::Secp256k1Tron((pk, _)) => pk,
            KeyPair::Ed25519Solana((pk, _)) => pk,
        }
    }

    pub fn get_sk_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        match self {
            KeyPair::Secp256k1Sha256((_, sk)) => *sk,
            KeyPair::Secp256k1Keccak256((_, sk)) => *sk,
            KeyPair::Secp256k1Bitcoin((_, sk, _, _)) => *sk,
            KeyPair::Secp256k1Tron((_, sk)) => *sk,
            KeyPair::Ed25519Solana((_, sk)) => *sk,
        }
    }

    pub fn get_local_eth_siger(&self) -> Result<PrivateKeySigner> {
        let bytes = self.get_sk_bytes();
        PrivateKeySigner::from_slice(&bytes)
            .map_err(|e| KeyPairError::EthersInvalidSecretKey(e.to_string()))
    }

    pub fn get_local_eth_wallet(&self) -> Result<EthereumWallet> {
        let signer: PrivateKeySigner = self.get_local_eth_siger()?;
        let wallet = EthereumWallet::from(signer);
        Ok(wallet)
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        match self {
            KeyPair::Secp256k1Keccak256((_, _sk)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_message_sync(msg)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Sha256((_, sk)) => {
                let secret_key =
                    K256SecretKey::from_slice(sk).or(Err(KeyPairError::InvalidSecretKey))?;
                let sig: Signature = schnorr::sign(msg, &secret_key)
                    .map_err(KeyPairError::SchorrError)?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Bitcoin((_, _sk, _, _)) | KeyPair::Secp256k1Tron((_, _sk)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_message_sync(msg)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Ed25519Solana((_, sk)) => {
                let signing_key = SigningKey::from_bytes(sk);
                let sig_bytes: [u8; 64] = signing_key.sign(msg).to_bytes();
                Ok(Signature::Ed25519Solana(sig_bytes))
            }
        }
    }

    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<Signature> {
        match self {
            KeyPair::Secp256k1Keccak256((_, _)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_hash_sync(&alloy::primitives::B256::from_slice(hash))
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;
                Ok(sig)
            }
            KeyPair::Secp256k1Sha256((_, _)) => Err(KeyPairError::InvalidSecp256k1Sha256),
            KeyPair::Secp256k1Bitcoin((_, _, _, _)) => Err(KeyPairError::InvalidSecp256k1Bitcoin),
            KeyPair::Secp256k1Tron((_, _)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_hash_sync(&alloy::primitives::B256::from_slice(hash))
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;
                Ok(sig)
            }
            KeyPair::Ed25519Solana((_, _)) => Err(KeyPairError::InvalidEd25519Solana),
        }
    }

    pub async fn sign_typed_data_eip712(&self, data: TypedData) -> Result<Signature> {
        match self {
            KeyPair::Secp256k1Keccak256((_, _)) => {
                let signer = self.get_local_eth_siger()?;
                let signing_hash = data
                    .eip712_signing_hash()
                    .map_err(|e| KeyPairError::Eip712Error(e.to_string()))?;
                let signature = signer
                    .sign_hash(&signing_hash)
                    .await
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let sig = signature
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Sha256((_, _)) => Err(KeyPairError::InvalidSecp256k1Sha256),
            KeyPair::Secp256k1Bitcoin((_, _, _, _)) => Err(KeyPairError::InvalidSecp256k1Bitcoin),
            KeyPair::Secp256k1Tron((_, _)) => Err(KeyPairError::InvalidSecp256k1Tron),
            KeyPair::Ed25519Solana((_, _)) => Err(KeyPairError::InvalidEd25519Solana),
        }
    }

    pub fn verify_sig(&self, msg_bytes: &[u8], sig: &Signature) -> Result<bool> {
        let pk = self.get_pubkey()?;
        let is_verify = sig
            .verify(msg_bytes, &pk)
            .map_err(KeyPairError::InvalidSignature)?;

        Ok(is_verify)
    }

    pub fn verify_hash(&self, hash: &[u8; 32], sig: &Signature) -> Result<bool> {
        let pk = self.get_pubkey()?;
        let is_verify = sig
            .verify_hash(hash, &pk)
            .map_err(KeyPairError::InvalidSignature)?;

        Ok(is_verify)
    }

    pub async fn sign_tx(&self, tx: TransactionRequest) -> Result<TransactionReceipt> {
        tx.sign(self)
            .await
            .map_err(|e| KeyPairError::TransactionErrors(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            KeyPair::Secp256k1Sha256((pk, sk)) => {
                let mut result = vec![0u8];
                result.extend_from_slice(pk);
                result.extend_from_slice(sk);
                Ok(result)
            }
            KeyPair::Secp256k1Keccak256((pk, sk)) => {
                let mut result = vec![1u8];
                result.extend_from_slice(pk);
                result.extend_from_slice(sk);
                Ok(result)
            }
            KeyPair::Secp256k1Bitcoin((pk, sk, network, addr_type)) => {
                let mut result = vec![2u8];
                result.push(network.to_byte());
                result.push(addr_type.to_byte());
                result.extend_from_slice(pk);
                result.extend_from_slice(sk);
                Ok(result)
            }
            KeyPair::Secp256k1Tron((pk, sk)) => {
                let mut result = vec![3u8];
                result.extend_from_slice(pk);
                result.extend_from_slice(sk);
                Ok(result)
            }
            KeyPair::Ed25519Solana((pk, sk)) => {
                let mut result = vec![5u8];
                result.extend_from_slice(pk);
                result.extend_from_slice(sk);
                Ok(result)
            }
        }
    }

    pub fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(KeyPairError::InvalidLength);
        }

        let key_type = bytes[0];

        match key_type {
            0 | 1 | 3 => {
                if bytes.len() != KEYPAIR_BYTES_SIZE {
                    return Err(KeyPairError::InvalidLength);
                }
                let pk: [u8; PUB_KEY_SIZE] = bytes[1..PUB_KEY_SIZE + 1]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidPublicKey)?;
                let sk: [u8; SECRET_KEY_SIZE] = bytes[PUB_KEY_SIZE + 1..]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidSecretKey)?;

                match key_type {
                    0 => Ok(KeyPair::Secp256k1Sha256((pk, sk))),
                    1 => Ok(KeyPair::Secp256k1Keccak256((pk, sk))),
                    3 => Ok(KeyPair::Secp256k1Tron((pk, sk))),
                    _ => unreachable!(),
                }
            }
            5 => {
                if bytes.len() != ED25519_PUB_KEY_SIZE + SECRET_KEY_SIZE + 1 {
                    return Err(KeyPairError::InvalidLength);
                }
                let pk: [u8; ED25519_PUB_KEY_SIZE] = bytes[1..ED25519_PUB_KEY_SIZE + 1]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidPublicKey)?;
                let sk: [u8; SECRET_KEY_SIZE] = bytes[ED25519_PUB_KEY_SIZE + 1..]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidSecretKey)?;
                Ok(KeyPair::Ed25519Solana((pk, sk)))
            }
            2 => {
                if bytes.len() != PUB_KEY_SIZE + SECRET_KEY_SIZE + 3 {
                    return Err(KeyPairError::InvalidLength);
                }
                let network = bitcoin::Network::from_byte(bytes[1])
                    .map_err(|_| KeyPairError::InvalidKeyType)?;
                let addr_type = bitcoin::AddressType::from_byte(bytes[2])
                    .map_err(|_| KeyPairError::InvalidKeyType)?;
                let pk: [u8; PUB_KEY_SIZE] = bytes[3..PUB_KEY_SIZE + 3]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidPublicKey)?;
                let sk: [u8; SECRET_KEY_SIZE] = bytes[PUB_KEY_SIZE + 3..]
                    .try_into()
                    .map_err(|_| KeyPairError::InvalidSecretKey)?;

                Ok(KeyPair::Secp256k1Bitcoin((pk, sk, network, addr_type)))
            }
            _ => Err(KeyPairError::InvalidKeyType),
        }
    }
}

#[cfg(test)]
mod tests_keypair {
    use super::*;
    use config::bip39::EN_WORDS;
    use pqbip39::mnemonic::Mnemonic;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;
    use std::borrow::Cow;

    fn create_test_keypair(key_type: u8) -> KeyPair {
        let pk = [1u8; PUB_KEY_SIZE];
        let sk = [2u8; SECRET_KEY_SIZE];
        match key_type {
            0 => KeyPair::Secp256k1Sha256((pk, sk)),
            1 => KeyPair::Secp256k1Keccak256((pk, sk)),
            _ => panic!("Invalid key type for test"),
        }
    }

    #[test]
    fn test_to_bytes_secp256k1_sha256() {
        let keypair = create_test_keypair(0);
        let bytes = keypair.to_bytes().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..PUB_KEY_SIZE + 1], &[1u8; PUB_KEY_SIZE]);
        assert_eq!(&bytes[PUB_KEY_SIZE + 1..], &[2u8; SECRET_KEY_SIZE]);
    }

    #[test]
    fn test_to_bytes_secp256k1_keccak256() {
        let keypair = create_test_keypair(1);
        let bytes = keypair.to_bytes().unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..PUB_KEY_SIZE + 1], &[1u8; PUB_KEY_SIZE]);
        assert_eq!(&bytes[PUB_KEY_SIZE + 1..], &[2u8; SECRET_KEY_SIZE]);
    }

    #[test]
    fn test_from_bytes_secp256k1_sha256() {
        let original = create_test_keypair(0);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_secp256k1_keccak256() {
        let original = create_test_keypair(1);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = vec![0u8; KEYPAIR_BYTES_SIZE - 1];
        let result = KeyPair::from_bytes(Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(KeyPairError::InvalidLength)));
    }

    #[test]
    fn test_from_bytes_invalid_key_type() {
        let mut bytes = vec![0u8; KEYPAIR_BYTES_SIZE];
        bytes[0] = 99;
        let result = KeyPair::from_bytes(Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(KeyPairError::InvalidKeyType)));
    }

    #[test]
    fn test_sign_message() {
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_entropy();

        for _ in 0..10 {
            let key_pair = KeyPair::gen_sha256().unwrap();
            let mut message_bytes = [0u8; 100];

            rng.fill_bytes(&mut message_bytes);

            let signature = key_pair.sign_message(&message_bytes).unwrap();
            let verify = key_pair.verify_sig(&message_bytes, &signature);

            assert!(verify.is_ok());
            assert!(verify.unwrap());
        }

        for _ in 0..10 {
            let key_pair = KeyPair::gen_keccak256().unwrap();
            let mut message_bytes = [0u8; 100];

            rng.fill_bytes(&mut message_bytes);
            let signature = key_pair.sign_message(&message_bytes).unwrap();
            let verify = key_pair.verify_sig(&message_bytes, &signature);

            assert!(verify.is_ok());
            assert!(verify.unwrap());
        }
    }

    #[test]
    fn from_to_bytes() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let bytes = key_pair.to_bytes().unwrap();
        let restored_key_pair = KeyPair::from_bytes(bytes[..].into()).unwrap();

        assert_eq!(restored_key_pair, key_pair);
    }

    #[test]
    fn test_bip39_derivation_bitcoin() {
        use test_data::ANVIL_MNEMONIC;

        let m = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = m.to_seed(&SecretString::from("")).unwrap();

        let btc_bip84_path = DerivationPath::new(
            slip44::BITCOIN,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP84_PURPOSE,
            Some(bitcoin::Network::Bitcoin),
        );
        let btc_key_pair = KeyPair::from_bip39_seed(seed.expose_secret(), &btc_bip84_path).unwrap();
        let btc_addr = btc_key_pair.get_addr().unwrap();

        assert!(matches!(btc_key_pair, KeyPair::Secp256k1Bitcoin(_)));
        assert!(matches!(btc_addr, Address::Secp256k1Bitcoin(_)));

        let btc_addr_str = btc_addr.auto_format();
        assert!(btc_addr_str.starts_with("bc1"));

        let btc_bip44_path = DerivationPath::new(
            slip44::BITCOIN,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
            Some(bitcoin::Network::Bitcoin),
        );
        let btc_legacy_key_pair = KeyPair::from_bip39_seed(seed.expose_secret(), &btc_bip44_path).unwrap();
        let btc_legacy_addr = btc_legacy_key_pair.get_addr().unwrap();
        let btc_legacy_addr_str = btc_legacy_addr.auto_format();
        assert!(btc_legacy_addr_str.starts_with("1"));
    }

    #[test]
    fn test_bip39_derivation() {
        use test_data::ANVIL_MNEMONIC;

        let m = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = m.to_seed(&SecretString::from("")).unwrap();

        assert_eq!(
            [
                157, 252, 60, 100, 194, 248, 190, 222, 21, 51, 182, 167, 159, 133, 112, 229, 148,
                62, 11, 143, 209, 207, 119, 16, 122, 223, 123, 114, 206, 244, 33, 133, 213, 100,
                163, 174, 226, 76, 171, 67, 248, 14, 60, 69, 56, 8, 125, 112, 252, 130, 78, 171,
                186, 213, 150, 162, 60, 151, 182, 238, 131, 34, 204, 192,
            ],
            *seed.expose_secret()
        );

        let zil_path = DerivationPath::new(slip44::ZILLIQA, crypto::bip49::DerivationType::AddressIndex(0, 0, 0), DerivationPath::BIP44_PURPOSE, None);
        let eth_path =
            DerivationPath::new(slip44::ETHEREUM, crypto::bip49::DerivationType::AddressIndex(0, 0, 0), DerivationPath::BIP44_PURPOSE, None);

        let zil_key_pair = KeyPair::from_bip39_seed(seed.expose_secret(), &zil_path).unwrap();
        let eth_key_pair = KeyPair::from_bip39_seed(seed.expose_secret(), &eth_path).unwrap();

        let addr_eth = eth_key_pair.get_addr().unwrap();
        let addr_zil = zil_key_pair.get_addr().unwrap();

        assert_eq!(
            addr_eth.to_string(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            addr_zil.to_string(),
            "0xBE9390B088c7651Af28751CEb84e233Be3B8162D"
        );

        assert_ne!(
            zil_key_pair.get_pubkey().unwrap(),
            eth_key_pair.get_pubkey().unwrap()
        );
        assert_ne!(
            zil_key_pair.get_secretkey().unwrap(),
            eth_key_pair.get_secretkey().unwrap()
        );

        assert_eq!(
            zil_key_pair.get_secretkey().unwrap().to_string(),
            "01846513a18ccac9459cc9fd8567b3d763f0715bd84c9e9a6d1b08dd14d0f329ef"
        );
        assert_eq!(
            eth_key_pair.get_secretkey().unwrap().to_string(),
            "01ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
        assert_eq!(
            eth_key_pair.get_pubkey().unwrap().to_string(),
            "01038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"
        );
        assert_eq!(
            zil_key_pair.get_pubkey().unwrap().to_string(),
            "0102d8855750cd4a1b807e1f88069781d8197b7743b51c00e57e72f66258fa6c2333"
        );
    }

    #[test]
    fn test_derivation_path_generation() {
        let eth_path =
            DerivationPath::new(slip44::ETHEREUM, crypto::bip49::DerivationType::AddressIndex(0, 0, 0), DerivationPath::BIP44_PURPOSE, None);
        let zil_path = DerivationPath::new(slip44::ZILLIQA, crypto::bip49::DerivationType::AddressIndex(0, 0, 1), DerivationPath::BIP44_PURPOSE, None);

        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/0");
        assert_eq!(zil_path.get_path(), "m/44'/313'/0'/0/1");

        assert_eq!(eth_path.get_index(), 0);
        assert_eq!(zil_path.get_index(), 1);
    }

    #[tokio::test]
    async fn test_sign_typed_data_eip712_success() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let address = key_pair.get_pubkey().unwrap().get_addr().unwrap();
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ]
            },
            "primaryType": "Person",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "name": "Bob",
                "wallet": address.to_eth_checksummed().unwrap()
            }
        });
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string()).unwrap();
        let signature = key_pair.sign_typed_data_eip712(typed_data).await;
        assert!(signature.is_ok());
    }

    #[tokio::test]
    async fn test_sign_typed_data_eip712_invalid_type() {
        let key_pair = KeyPair::gen_sha256().unwrap();
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ]
            },
            "primaryType": "Person",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            }
        });
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string()).unwrap();
        let result = key_pair.sign_typed_data_eip712(typed_data).await;
        assert!(matches!(result, Err(KeyPairError::InvalidSecp256k1Sha256)));
    }

    #[tokio::test]
    async fn test_sign_typed_data_eip712_bitcoin_not_supported() {
        let key_pair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ]
            },
            "primaryType": "Person",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            }
        });
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string()).unwrap();
        let result = key_pair.sign_typed_data_eip712(typed_data).await;
        assert!(matches!(result, Err(KeyPairError::InvalidSecp256k1Bitcoin)));
    }

    #[test]
    fn test_gen_bitcoin_keypair() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Bitcoin(_)));

        let pubkey = keypair.get_pubkey().unwrap();
        assert!(matches!(pubkey, PubKey::Secp256k1Bitcoin(_)));

        let secret_key = keypair.get_secretkey().unwrap();
        assert!(matches!(secret_key, SecretKey::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_keypair_get_addr() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let addr = keypair.get_addr().unwrap();

        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_keypair_to_bytes() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let bytes = keypair.to_bytes().unwrap();

        assert_eq!(bytes[0], 2);
        assert_eq!(bytes.len(), PUB_KEY_SIZE + SECRET_KEY_SIZE + 3);
    }

    #[test]
    fn test_bitcoin_keypair_from_bytes() {
        let original =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bitcoin_keypair_sign_message() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let message = b"Hello Bitcoin!";

        let signature = keypair.sign_message(message);
        assert!(signature.is_ok());
    }

    #[test]
    fn test_bitcoin_keypair_conversion() {
        let keypair_zil = KeyPair::gen_sha256().unwrap();
        let keypair_btc =
            keypair_zil.to_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh);

        assert!(matches!(keypair_btc, KeyPair::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_from_secret_key() {
        let sk = SecretKey::Secp256k1Bitcoin((
            [42u8; SECRET_KEY_SIZE],
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));
        let result = KeyPair::from_secret_key(sk);

        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_address_generation() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let address = keypair.get_addr().unwrap();

        let btc_addr = address.auto_format();
        assert!(btc_addr.starts_with("bc1"));
    }

    #[test]
    fn test_bitcoin_known_key_address_derivation() {
        let public_key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
        let pubkey = PubKey::Secp256k1Bitcoin((
            pk_array,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2pkh,
        ));

        let address = Address::from_pubkey(&pubkey).unwrap();

        let btc_address = address.auto_format();
        assert_eq!(btc_address, expected_address);
    }

    #[test]
    fn test_bitcoin_derived_addresses_from_csv() {
        let test_cases = vec![
            (
                "024447e68ff4efc6dccac32b60c9af9421654763a93d9573d7284567b70f7993ef",
                "183jY8BqANQctEHNB7z3KfCxbBKav6C2Xb",
            ),
            (
                "0344d7472c77f5400f2671c9e6fc1a167c9fa98d2d0c98c5253dd8a11771b232d4",
                "14WTRqxezCyjJ8bGLMey8FAUeucQyBGvqj",
            ),
            (
                "03ef8ac6029411ae46a2cdb4d15a87a318f3bd68b91aa9d08869bc778b9e8e19cf",
                "1wi5gLfdxVbfmCHrYe9YeV5VrZQiUAuB2",
            ),
            (
                "02edbcf32cbdf36bf161cbf4aa10e5b6704320e6bcd8abdaf4a301adb1acd65150",
                "14X5Y28wnQkYNcHekFjixbVkZjXpScvwvc",
            ),
            (
                "0371f0511f34bd3875bdf0565eb73940fea335caf991fcf09c9a09d5074eaa21c2",
                "1EJpWTHGfoX3azrA5Z8VCBmwp5J8YQ3SA9",
            ),
        ];

        for (pubkey_hex, expected_addr) in test_cases {
            let pk_bytes = hex::decode(pubkey_hex).unwrap();
            let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
            let pubkey = PubKey::Secp256k1Bitcoin((
                pk_array,
                bitcoin::Network::Bitcoin,
                bitcoin::AddressType::P2pkh,
            ));

            let address = Address::from_pubkey(&pubkey).unwrap();
            let btc_address = address.auto_format();

            assert_eq!(
                btc_address, expected_addr,
                "Failed for pubkey: {}",
                pubkey_hex
            );
        }
    }

    #[test]
    fn test_bitcoin_wif_private_key_decode() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let expected_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

        let decoded = bs58::decode(wif).into_vec().unwrap();

        assert_eq!(decoded[0], 0x80);
        assert_eq!(decoded.len(), 38);

        let private_key_bytes: [u8; SECRET_KEY_SIZE] = decoded[1..33].try_into().unwrap();

        let (pk, sk) = KeyPair::from_sk_bytes(private_key_bytes).unwrap();
        let keypair_btc = KeyPair::Secp256k1Bitcoin((
            pk,
            sk,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2pkh,
        ));

        let pubkey = keypair_btc.get_pubkey().unwrap();
        let pubkey_hex = hex::encode(pubkey.as_bytes());
        assert_eq!(pubkey_hex, expected_pubkey);

        let address = keypair_btc.get_addr().unwrap();
        let btc_address = address.auto_format();
        assert_eq!(btc_address, expected_address);
    }

    #[test]
    fn test_bitcoin_multiple_wif_keys() {
        let test_cases = vec![
            (
                "L1NQXBsdws444VbdxGqztar6nf1GcmZNXZWDYetAUJ9NE47SRWxN",
                "024447e68ff4efc6dccac32b60c9af9421654763a93d9573d7284567b70f7993ef",
                "183jY8BqANQctEHNB7z3KfCxbBKav6C2Xb",
            ),
            (
                "L4PvnB6kR8bmrMvUS86RESUeDFWGNB5UmH6663yJCGgrhEgJdyq3",
                "0344d7472c77f5400f2671c9e6fc1a167c9fa98d2d0c98c5253dd8a11771b232d4",
                "14WTRqxezCyjJ8bGLMey8FAUeucQyBGvqj",
            ),
            (
                "L2NZxVEQmDc4fDrLvX7NDsCMSTugKZxZ6vrX61UJvZLkWgXrACoe",
                "03ef8ac6029411ae46a2cdb4d15a87a318f3bd68b91aa9d08869bc778b9e8e19cf",
                "1wi5gLfdxVbfmCHrYe9YeV5VrZQiUAuB2",
            ),
        ];

        for (wif, expected_pubkey, expected_address) in test_cases {
            let decoded = bs58::decode(wif).into_vec().unwrap();
            let private_key_bytes: [u8; SECRET_KEY_SIZE] = decoded[1..33].try_into().unwrap();

            let (pk, sk) = KeyPair::from_sk_bytes(private_key_bytes).unwrap();
            let keypair_btc = KeyPair::Secp256k1Bitcoin((
                pk,
                sk,
                bitcoin::Network::Bitcoin,
                bitcoin::AddressType::P2pkh,
            ));

            let pubkey = keypair_btc.get_pubkey().unwrap();
            let pubkey_hex = hex::encode(pubkey.as_bytes());
            assert_eq!(pubkey_hex, expected_pubkey, "Failed for WIF: {}", wif);

            let address = keypair_btc.get_addr().unwrap();
            let btc_address = address.auto_format();
            assert_eq!(btc_address, expected_address, "Failed for WIF: {}", wif);
        }
    }

    #[test]
    fn test_bitcoin_keypair_roundtrip_all_networks() {
        let networks = vec![
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Testnet4,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];

        for network in networks {
            let original = KeyPair::gen_bitcoin(network, bitcoin::AddressType::P2wpkh).unwrap();
            let bytes = original.to_bytes().unwrap();
            let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn test_bitcoin_keypair_roundtrip_all_address_types() {
        let addr_types = vec![
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2sh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2wsh,
            bitcoin::AddressType::P2tr,
            bitcoin::AddressType::P2a,
        ];

        for addr_type in addr_types {
            let original = KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, addr_type).unwrap();
            let bytes = original.to_bytes().unwrap();
            let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn test_bitcoin_keypair_roundtrip_combinations() {
        let test_cases = vec![
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2tr),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Signet, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Regtest, bitcoin::AddressType::P2pkh),
        ];

        for (network, addr_type) in test_cases {
            let original = KeyPair::gen_bitcoin(network, addr_type).unwrap();
            let bytes = original.to_bytes().unwrap();
            let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn test_bitcoin_keypair_to_bytes_structure() {
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();
        let bytes = keypair.to_bytes().unwrap();

        assert_eq!(bytes[0], 2); // Bitcoin variant
        assert_eq!(bytes[1], bitcoin::Network::Bitcoin.to_byte());
        assert_eq!(bytes[2], bitcoin::AddressType::P2wpkh.to_byte());
        assert_eq!(bytes.len(), PUB_KEY_SIZE + SECRET_KEY_SIZE + 3);
    }

    #[test]
    fn test_bitcoin_keypair_conversion_roundtrip() {
        let zil_keypair = KeyPair::gen_sha256().unwrap();
        let btc_keypair =
            zil_keypair.to_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh);

        let bytes = btc_keypair.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(btc_keypair, recovered);
    }

    #[test]
    fn test_all_keypair_types_roundtrip() {
        let zil = KeyPair::gen_sha256().unwrap();
        let eth = KeyPair::gen_keccak256().unwrap();
        let btc =
            KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh).unwrap();

        for keypair in [zil, eth, btc] {
            let bytes = keypair.to_bytes().unwrap();
            let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
            assert_eq!(keypair, recovered);
        }
    }

    #[test]
    fn test_bitcoin_keypair_network_preservation() {
        let networks = vec![
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Regtest,
        ];

        for network in networks {
            let keypair = KeyPair::gen_bitcoin(network, bitcoin::AddressType::P2wpkh).unwrap();

            if let KeyPair::Secp256k1Bitcoin((_, _, recovered_network, _)) = keypair {
                assert_eq!(recovered_network, network);
            } else {
                panic!("Expected Bitcoin keypair");
            }
        }
    }

    #[test]
    fn test_bitcoin_keypair_address_type_preservation() {
        let addr_types = vec![
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2tr,
        ];

        for addr_type in addr_types {
            let keypair = KeyPair::gen_bitcoin(bitcoin::Network::Bitcoin, addr_type).unwrap();

            if let KeyPair::Secp256k1Bitcoin((_, _, _, recovered_addr_type)) = keypair {
                assert_eq!(recovered_addr_type, addr_type);
            } else {
                panic!("Expected Bitcoin keypair");
            }
        }
    }

    #[test]
    fn test_gen_tron_keypair() {
        let keypair = KeyPair::gen_tron().unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Tron(_)));

        let pubkey = keypair.get_pubkey().unwrap();
        assert!(matches!(pubkey, PubKey::Secp256k1Tron(_)));

        let secret_key = keypair.get_secretkey().unwrap();
        assert!(matches!(secret_key, SecretKey::Secp256k1Tron(_)));
    }

    #[test]
    fn test_tron_keypair_get_addr() {
        let keypair = KeyPair::gen_tron().unwrap();
        let addr = keypair.get_addr().unwrap();

        assert!(matches!(addr, Address::Secp256k1Tron(_)));

        let tron_addr_str = addr.auto_format();
        assert!(tron_addr_str.starts_with('T'));
        assert_eq!(tron_addr_str.len(), 34);
    }

    #[test]
    fn test_tron_keypair_to_bytes() {
        let keypair = KeyPair::gen_tron().unwrap();
        let bytes = keypair.to_bytes().unwrap();

        assert_eq!(bytes[0], 3);
        assert_eq!(bytes.len(), PUB_KEY_SIZE + SECRET_KEY_SIZE + 1);
    }

    #[test]
    fn test_tron_keypair_from_bytes() {
        let original = KeyPair::gen_tron().unwrap();
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_tron_keypair_sign_message() {
        let keypair = KeyPair::gen_tron().unwrap();
        let message = b"Hello Tron!";

        let signature = keypair.sign_message(message);
        assert!(signature.is_ok());

        let sig = signature.unwrap();
        let verify = keypair.verify_sig(message, &sig);
        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }

    #[test]
    fn test_tron_keypair_conversion() {
        let keypair_zil = KeyPair::gen_sha256().unwrap();
        let keypair_tron = keypair_zil.to_tron();

        assert!(matches!(keypair_tron, KeyPair::Secp256k1Tron(_)));

        let keypair_eth = KeyPair::gen_keccak256().unwrap();
        let keypair_tron_from_eth = keypair_eth.to_tron();

        assert!(matches!(keypair_tron_from_eth, KeyPair::Secp256k1Tron(_)));
    }

    #[test]
    fn test_tron_from_secret_key() {
        let sk = SecretKey::Secp256k1Tron([42u8; SECRET_KEY_SIZE]);
        let result = KeyPair::from_secret_key(sk);

        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Tron(_)));
    }

    #[test]
    fn test_tron_bip39_derivation() {
        use test_data::ANVIL_MNEMONIC;

        let m = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = m.to_seed(&SecretString::from("")).unwrap();

        let tron_path = DerivationPath::new(slip44::TRON, crypto::bip49::DerivationType::AddressIndex(0, 0, 0), DerivationPath::BIP44_PURPOSE, None);
        let tron_key_pair = KeyPair::from_bip39_seed(seed.expose_secret(), &tron_path).unwrap();
        let tron_addr = tron_key_pair.get_addr().unwrap();

        assert!(matches!(tron_key_pair, KeyPair::Secp256k1Tron(_)));
        assert!(matches!(tron_addr, Address::Secp256k1Tron(_)));

        let tron_addr_str = tron_addr.auto_format();
        assert!(tron_addr_str.starts_with('T'));
        assert_eq!(tron_addr_str.len(), 34);
    }

    #[test]
    fn test_tron_derivation_path() {
        let tron_path = DerivationPath::new(slip44::TRON, crypto::bip49::DerivationType::AddressIndex(0, 0, 0), DerivationPath::BIP44_PURPOSE, None);

        assert_eq!(tron_path.get_path(), "m/44'/195'/0'/0/0");
    }

    #[test]
    fn test_tron_keypair_roundtrip() {
        let keypair = KeyPair::gen_tron().unwrap();
        let bytes = keypair.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(keypair, recovered);

        let addr_original = keypair.get_addr().unwrap();
        let addr_recovered = recovered.get_addr().unwrap();
        assert_eq!(addr_original, addr_recovered);
    }

    #[test]
    fn test_tron_keypair_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let message = b"Test message for Tron signing";

        let signature = keypair.sign_message(message).unwrap();
        let is_valid = keypair.verify_sig(message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_tron_multiple_addresses_from_mnemonic() {
        use test_data::ANVIL_MNEMONIC;

        let m = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        let seed = m.to_seed(&SecretString::from("")).unwrap();

        let expected_addresses = test_data::tron_addresses::ALL;

        for (index, expected_addr) in expected_addresses.iter().enumerate() {
            let tron_path =
                DerivationPath::new(slip44::TRON, crypto::bip49::DerivationType::AddressIndex(0, 0, index), DerivationPath::BIP44_PURPOSE, None);
            let keypair = KeyPair::from_bip39_seed(seed.expose_secret(), &tron_path).unwrap();
            let addr = keypair.get_addr().unwrap();
            let derived_addr = addr.auto_format();

            assert_eq!(
                derived_addr, *expected_addr,
                "Address mismatch at index {}: expected {}, got {}",
                index, expected_addr, derived_addr
            );
        }
    }

    #[test]
    fn test_solana_gen_keypair() {
        let keypair = KeyPair::gen_solana().unwrap();
        assert!(matches!(keypair, KeyPair::Ed25519Solana(_)));

        let pubkey = keypair.get_pubkey().unwrap();
        assert!(matches!(pubkey, crate::pubkey::PubKey::Ed25519Solana(_)));

        let addr = keypair.get_addr().unwrap();
        assert!(matches!(addr, crate::address::Address::Ed25519Solana(_)));

        let addr_str = addr.auto_format();
        assert!(!addr_str.is_empty());
    }

    #[test]
    fn test_solana_keypair_from_bip39() {
        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();

        let vectors: &[(crypto::bip49::DerivationType, &str)] = &[
            (crypto::bip49::DerivationType::Root, "9tKf8Q98FsGKJiM4oqMnTxmYH3fU2qJzSwzc76vgzyBT"),
            (crypto::bip49::DerivationType::Account(0), "BtELVjZSaWhMat94P9HyasX3Gvpv6C7WHXJGqWdZbwSQ"),
            (crypto::bip49::DerivationType::Account(1), "M9juqHHtP85PvRKX3d4FS9jkF1WHZwyX3dG7NcYswdH"),
        ];

        for (derivation, expected_addr) in vectors {
            let path = DerivationPath::new(slip44::SOLANA, *derivation, DerivationPath::BIP44_PURPOSE, None);
            let keypair = KeyPair::from_bip39_seed(seed.expose_secret(), &path).unwrap();
            assert!(matches!(keypair, KeyPair::Ed25519Solana(_)));
            let addr = keypair.get_addr().unwrap().auto_format();
            assert_eq!(addr, *expected_addr);
        }
    }

    #[test]
    fn test_solana_keypair_sign_verify() {
        let keypair = KeyPair::gen_solana().unwrap();
        let message = b"hello solana";

        let signature = keypair.sign_message(message).unwrap();
        assert!(matches!(signature, crate::signature::Signature::Ed25519Solana(_)));

        let is_valid = keypair.verify_sig(message, &signature).unwrap();
        assert!(is_valid);

        let wrong_msg = b"wrong message";
        let is_valid_wrong = keypair.verify_sig(wrong_msg, &signature).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_solana_keypair_to_from_bytes() {
        let keypair = KeyPair::gen_solana().unwrap();
        let bytes = keypair.to_bytes().unwrap();

        assert_eq!(bytes[0], 5u8);
        assert_eq!(bytes.len(), ED25519_PUB_KEY_SIZE + SECRET_KEY_SIZE + 1);

        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(keypair, recovered);
        assert_eq!(
            keypair.get_addr().unwrap().auto_format(),
            recovered.get_addr().unwrap().auto_format()
        );
    }

    #[test]
    fn test_solana_from_secret_key() {
        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();

        let path = DerivationPath::new(slip44::SOLANA, crypto::bip49::DerivationType::Account(0), DerivationPath::BIP44_PURPOSE, None);
        let keypair = KeyPair::from_bip39_seed(seed.expose_secret(), &path).unwrap();

        let sk = keypair.get_secretkey().unwrap();
        let keypair2 = KeyPair::from_secret_key(sk).unwrap();

        assert_eq!(keypair.get_pubkey_bytes(), keypair2.get_pubkey_bytes());
        assert_eq!(
            keypair.get_addr().unwrap().auto_format(),
            "BtELVjZSaWhMat94P9HyasX3Gvpv6C7WHXJGqWdZbwSQ"
        );
    }
}
