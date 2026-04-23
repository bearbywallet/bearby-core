use config::sha::SHA256_SIZE;
use ed25519_dalek::SigningKey;
use errors::bip32::Bip329Errors;
use hmac::{Hmac, KeyInit, Mac};
use k256::{
    elliptic_curve::{bigint::U256, scalar::FromUintUnchecked},
    SecretKey,
};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha512;
use std::str::FromStr;

const HARDENED_BIT: u32 = 1 << 31;
const BITCOIN_SEED: &[u8] = b"Bitcoin seed";
const ED25519_SEED: &[u8] = b"ed25519 seed";

type Result<T> = std::result::Result<T, Bip329Errors>;

#[derive(Clone, Debug)]
struct ChildNumber(u32);

impl ChildNumber {
    fn is_hardened(&self) -> bool {
        self.0 & HARDENED_BIT == HARDENED_BIT
    }

    fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl FromStr for ChildNumber {
    type Err = Bip329Errors;

    fn from_str(s: &str) -> Result<Self> {
        let (num_str, hardened) = if let Some(stripped) = s.strip_suffix('\'') {
            (stripped, true)
        } else {
            (s, false)
        };

        let index: u32 = num_str.parse().map_err(|e| {
            Bip329Errors::InvalidChild(format!("Failed to parse child number: {}", e))
        })?;

        if index >= HARDENED_BIT {
            return Err(Bip329Errors::InvalidChild(
                "Child number too large".to_string(),
            ));
        }

        Ok(ChildNumber(if hardened {
            index | HARDENED_BIT
        } else {
            index
        }))
    }
}

type ChainCode = SecretBox<[u8; SHA256_SIZE]>;

fn derive_master_key(seed: &SecretBox<[u8; 64]>) -> Result<(SecretKey, ChainCode)> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(BITCOIN_SEED)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    hmac.update(seed.expose_secret());

    let result = hmac.finalize().into_bytes();
    let (key_bytes, chain_code) = result.split_at(32);

    let mut chain_code_arr = [0u8; SHA256_SIZE];
    chain_code_arr.copy_from_slice(chain_code);

    Ok((
        SecretKey::from_slice(key_bytes).map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?,
        SecretBox::init_with(|| chain_code_arr),
    ))
}

pub fn derive_private_key(seed: &SecretBox<[u8; 64]>, path: &str) -> Result<SecretKey> {
    if !path.starts_with("m/") {
        return Err(Bip329Errors::InvalidPath(
            "Path must start with 'm/'".to_string(),
        ));
    }

    let path_parts: Vec<&str> = path[2..].split('/').collect();
    let (mut key, mut chain_code) = derive_master_key(seed)?;

    for part in path_parts {
        if part.is_empty() {
            continue;
        }

        let child_number = ChildNumber::from_str(part)?;
        let (child_key, child_chain) =
            derive_child_key(&key, chain_code.expose_secret(), &child_number)?;
        key = child_key;
        chain_code = child_chain;
    }

    Ok(key)
}

fn derive_child_key(
    parent_key: &SecretKey,
    chain_code: &[u8; SHA256_SIZE],
    child: &ChildNumber,
) -> Result<(SecretKey, ChainCode)> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    if child.is_hardened() {
        hmac.update(&[0]);
        hmac.update(&parent_key.to_bytes());
    } else {
        hmac.update(&parent_key.public_key().to_sec1_bytes());
    }

    hmac.update(&child.to_bytes());

    let result = hmac.finalize().into_bytes();
    let (child_key, new_chain_code) = result.split_at(32);

    let child_scalar = U256::from_be_slice(child_key);
    let child_sk = k256::Scalar::from_uint_unchecked(child_scalar);

    let key_bytes = parent_key.to_bytes();
    let parent_scalar = U256::from_be_slice(&key_bytes);
    let parent_sk = k256::Scalar::from_uint_unchecked(parent_scalar);

    let sum = child_sk + parent_sk;
    let sum_bytes = sum.to_bytes();

    let mut chain_code_arr = [0u8; 32];
    chain_code_arr.copy_from_slice(new_chain_code);

    Ok((
        SecretKey::from_slice(&sum_bytes).map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?,
        SecretBox::init_with(|| chain_code_arr),
    ))
}

fn derive_ed25519_master_key(seed: &SecretBox<[u8; 64]>) -> Result<(SigningKey, ChainCode)> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(ED25519_SEED)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    hmac.update(seed.expose_secret());

    let result = hmac.finalize().into_bytes();
    let (key_bytes, chain_code) = result.split_at(32);

    let mut chain_code_arr = [0u8; SHA256_SIZE];
    chain_code_arr.copy_from_slice(chain_code);

    let signing_key = SigningKey::from_bytes(
        key_bytes
            .try_into()
            .map_err(|_| Bip329Errors::InvalidKey("Invalid ed25519 key length".to_string()))?,
    );

    Ok((signing_key, SecretBox::init_with(|| chain_code_arr)))
}

fn derive_ed25519_child_key(
    parent_key: &SigningKey,
    chain_code: &[u8; SHA256_SIZE],
    child: &ChildNumber,
) -> Result<(SigningKey, ChainCode)> {
    if !child.is_hardened() {
        return Err(Bip329Errors::InvalidChild(
            "Ed25519 only supports hardened derivation".to_string(),
        ));
    }

    let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    hmac.update(&[0x00]);
    hmac.update(&parent_key.to_bytes());
    hmac.update(&child.to_bytes());

    let result = hmac.finalize().into_bytes();
    let (child_key, new_chain_code) = result.split_at(32);

    let mut chain_code_arr = [0u8; SHA256_SIZE];
    chain_code_arr.copy_from_slice(new_chain_code);

    let signing_key = SigningKey::from_bytes(
        child_key
            .try_into()
            .map_err(|_| Bip329Errors::InvalidKey("Invalid ed25519 key length".to_string()))?,
    );

    Ok((signing_key, SecretBox::init_with(|| chain_code_arr)))
}

pub fn derive_ed25519_key(seed: &SecretBox<[u8; 64]>, path: &str) -> Result<SigningKey> {
    if !path.starts_with("m/") {
        return Err(Bip329Errors::InvalidPath(
            "Path must start with 'm/'".to_string(),
        ));
    }

    let path_parts: Vec<&str> = path[2..].split('/').collect();
    let (mut key, mut chain_code) = derive_ed25519_master_key(seed)?;

    for part in path_parts {
        if part.is_empty() {
            continue;
        }

        let child_number = ChildNumber::from_str(part)?;
        let (child_key, child_chain) =
            derive_ed25519_child_key(&key, chain_code.expose_secret(), &child_number)?;
        key = child_key;
        chain_code = child_chain;
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::bip39::EN_WORDS;
    use crypto::bip49::DerivationPath;
    use pqbip39::mnemonic::Mnemonic;
    use secrecy::{SecretBox, SecretString};

    #[test]
    fn bip39_to_address() {
        use crypto::slip44;

        let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";
        let expected_secret_key = b"\xff\x1e\x68\xeb\x7b\xf2\xf4\x86\x51\xc4\x7e\xf0\x17\x7e\xb8\x15\x85\x73\x22\x25\x7c\x58\x94\xbb\x4c\xfd\x11\x76\xc9\x98\x93\x14";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();

        let derivation_path = DerivationPath::new(
            slip44::ETHEREUM,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        let account = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        assert_eq!(
            expected_secret_key.to_vec(),
            account.to_bytes().to_vec(),
            "Secret key is invalid"
        );
    }

    #[test]
    fn bip39_to_btc_bip44_legacy() {
        use crate::address::Address;
        use crate::keypair::KeyPair;
        use crate::secret_key::SecretKey;
        use crypto::slip44;

        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();

        let derivation_path = DerivationPath::new(
            slip44::BITCOIN,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        let btc_secret_key = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        let sk_bytes = btc_secret_key.to_bytes();
        let keypair = KeyPair::from_secret_key(SecretKey::Secp256k1Bitcoin((
            sk_bytes.into(),
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2pkh,
        )))
        .unwrap();

        let address = keypair.get_addr().unwrap();

        assert!(
            matches!(address, Address::Secp256k1Bitcoin(_)),
            "Address should be Bitcoin type"
        );

        let p2pkh_address = address.auto_format();
        assert!(
            p2pkh_address.starts_with('1'),
            "P2PKH address should start with '1'"
        );

        println!("BIP44 P2PKH Address: {}", p2pkh_address);
        println!("Public Key: {}", hex::encode(keypair.get_pubkey_bytes()));
    }

    #[test]
    fn bip39_to_btc_bip84_native_segwit() {
        use crate::address::Address;
        use crate::keypair::KeyPair;
        use crate::secret_key::SecretKey;
        use crypto::slip44;

        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        let seed = mnemonic.to_seed(&SecretString::from("")).unwrap();

        let derivation_path = DerivationPath::new(
            slip44::BITCOIN,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP84_PURPOSE,
        );
        let btc_secret_key = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        let sk_bytes = btc_secret_key.to_bytes();
        let keypair = KeyPair::from_secret_key(SecretKey::Secp256k1Bitcoin((
            sk_bytes.into(),
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        )))
        .unwrap();

        let address = keypair.get_addr().unwrap();

        assert!(
            matches!(address, Address::Secp256k1Bitcoin(_)),
            "Address should be Bitcoin type"
        );

        let bech32_address = address.auto_format();
        assert!(
            bech32_address.starts_with("bc1"),
            "Bech32 address should start with 'bc1'"
        );

        let expected_bech32 = "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te";

        println!("BIP84 Native SegWit Address: {}", bech32_address);
        println!("Expected: {}", expected_bech32);
        println!("Public Key: {}", hex::encode(keypair.get_pubkey_bytes()));

        assert_eq!(
            bech32_address, expected_bech32,
            "Native SegWit address does not match expected value"
        );
    }

    struct SolanaTestVector {
        path: &'static str,
        address: &'static str,
        pk_hex: &'static str,
        sk_hex: &'static str,
    }

    fn get_solana_test_vectors() -> Vec<SolanaTestVector> {
        vec![
            SolanaTestVector {
                path: "m/44'/501'",
                address: "9tKf8Q98FsGKJiM4oqMnTxmYH3fU2qJzSwzc76vgzyBT",
                pk_hex: "8403366f00cce80bc3ae339d4bc5ec33a7b831c650993f95bf85fb8f62a227f6",
                sk_hex: "4f07a1aa645aea61ccfaa125525698c0542e81e6a3d7ec815f35acfe8adc827e8403366f00cce80bc3ae339d4bc5ec33a7b831c650993f95bf85fb8f62a227f6",
            },
            SolanaTestVector {
                path: "m/44'/501'/0'",
                address: "BtELVjZSaWhMat94P9HyasX3Gvpv6C7WHXJGqWdZbwSQ",
                pk_hex: "a1b491da17beb9b38715352118ff8ab17b1896e828329e6895e905cdedc18f69",
                sk_hex: "8ba10912374d1adbc6db8aae59ea0af7f1e6c8e47349ca958c26b99ee0229af6a1b491da17beb9b38715352118ff8ab17b1896e828329e6895e905cdedc18f69",
            },
            SolanaTestVector {
                path: "m/44'/501'/1'",
                address: "M9juqHHtP85PvRKX3d4FS9jkF1WHZwyX3dG7NcYswdH",
                pk_hex: "05297f941b545092312cff6b50174622b8999daaea824d2afdccfa0dd490e4b0",
                sk_hex: "d8ae076a3ab77c0756e5e99261de3564ff1b03275ac299312dd3c25a164a65b705297f941b545092312cff6b50174622b8999daaea824d2afdccfa0dd490e4b0",
            },
            SolanaTestVector {
                path: "m/44'/501'/2'",
                address: "9gWFETMPDvG69vJZEbC7HvHKV1jiFJPnBjduJ5f7dHxb",
                pk_hex: "80fc36fe7171cefea0db1c71c2667a1fa787a52a9cf37ca386e0034b76302018",
                sk_hex: "b4f2279e31b81f98ec38172c6057b6f85be4e98327f8d621917f788d6e381d1e80fc36fe7171cefea0db1c71c2667a1fa787a52a9cf37ca386e0034b76302018",
            },
            SolanaTestVector {
                path: "m/44'/501'/3'",
                address: "DUuxpc4CH1cWdNHGCieWi5ELq4KZtNG6XtPskqgV5TJH",
                pk_hex: "b972cf4cfad761e510bf7a602c8abb918c5983290b85c4c7c0615d95dd45e4d2",
                sk_hex: "797fdcc65e08ec4091607b1844413843299bbea7b2f30b3c745be2da7f2a01a6b972cf4cfad761e510bf7a602c8abb918c5983290b85c4c7c0615d95dd45e4d2",
            },
            SolanaTestVector {
                path: "m/44'/501'/4'",
                address: "bGmWV1RDMDLgNSg7GQ5xi676n35s1HPZuuceSh8ANFC",
                pk_hex: "08c793643088c3546fb89c25581ffc5fbc93df28a67baba6975cd9120de0dac3",
                sk_hex: "155bdc4226390416e761f7ebe293962cb68df95dbea295871c6d5c5c4bcbfaac08c793643088c3546fb89c25581ffc5fbc93df28a67baba6975cd9120de0dac3",
            },
            SolanaTestVector {
                path: "m/44'/501'/5'",
                address: "24qfTdWF17cw6TbybnXKVPH9cfTjtHF6NTiAF7ksLns2",
                pk_hex: "0fd773f024c3ffff609a6da2771d83d5ec699d3c0b1ca25170bb4d0544dca621",
                sk_hex: "ff5f857d29149aeeb072a700bc0f1725e5332402ef03ab7b7a38171b35c251240fd773f024c3ffff609a6da2771d83d5ec699d3c0b1ca25170bb4d0544dca621",
            },
            SolanaTestVector {
                path: "m/44'/501'/6'",
                address: "9haXfSw2unw7xWf2cBwYubC4pn3kihUs1tsVTJGaZnWc",
                pk_hex: "8142a385ec6bf0a6ba134f3b46d8800f1fe5b6f330b0d4b9c1609169e0d185b9",
                sk_hex: "13e2188c469057e9ca0a2c872cfff549f4946e0847b882ee6cc9498ef37e0a928142a385ec6bf0a6ba134f3b46d8800f1fe5b6f330b0d4b9c1609169e0d185b9",
            },
            SolanaTestVector {
                path: "m/44'/501'/7'",
                address: "BVbaPDWn9DYUJphQAjfsnA7oSetLubTrHpFafjpZncbE",
                pk_hex: "9be83a04fe0ddd36fb7ea1f04e1eba670f96b445ba0198a88e448bb2aafab595",
                sk_hex: "3820f6d87e693d0d5da007e539ec156fd7b2ec9ca0cd603eb79a2b588ee676059be83a04fe0ddd36fb7ea1f04e1eba670f96b445ba0198a88e448bb2aafab595",
            },
            SolanaTestVector {
                path: "m/44'/501'/8'",
                address: "9MzPWbpykVd4ZzBXPtWPTMn1Kcp1En7KgrFJsLwQ9Yf5",
                pk_hex: "7c3e002309bd8d448a4110e54e81a7beb65103183b1350f81923402f968dea2c",
                sk_hex: "c93cbf0e15354cdbc47ecdc054d5d76525221f10dac639dcf0ae62634ac4d5e47c3e002309bd8d448a4110e54e81a7beb65103183b1350f81923402f968dea2c",
            },
            SolanaTestVector {
                path: "m/44'/501'/9'",
                address: "8MQnF7zZcDkT5AqyevDZiaQEWj8zBn4LgUFdnCjzPJ6w",
                pk_hex: "6d3c5017ed5cb868880934809c6a5114d620dd270fe83e4c52508540185c563c",
                sk_hex: "a412f7a412265fa9e26406f313c2a43247e6b0acad9d5b2308a786b570e426526d3c5017ed5cb868880934809c6a5114d620dd270fe83e4c52508540185c563c",
            },
            SolanaTestVector {
                path: "m/44'/501'/0'/0'",
                address: "oeYf6KAJkLYhBuR8CiGc6L4D4Xtfepr85fuDgA9kq96",
                pk_hex: "0bf32b9f0db09672038fea36139b18f98a5f0149ef4ce0332e44b9a77e83c22d",
                sk_hex: "a01c67efb5cb8f62f15907a9fcf124c73d2695c8a9a31f21c05742a31ca1dc720bf32b9f0db09672038fea36139b18f98a5f0149ef4ce0332e44b9a77e83c22d",
            },
            SolanaTestVector {
                path: "m/44'/501'/1'/0'",
                address: "AqynRZwvVqUPRwRJXvm6odUb3t93fDjnWe3p6BeuUFxD",
                pk_hex: "9245441f4a752ea6328c6d8d2d2afcb36d131db998a47ca04d6d5d8587d0b012",
                sk_hex: "3f25626cf245c8dd65a2b91a70e6f4c285182489fda230e2553c3752aa962b619245441f4a752ea6328c6d8d2d2afcb36d131db998a47ca04d6d5d8587d0b012",
            },
            SolanaTestVector {
                path: "m/44'/501'/2'/0'",
                address: "CqMbRgMuEhQi9BUS8xP44Wk5nENm48FqJnfjEi4eNb1k",
                pk_hex: "afd3b86041f0efc7b85ca8452ef84a18e511924c9beaf756afe3ab57df10b32b",
                sk_hex: "8eabe4c79ac3a146c1bc447a64233ea70694669b997b0565039471b2939e8c5eafd3b86041f0efc7b85ca8452ef84a18e511924c9beaf756afe3ab57df10b32b",
            },
            SolanaTestVector {
                path: "m/44'/501'/3'/0'",
                address: "9Tj3srBSxH7RFRCm8uharreY7ZBS49XSfpwCeYa7Xaqp",
                pk_hex: "7db6245f484d12f2d12cfcd00d9c762b71805ac04d82e194e090f2df3339cea3",
                sk_hex: "f55bf85006beb673056861062dd8f8d8ff0bb63dd61d45f86fe438bf6e442abb7db6245f484d12f2d12cfcd00d9c762b71805ac04d82e194e090f2df3339cea3",
            },
            SolanaTestVector {
                path: "m/44'/501'/4'/0'",
                address: "6gYw7q94fJdEwL8WkT1a6LHBdTMbix1aciALwEWPx3Wp",
                pk_hex: "546c316992b37ac1a0a5ad305ea12169341772d9a396080272e722e9662b0361",
                sk_hex: "3eb11a2e242212be157793db9fa881edffcfb391174b07d20369521ba1a084b1546c316992b37ac1a0a5ad305ea12169341772d9a396080272e722e9662b0361",
            },
            SolanaTestVector {
                path: "m/44'/501'/5'/0'",
                address: "7EeV8eiRuGoR8bFHCjdCRGQd1RM5sR2dAkdiTEtC9ko7",
                pk_hex: "5ca50e79425ee33361ca1d9fbd96b42fd9b8b204b4508a7220d425632853368e",
                sk_hex: "22e6f8ea7e213a67f801d313daa33046f5f7b1808f38d5b2bb7301aefa158cbc5ca50e79425ee33361ca1d9fbd96b42fd9b8b204b4508a7220d425632853368e",
            },
            SolanaTestVector {
                path: "m/44'/501'/6'/0'",
                address: "F9fVg2LeE2RhM6CfNn888hbjqovZDEWY3vm2hEkvX3Nh",
                pk_hex: "d23bca05da7d072271b71c3f17fe6d83fbdb78ffb7406532ab57e0963d940852",
                sk_hex: "9515bfa8fecc7b7ebe75fd55e9d15b6f7988d79dbf6546f998630cacafb63fc7d23bca05da7d072271b71c3f17fe6d83fbdb78ffb7406532ab57e0963d940852",
            },
            SolanaTestVector {
                path: "m/44'/501'/7'/0'",
                address: "26roUwgM5T6bccX41hakjiW4fDiKFSao1RyoFsAxr6e6",
                pk_hex: "105be6cf9bf3089e1d57f9bd7eac2cffd8e6201f2f14e3dc1484c103ee09c653",
                sk_hex: "3979d8b5812d7747cfd25215b0a904fdbdf8f7c24aa82a91c2e00878ff1146ff105be6cf9bf3089e1d57f9bd7eac2cffd8e6201f2f14e3dc1484c103ee09c653",
            },
            SolanaTestVector {
                path: "m/44'/501'/8'/0'",
                address: "5mCGtMUD21HEvWJxKGKS6HEAH7ezzy12MWGs4bPgcJwV",
                pk_hex: "46c10cfc8924a91466203d5bd3dc6b00886cf876df6ab7726abf2c1b83b70864",
                sk_hex: "c0c8348480fd4d865ffe93e11ba3a3b2431eeaaf1bf795faaac1710ec660730946c10cfc8924a91466203d5bd3dc6b00886cf876df6ab7726abf2c1b83b70864",
            },
            SolanaTestVector {
                path: "m/44'/501'/9'/0'",
                address: "2yaW8VAMLhQiornz1BgcSWDUSH2jC2dmB8RWnTJi8Yab",
                pk_hex: "1d5a17e3e856b0f4c31d9590442c411abfab3012cea3087f37fcc2d851b65140",
                sk_hex: "f5606f75eaffadd56cc1247896e4e79237c37fe57cc970cfb12fb7d3043236611d5a17e3e856b0f4c31d9590442c411abfab3012cea3087f37fcc2d851b65140",
            },
        ]
    }

    fn solana_seed() -> SecretBox<[u8; 64]> {
        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
        mnemonic.to_seed(&SecretString::from("")).unwrap()
    }

    fn solana_address(signing_key: &SigningKey) -> String {
        let pubkey = signing_key.verifying_key();
        bs58::encode(pubkey.to_bytes()).into_string()
    }

    #[test]
    fn solana_root_derivation() {
        let seed = solana_seed();
        let vectors = get_solana_test_vectors();
        let tv = &vectors[0];

        let signing_key = derive_ed25519_key(&seed, tv.path).unwrap();
        let pk = signing_key.verifying_key();

        assert_eq!(
            hex::encode(pk.to_bytes()),
            tv.pk_hex,
            "PK mismatch for path {}",
            tv.path
        );
        assert_eq!(
            hex::encode(signing_key.to_bytes()),
            &tv.sk_hex[..64],
            "SK (secret part) mismatch for path {}",
            tv.path
        );
        assert_eq!(
            solana_address(&signing_key),
            tv.address,
            "Address mismatch for path {}",
            tv.path
        );
    }

    #[test]
    fn solana_account_derivation() {
        let seed = solana_seed();
        let vectors = get_solana_test_vectors();

        for tv in &vectors[1..11] {
            let signing_key = derive_ed25519_key(&seed, tv.path).unwrap();
            let pk = signing_key.verifying_key();

            assert_eq!(
                hex::encode(pk.to_bytes()),
                tv.pk_hex,
                "PK mismatch for path {}",
                tv.path
            );
            assert_eq!(
                hex::encode(signing_key.to_bytes()),
                &tv.sk_hex[..64],
                "SK (secret part) mismatch for path {}",
                tv.path
            );
            assert_eq!(
                solana_address(&signing_key),
                tv.address,
                "Address mismatch for path {}",
                tv.path
            );
        }
    }

    #[test]
    fn solana_account_change_derivation() {
        let seed = solana_seed();
        let vectors = get_solana_test_vectors();

        for tv in &vectors[11..] {
            let signing_key = derive_ed25519_key(&seed, tv.path).unwrap();
            let pk = signing_key.verifying_key();

            assert_eq!(
                hex::encode(pk.to_bytes()),
                tv.pk_hex,
                "PK mismatch for path {}",
                tv.path
            );
            assert_eq!(
                hex::encode(signing_key.to_bytes()),
                &tv.sk_hex[..64],
                "SK (secret part) mismatch for path {}",
                tv.path
            );
            assert_eq!(
                solana_address(&signing_key),
                tv.address,
                "Address mismatch for path {}",
                tv.path
            );
        }
    }

    #[test]
    fn solana_ed25519_rejects_non_hardened() {
        let seed = solana_seed();
        let result = derive_ed25519_key(&seed, "m/44'/501'/0");
        assert!(result.is_err());
    }
}
