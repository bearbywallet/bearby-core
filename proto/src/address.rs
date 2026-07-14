use crate::{
    btc_utils::create_btc_address,
    pubkey::PubKey,
    zil_address::{
        from_zil_base16, from_zil_bech32_address, from_zil_pub_key, to_bech32, to_checksum_address,
    },
};
use config::key::ED25519_PUB_KEY_SIZE;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use config::address::{ADDR_LEN, HRP_ZIL};
use errors::address::AddressError;

type Result<T> = std::result::Result<T, AddressError>;

#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    Secp256k1Sha256([u8; ADDR_LEN]),    // ZILLIQA
    Secp256k1Keccak256([u8; ADDR_LEN]), // Ethereum
    Secp256k1Bitcoin(Vec<u8>),          // Bitcoin (UTF-8 encoded address string)
    Secp256k1Tron([u8; ADDR_LEN]),      // Tron
    Ed25519Solana(Pubkey),              // Solana
}

impl Address {
    pub const ZERO: [u8; ADDR_LEN] = [0u8; ADDR_LEN];

    pub fn from_zil_base16(addr: &str) -> Result<Self> {
        let addr = from_zil_base16(addr.trim_start_matches("0x"))
            .ok_or(AddressError::InvalidBase16Address)?;

        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn auto_format(&self) -> String {
        match self {
            Address::Secp256k1Sha256(_) => self.get_zil_bech32().unwrap_or_default(),
            Address::Secp256k1Keccak256(_) => self.to_eth_checksummed().unwrap_or_default(),
            Address::Secp256k1Bitcoin(data) => String::from_utf8(data.clone()).unwrap_or_default(),
            Address::Secp256k1Tron(bytes) => Self::tron_to_base58check(bytes),
            Address::Ed25519Solana(pubkey) => pubkey.to_string(),
        }
    }

    pub fn from_solana_address(addr: &str) -> Result<Self> {
        let pubkey = Pubkey::from_str(addr)
            .map_err(|e| AddressError::InvalidSolanaAddress(e.to_string()))?;
        Ok(Self::Ed25519Solana(pubkey))
    }

    pub fn is_solana_address(addr: &str) -> bool {
        Pubkey::from_str(addr).is_ok()
    }

    pub fn from_str_hex(addr: &str) -> Result<Self> {
        if addr.starts_with(HRP_ZIL) {
            return Self::from_zil_bech32(addr);
        }

        if addr.starts_with("0x") {
            return Self::from_eth_address(addr);
        }

        if Self::is_tron_address(addr) {
            return Self::from_tron_address(addr);
        }

        if Self::is_solana_address(addr) {
            return Self::from_solana_address(addr);
        }

        if Self::is_bitcoin_address(addr) {
            return Self::from_bitcoin_address(addr);
        }

        let bytes = hex::decode(addr).map_err(|_| AddressError::InvalidHex)?;
        if bytes.len() != ADDR_LEN {
            return Err(AddressError::InvalidLength);
        }

        let eth_addr = format!("0x{}", addr);
        if let Ok(addr) = Self::from_eth_address(&eth_addr) {
            return Ok(addr);
        }

        let zil_addr = format!("0x{}", addr);
        Self::from_zil_base16(&zil_addr)
    }

    pub fn from_zil_bech32(addr: &str) -> Result<Self> {
        let addr = from_zil_bech32_address(addr)?;
        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn from_eth_address(addr: &str) -> Result<Self> {
        let addr = alloy::primitives::Address::from_str(addr)
            .map_err(|e| AddressError::InvalidETHAddress(e.to_string()))?;
        let bytes: [u8; ADDR_LEN] = addr
            .as_slice()
            .try_into()
            .map_err(|_| AddressError::InvalidETHAddress(addr.to_string()))?;

        Ok(Self::Secp256k1Keccak256(bytes))
    }

    pub fn to_alloy_addr(&self) -> alloy::primitives::Address {
        alloy::primitives::Address::from_slice(self.as_ref())
    }

    pub fn to_bitcoin_addr(&self) -> Result<bitcoin::Address> {
        match self {
            Address::Secp256k1Bitcoin(data) => {
                let addr_str = String::from_utf8(data.clone())
                    .map_err(|e| AddressError::BTCAddrError(e.to_string()))?;
                let addr = bitcoin::Address::from_str(&addr_str)
                    .map_err(|e| AddressError::BTCAddrError(e.to_string()))?
                    .assume_checked();

                Ok(addr)
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn to_solana_addr(&self) -> Result<solana_pubkey::Pubkey> {
        match self {
            Address::Ed25519Solana(data) => {
                Ok(solana_pubkey::Pubkey::new_from_array(data.to_bytes()))
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn re_encode_btc_network(&self, new_network: bitcoin::Network) -> Result<Self> {
        match self {
            Address::Secp256k1Bitcoin(_) => {
                let btc_addr = self.to_bitcoin_addr()?;
                let script = btc_addr.script_pubkey();
                let new_addr = bitcoin::Address::from_script(&script, new_network)
                    .map_err(|e| AddressError::BTCAddrError(e.to_string()))?;
                Ok(Self::Secp256k1Bitcoin(new_addr.to_string().into_bytes()))
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn is_bitcoin_address(addr: &str) -> bool {
        if addr.starts_with('1')
            || addr.starts_with('3')
            || addr.starts_with('m')
            || addr.starts_with('n')
            || addr.starts_with('2')
        {
            return true;
        }

        if addr.starts_with("bc1") || addr.starts_with("tb1") || addr.starts_with("bcrt1") {
            return true;
        }

        false
    }

    pub fn from_bitcoin_address(addr: &str) -> Result<Self> {
        let btc_addr = bitcoin::Address::from_str(addr)
            .map_err(|e| AddressError::BTCAddrError(e.to_string()))?
            .assume_checked();

        let addr_string = btc_addr.to_string();
        Ok(Self::Secp256k1Bitcoin(addr_string.into_bytes()))
    }

    pub fn get_bitcoin_address_type(&self) -> Result<bitcoin::AddressType> {
        let btc_addr = self.to_bitcoin_addr()?;
        btc_addr.address_type().ok_or(AddressError::BTCAddrError(
            "Unknown address type".to_string(),
        ))
    }

    pub fn get_bitcoin_network(&self) -> Result<bitcoin::Network> {
        match self {
            Address::Secp256k1Bitcoin(data) => {
                let addr_str = String::from_utf8(data.clone())
                    .map_err(|e| AddressError::BTCAddrError(e.to_string()))?;
                if addr_str.starts_with("bc1")
                    || addr_str.starts_with('1')
                    || addr_str.starts_with('3')
                {
                    Ok(bitcoin::Network::Bitcoin)
                } else if addr_str.starts_with("tb1")
                    || addr_str.starts_with('m')
                    || addr_str.starts_with('n')
                    || addr_str.starts_with('2')
                {
                    Ok(bitcoin::Network::Testnet)
                } else if addr_str.starts_with("bcrt1") {
                    Ok(bitcoin::Network::Regtest)
                } else {
                    Err(AddressError::BTCAddrError(
                        "Unknown network prefix".to_string(),
                    ))
                }
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn get_bip_purpose(&self) -> u32 {
        use crypto::bip49::DerivationPath;

        match self {
            Address::Secp256k1Sha256(_) => DerivationPath::BIP44_PURPOSE,
            Address::Secp256k1Keccak256(_) => DerivationPath::BIP44_PURPOSE,
            Address::Secp256k1Tron(_) => DerivationPath::BIP44_PURPOSE,
            Address::Ed25519Solana(_) => DerivationPath::BIP44_PURPOSE,
            Address::Secp256k1Bitcoin(_) => self
                .get_bitcoin_address_type()
                .map(DerivationPath::bip_from_address_type)
                .unwrap_or(DerivationPath::BIP84_PURPOSE),
        }
    }

    pub fn to_eth_checksummed(&self) -> Result<String> {
        let addr = alloy::primitives::Address::try_from(self.as_ref())
            .map_err(|e| AddressError::InvalidETHAddress(e.to_string()))?;

        // TODO: check chain id;
        Ok(addr.to_checksum(None))
    }

    pub fn is_tron_address(addr: &str) -> bool {
        addr.starts_with('T') && addr.len() == 34
    }

    pub fn from_tron_address(addr: &str) -> Result<Self> {
        let decoded = bs58::decode(addr)
            .into_vec()
            .map_err(|e| AddressError::InvalidTronAddress(e.to_string()))?;

        if decoded.len() != 25 {
            return Err(AddressError::InvalidTronAddress(
                "Invalid decoded length".to_string(),
            ));
        }

        if decoded[0] != 0x41 {
            return Err(AddressError::InvalidTronAddress(
                "Invalid version byte".to_string(),
            ));
        }

        // Verify checksum (double SHA256)
        let payload = &decoded[..21];
        let checksum = &decoded[21..];
        let hash1 = Sha256::digest(payload);
        let hash2 = Sha256::digest(hash1);
        if &hash2[..4] != checksum {
            return Err(AddressError::InvalidTronAddress(
                "Invalid checksum".to_string(),
            ));
        }

        let addr_bytes: [u8; ADDR_LEN] = decoded[1..21]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;

        Ok(Self::Secp256k1Tron(addr_bytes))
    }

    pub fn tron_to_base58check(bytes: &[u8; ADDR_LEN]) -> String {
        let mut payload = Vec::with_capacity(25);
        payload.push(0x41u8); // Tron mainnet prefix
        payload.extend_from_slice(bytes);

        let hash1 = Sha256::digest(&payload);
        let hash2 = Sha256::digest(hash1);
        payload.extend_from_slice(&hash2[..4]);

        bs58::encode(payload).into_string()
    }

    pub fn to_tron_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(21);
        bytes.push(0x41);
        bytes.extend_from_slice(self.as_ref());
        bytes
    }

    pub fn from_tron_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 21 || bytes[0] != 0x41 {
            return Err(AddressError::InvalidTronAddress(
                "Expected 21 bytes starting with 0x41".to_string(),
            ));
        }
        let addr_bytes: [u8; ADDR_LEN] = bytes[1..21]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;
        Ok(Self::Secp256k1Tron(addr_bytes))
    }

    pub fn from_pubkey(pk: &PubKey) -> Result<Self> {
        match pk {
            PubKey::Secp256k1Sha256(pk) => {
                let addr = from_zil_pub_key(pk)?;

                Ok(Self::Secp256k1Sha256(addr))
            }
            PubKey::Secp256k1Keccak256(_) => {
                let k256_pubkey: alloy::signers::k256::ecdsa::VerifyingKey = pk.try_into()?;
                let addr = alloy::primitives::Address::from_public_key(&k256_pubkey);

                Ok(Self::Secp256k1Keccak256(addr.into()))
            }
            PubKey::Secp256k1Bitcoin((pk_bytes, network, addr_type)) => {
                let addr = create_btc_address(pk_bytes, *network, *addr_type)
                    .map_err(|_| AddressError::InvalidPubKey)?;
                let addr_string = addr.to_string();

                Ok(Self::Secp256k1Bitcoin(addr_string.into_bytes()))
            }
            PubKey::Secp256k1Tron(_) => {
                let k256_pubkey: alloy::signers::k256::ecdsa::VerifyingKey = pk.try_into()?;
                let addr = alloy::primitives::Address::from_public_key(&k256_pubkey);

                Ok(Self::Secp256k1Tron(addr.into()))
            }
            PubKey::Ed25519Solana(pk) => Ok(Self::Ed25519Solana(*pk)),
        }
    }

    pub fn prefix_type(&self) -> u8 {
        match self {
            Address::Secp256k1Sha256(_) => 0,
            Address::Secp256k1Keccak256(_) => 1,
            Address::Secp256k1Bitcoin(_) => 2,
            Address::Ed25519Solana(_) => 3,
            Address::Secp256k1Tron(_) => 4,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![self.prefix_type()];
        result.extend_from_slice(self.as_ref());
        result
    }

    pub fn addr_bytes(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256(v) => v,
            Address::Secp256k1Keccak256(v) => v,
            Address::Secp256k1Bitcoin(v) => v,
            Address::Secp256k1Tron(v) => v,
            Address::Ed25519Solana(v) => v.as_ref(),
        }
    }

    pub fn to_hash(&self) -> usize {
        let bytes = self.addr_bytes();
        let chunk = std::mem::size_of::<usize>();
        let mut result = 0usize;
        for (i, &byte) in bytes.iter().enumerate() {
            result ^= (byte as usize) << ((i % chunk) * 8);
        }
        result
    }

    pub fn get_zil_bech32(&self) -> Result<String> {
        let value = self.addr_bytes();

        to_bech32(HRP_ZIL, value)
    }

    pub fn get_zil_base16(&self) -> Result<String> {
        match self {
            Address::Secp256k1Sha256(v) => Ok(hex::encode(v)),
            Address::Secp256k1Keccak256(v) => Ok(hex::encode(v)),
            Address::Secp256k1Bitcoin(_) => Err(AddressError::InvalidAddressType),
            Address::Secp256k1Tron(_) => Err(AddressError::InvalidAddressType),
            Address::Ed25519Solana(_) => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn get_zil_check_sum_addr(&self) -> Result<String> {
        match self {
            Address::Secp256k1Sha256(v) => to_checksum_address(&hex::encode(v)),
            Address::Secp256k1Keccak256(v) => to_checksum_address(&hex::encode(v)),
            Address::Secp256k1Bitcoin(_) => Err(AddressError::InvalidAddressType),
            Address::Secp256k1Tron(_) => Err(AddressError::InvalidAddressType),
            Address::Ed25519Solana(_) => Err(AddressError::InvalidAddressType),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256(bytes) => write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap()),
            Self::Secp256k1Keccak256(bytes) => {
                write!(
                    f,
                    "{}",
                    alloy::primitives::Address::from_slice(bytes).to_checksum(None)
                )
            }
            Self::Secp256k1Bitcoin(_) => write!(f, "{}", self.auto_format()),
            Self::Secp256k1Tron(bytes) => write!(f, "{}", Self::tron_to_base58check(bytes)),
            Self::Ed25519Solana(pubkey) => write!(f, "{pubkey}"),
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256(bytes) => write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap()),
            Self::Secp256k1Keccak256(bytes) => {
                write!(
                    f,
                    "{}",
                    alloy::primitives::Address::from_slice(bytes).to_checksum(None)
                )
            }
            Self::Secp256k1Bitcoin(_) => write!(f, "{}", self.auto_format()),
            Self::Secp256k1Tron(bytes) => write!(f, "{}", Self::tron_to_base58check(bytes)),
            Self::Ed25519Solana(pubkey) => write!(f, "{pubkey}"),
        }
    }
}

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Address::Secp256k1Sha256(_) => 0u8.hash(state),
            Address::Secp256k1Keccak256(_) => 1u8.hash(state),
            Address::Secp256k1Bitcoin(_) => 2u8.hash(state),
            Address::Ed25519Solana(_) => 3u8.hash(state),
            Address::Secp256k1Tron(_) => 4u8.hash(state),
        }

        self.as_ref().hash(state);
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self> {
        let data = hex::decode(s).map_err(|_| AddressError::InvalidHex)?;
        Address::try_from(data.as_slice())
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = AddressError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        if slice.is_empty() {
            return Err(AddressError::InvalidLength);
        }

        let key_type = slice[0];

        match key_type {
            0 | 1 => {
                if slice.len() != ADDR_LEN + 1 {
                    return Err(AddressError::InvalidLength);
                }
                let key_data: [u8; ADDR_LEN] = slice[1..]
                    .try_into()
                    .map_err(|_| AddressError::InvalidLength)?;

                match key_type {
                    0 => Ok(Address::Secp256k1Sha256(key_data)),
                    1 => Ok(Address::Secp256k1Keccak256(key_data)),
                    _ => unreachable!(),
                }
            }
            2 => {
                let addr_bytes = slice[1..].to_vec();
                Ok(Address::Secp256k1Bitcoin(addr_bytes))
            }
            3 => {
                if slice.len() != ED25519_PUB_KEY_SIZE + 1 {
                    return Err(AddressError::InvalidLength);
                }
                let key_data: [u8; ED25519_PUB_KEY_SIZE] = slice[1..]
                    .try_into()
                    .map_err(|_| AddressError::InvalidLength)?;
                Ok(Address::Ed25519Solana(Pubkey::from(key_data)))
            }
            4 => {
                if slice.len() != ADDR_LEN + 1 {
                    return Err(AddressError::InvalidLength);
                }
                let key_data: [u8; ADDR_LEN] = slice[1..]
                    .try_into()
                    .map_err(|_| AddressError::InvalidLength)?;
                Ok(Address::Secp256k1Tron(key_data))
            }
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256(data) => data,
            Address::Secp256k1Keccak256(data) => data,
            Address::Secp256k1Bitcoin(data) => data,
            Address::Secp256k1Tron(data) => data,
            Address::Ed25519Solana(data) => data.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let zil_data = [1u8; ADDR_LEN];
        let eth_data = [2u8; ADDR_LEN];

        let zil_addr = Address::Secp256k1Sha256(zil_data);
        let eth_addr = Address::Secp256k1Keccak256(eth_data);

        assert_eq!(zil_addr.as_ref(), &zil_data);
        assert_eq!(eth_addr.as_ref(), &eth_data);
    }

    #[test]
    fn test_to_bytes() {
        let zil_data = [1u8; ADDR_LEN];
        let eth_data = [2u8; ADDR_LEN];

        let zil_addr = Address::Secp256k1Sha256(zil_data);
        let eth_addr = Address::Secp256k1Keccak256(eth_data);

        let zil_bytes = zil_addr.to_bytes();
        let eth_bytes = eth_addr.to_bytes();

        assert_eq!(zil_bytes[0], 0);
        assert_eq!(eth_bytes[0], 1);
        assert_eq!(&zil_bytes[1..], &zil_data);
        assert_eq!(&eth_bytes[1..], &eth_data);
    }

    #[test]
    fn test_display() {
        let zil_data = [1u8; ADDR_LEN];
        let zil_addr = Address::Secp256k1Sha256(zil_data);

        let expected = to_bech32(HRP_ZIL, &zil_data).unwrap();
        assert_eq!(zil_addr.to_string(), expected);
    }

    #[test]
    fn test_from_bytes() {
        let mut zil_bytes = [0u8; ADDR_LEN + 1];
        zil_bytes[0] = 0;
        zil_bytes[1..].fill(1);

        let addr: Address = zil_bytes.as_slice().try_into().unwrap();
        assert!(matches!(addr, Address::Secp256k1Sha256(_)));
        assert_eq!(addr.as_ref(), &zil_bytes[1..]);
    }

    #[test]
    fn test_try_from_slice() {
        let mut zil_slice = vec![0u8; ADDR_LEN + 1];
        zil_slice[1..].fill(1);

        let addr = Address::try_from(zil_slice.as_slice()).unwrap();
        assert!(matches!(addr, Address::Secp256k1Sha256(_)));

        // Test invalid length
        let invalid_slice = vec![0u8; ADDR_LEN];
        assert!(matches!(
            Address::try_from(invalid_slice.as_slice()),
            Err(AddressError::InvalidLength)
        ));

        // Test invalid key type
        let invalid_type_slice = vec![9u8; ADDR_LEN + 1];
        assert!(matches!(
            Address::try_from(invalid_type_slice.as_slice()),
            Err(AddressError::InvalidKeyType)
        ));
    }

    #[test]
    fn test_as_ref() {
        let data = [1u8; ADDR_LEN];
        let addr = Address::Secp256k1Sha256(data);
        assert_eq!(addr.as_ref(), &data);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = [1u8; ADDR_LEN];
        let addr = Address::Secp256k1Sha256(original_data);
        let bytes = addr.to_bytes();
        let roundtrip_addr = bytes.as_slice().try_into().unwrap();
        assert_eq!(addr, roundtrip_addr);
    }

    #[test]
    fn test_addr() {
        let pubkey_eth: PubKey =
            "0103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();
        let pubkey_zil: PubKey =
            "0003150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();
        let addr_eth = Address::from_pubkey(&pubkey_eth).unwrap();
        let addr_zil = Address::from_pubkey(&pubkey_zil).unwrap();

        assert_eq!(
            addr_eth.to_string(),
            "0xC315295101461753b838E0BE8688E744cf52Dd6b"
        );
        assert_eq!(
            addr_zil.to_string(),
            "zil1a0vtxuxamd3kltmyzpqdyxqu25vsss8mp58jtu"
        );
    }

    #[test]
    fn test_from_eth_address() {
        let hex_eth_adr = "0xf06686B5Eb5cAe38c09f12412B729045647E74e3";
        let addr = Address::from_eth_address(hex_eth_adr).unwrap();

        assert!(matches!(addr, Address::Secp256k1Keccak256(_)));
        assert_eq!(addr.to_eth_checksummed().unwrap(), hex_eth_adr);
        assert!(Address::from_eth_address("0x1234").is_err());

        let hex_sha256_type = "0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe";
        let addr = Address::from_eth_address(hex_sha256_type).unwrap();

        assert!(matches!(addr, Address::Secp256k1Keccak256(_)));
        assert_eq!(addr.to_eth_checksummed().unwrap(), hex_sha256_type);
    }

    #[test]
    fn test_alloy_addr() {
        let hex_eth_adr = "0xf06686B5Eb5cAe38c09f12412B729045647E74e3";
        let addr = Address::from_eth_address(hex_eth_adr).unwrap();
        let alloy_addr = addr.to_alloy_addr();

        assert_eq!(alloy_addr.to_checksum(None), hex_eth_adr);
    }

    #[test]
    fn test_bitcoin_address_creation() {
        let btc_data = vec![42u8; ADDR_LEN];
        let btc_addr = Address::Secp256k1Bitcoin(btc_data.clone());

        assert_eq!(btc_addr.as_ref(), &btc_data);
        assert_eq!(btc_addr.prefix_type(), 2);
    }

    #[test]
    fn test_bitcoin_to_bytes() {
        let btc_data = vec![42u8; ADDR_LEN];
        let btc_addr = Address::Secp256k1Bitcoin(btc_data.clone());
        let btc_bytes = btc_addr.to_bytes();

        assert_eq!(btc_bytes[0], 2);
        assert_eq!(&btc_bytes[1..], &btc_data);
    }

    #[test]
    fn test_bitcoin_from_bytes() {
        let mut btc_bytes = [0u8; ADDR_LEN + 1];
        btc_bytes[0] = 2;
        btc_bytes[1..].fill(42);

        let addr: Address = btc_bytes.as_slice().try_into().unwrap();
        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
        assert_eq!(addr.as_ref(), &btc_bytes[1..]);
    }

    #[test]
    fn test_bitcoin_address_roundtrip() {
        let original_data = vec![123u8; ADDR_LEN];
        let addr = Address::Secp256k1Bitcoin(original_data.clone());
        let bytes = addr.to_bytes();
        let roundtrip_addr: Address = bytes.as_slice().try_into().unwrap();

        assert_eq!(addr, roundtrip_addr);
    }

    #[test]
    fn test_p2pkh_address_bip44() {
        let addr_str = "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2pkh
        );
        assert_eq!(addr.get_bip_purpose(), 44);
    }

    #[test]
    fn test_p2sh_address_bip49() {
        let addr_str = "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2sh
        );
        assert_eq!(addr.get_bip_purpose(), 49);
    }

    #[test]
    fn test_p2wpkh_address_bip84() {
        let addr_str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2wpkh
        );
        assert_eq!(addr.get_bip_purpose(), 84);
    }

    #[test]
    fn test_p2tr_address_bip86() {
        let addr_str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2tr
        );
        assert_eq!(addr.get_bip_purpose(), 86);
    }

    #[test]
    fn test_p2wsh_address() {
        let addr_str = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2wsh
        );
    }

    #[test]
    fn test_testnet_p2pkh_address() {
        let addr_str = "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2pkh
        );
        assert_eq!(addr.get_bip_purpose(), 44);
    }

    #[test]
    fn test_testnet_p2sh_address() {
        let addr_str = "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2sh
        );
        assert_eq!(addr.get_bip_purpose(), 49);
    }

    #[test]
    fn test_testnet_p2wsh_address() {
        let addr_str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2wsh
        );
    }

    #[test]
    fn test_regtest_p2wpkh_address() {
        let addr_str = "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();

        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(
            addr.get_bitcoin_address_type().unwrap(),
            bitcoin::AddressType::P2wpkh
        );
        assert_eq!(addr.get_bip_purpose(), 84);
    }

    #[test]
    fn test_is_bitcoin_address() {
        assert!(Address::is_bitcoin_address(
            "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY"
        ));
        assert!(Address::is_bitcoin_address(
            "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE"
        ));
        assert!(Address::is_bitcoin_address(
            "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw"
        ));
        assert!(Address::is_bitcoin_address(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        ));
        assert!(Address::is_bitcoin_address(
            "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC"
        ));
        assert!(Address::is_bitcoin_address(
            "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr"
        ));
        assert!(Address::is_bitcoin_address(
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
        ));
        assert!(Address::is_bitcoin_address(
            "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl"
        ));

        assert!(!Address::is_bitcoin_address(
            "0xf06686B5Eb5cAe38c09f12412B729045647E74e3"
        ));
        assert!(!Address::is_bitcoin_address(
            "zil1a0vtxuxamd3kltmyzpqdyxqu25vsss8mp58jtu"
        ));
    }

    #[test]
    fn test_from_str_hex_bitcoin() {
        let addr_str = "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY";
        let addr = Address::from_str_hex(addr_str).unwrap();

        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
        assert_eq!(addr.auto_format(), addr_str);
    }

    #[test]
    fn test_bitcoin_address_type_detection() {
        let test_cases = vec![
            (
                "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY",
                bitcoin::AddressType::P2pkh,
                44,
            ),
            (
                "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE",
                bitcoin::AddressType::P2sh,
                49,
            ),
            (
                "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw",
                bitcoin::AddressType::P2wpkh,
                84,
            ),
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                bitcoin::AddressType::P2tr,
                86,
            ),
        ];

        for (addr_str, expected_type, expected_bip) in test_cases {
            let addr = Address::from_bitcoin_address(addr_str).unwrap();
            assert_eq!(addr.get_bitcoin_address_type().unwrap(), expected_type);
            assert_eq!(addr.get_bip_purpose(), expected_bip);
        }
    }

    #[test]
    fn test_invalid_bitcoin_address() {
        let invalid_addr = "1InvalidBitcoinAddress";
        let result = Address::from_bitcoin_address(invalid_addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitcoin_address_serialization() {
        let addr_str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
        let addr = Address::from_bitcoin_address(addr_str).unwrap();
        let bytes = addr.to_bytes();
        let roundtrip_addr: Address = bytes.as_slice().try_into().unwrap();

        assert_eq!(addr, roundtrip_addr);
        assert_eq!(roundtrip_addr.auto_format(), addr_str);
    }

    #[test]
    fn test_tron_addresses() {
        for addr_str in test_data::tron_addresses::ALL {
            let addr = Address::from_tron_address(addr_str).unwrap();

            assert!(matches!(addr, Address::Secp256k1Tron(_)));
            assert!(Address::is_tron_address(addr_str));
            assert_eq!(addr.prefix_type(), 4);

            let serialized = serde_json::to_string(&addr).unwrap();
            let deserialized: Address = serde_json::from_str(&serialized).unwrap();
            assert_eq!(addr, deserialized);

            let bytes = addr.to_bytes();
            let from_bytes: Address = bytes.as_slice().try_into().unwrap();
            assert_eq!(addr, from_bytes);

            assert_eq!(addr.to_string(), addr_str);
            assert_eq!(addr.auto_format(), addr_str);
        }
    }

    #[test]
    fn test_solana_address_from_pubkey() {
        let pk_hex = "8403366f00cce80bc3ae339d4bc5ec33a7b831c650993f95bf85fb8f62a227f6";
        let pk_bytes: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        let pk = PubKey::Ed25519Solana(pk_bytes.into());

        let addr = Address::from_pubkey(&pk).unwrap();
        assert!(matches!(addr, Address::Ed25519Solana(_)));
        assert_eq!(addr.prefix_type(), 3);
        assert_eq!(
            addr.auto_format(),
            "9tKf8Q98FsGKJiM4oqMnTxmYH3fU2qJzSwzc76vgzyBT"
        );
    }

    #[test]
    fn test_solana_address_roundtrip() {
        let addr_str = "BtELVjZSaWhMat94P9HyasX3Gvpv6C7WHXJGqWdZbwSQ";
        let addr = Address::from_solana_address(addr_str).unwrap();

        assert!(matches!(addr, Address::Ed25519Solana(_)));
        assert_eq!(addr.auto_format(), addr_str);
        assert_eq!(addr.to_string(), addr_str);
    }

    #[test]
    fn test_solana_address_to_from_bytes() {
        let addr_str = "9tKf8Q98FsGKJiM4oqMnTxmYH3fU2qJzSwzc76vgzyBT";
        let addr = Address::from_solana_address(addr_str).unwrap();

        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], 3u8);
        assert_eq!(bytes.len(), ED25519_PUB_KEY_SIZE + 1);

        let recovered: Address = bytes.as_slice().try_into().unwrap();
        assert_eq!(addr, recovered);
        assert_eq!(recovered.auto_format(), addr_str);
    }

    #[test]
    fn test_solana_address_serde() {
        let addr_str = "M9juqHHtP85PvRKX3d4FS9jkF1WHZwyX3dG7NcYswdH";
        let addr = Address::from_solana_address(addr_str).unwrap();

        let json = serde_json::to_string(&addr).unwrap();
        let recovered: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, recovered);
        assert_eq!(recovered.auto_format(), addr_str);
    }
}
