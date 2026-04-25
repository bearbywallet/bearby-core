use config::sha::SHA512_SIZE;
use crypto::bip49::{DerivationPath, DerivationType};
use crypto::slip44;
use errors::bip32::Bip329Errors;
use errors::keypair::PubKeyError;
use secrecy::SecretBox;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

use crate::address::Address;

type Result<T> = std::result::Result<T, PubKeyError>;

pub const GAP_LIMIT: u32 = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct BtcAddressEntry {
    pub address: Address,
    pub path: DerivationPath,
    pub history: Vec<bitcoin::Txid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressChain {
    pub external: Vec<BtcAddressEntry>,
    pub internal: Vec<BtcAddressEntry>,
}

impl AddressChain {
    pub fn get_external(&self) -> Result<&BtcAddressEntry> {
        self.external
            .iter()
            .rfind(|e| e.history.is_empty())
            .ok_or(PubKeyError::NoUnusedAddress)
    }

    pub fn get_internal(&self) -> Result<&BtcAddressEntry> {
        self.internal
            .iter()
            .rfind(|e| e.history.is_empty())
            .ok_or(PubKeyError::NoUnusedAddress)
    }
}

pub trait ByteCodec: Sized {
    fn to_byte(&self) -> u8;
    fn from_byte(byte: u8) -> Result<Self>;
}

impl ByteCodec for bitcoin::Network {
    fn to_byte(&self) -> u8 {
        match self {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Testnet4 => 2,
            bitcoin::Network::Signet => 3,
            bitcoin::Network::Regtest => 4,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(bitcoin::Network::Bitcoin),
            1 => Ok(bitcoin::Network::Testnet),
            2 => Ok(bitcoin::Network::Testnet4),
            3 => Ok(bitcoin::Network::Signet),
            4 => Ok(bitcoin::Network::Regtest),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

impl ByteCodec for bitcoin::AddressType {
    fn to_byte(&self) -> u8 {
        match self {
            bitcoin::AddressType::P2pkh => 0,
            bitcoin::AddressType::P2sh => 1,
            bitcoin::AddressType::P2wpkh => 2,
            bitcoin::AddressType::P2wsh => 3,
            bitcoin::AddressType::P2tr => 4,
            bitcoin::AddressType::P2a => 5,
            &_ => todo!(),
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(bitcoin::AddressType::P2pkh),
            1 => Ok(bitcoin::AddressType::P2sh),
            2 => Ok(bitcoin::AddressType::P2wpkh),
            3 => Ok(bitcoin::AddressType::P2wsh),
            4 => Ok(bitcoin::AddressType::P2tr),
            5 => Ok(bitcoin::AddressType::P2a),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

pub fn create_btc_address(
    pk_bytes: &[u8],
    network: bitcoin::Network,
    addr_type: bitcoin::AddressType,
) -> Result<bitcoin::Address> {
    use bitcoin::{CompressedPublicKey, KnownHrp};

    let compressed_pk =
        CompressedPublicKey::from_slice(pk_bytes).map_err(|_| PubKeyError::FailIntoPubKey)?;

    let hrp: KnownHrp = network.into();

    let addr = match addr_type {
        bitcoin::AddressType::P2pkh => bitcoin::Address::p2pkh(compressed_pk, network),
        bitcoin::AddressType::P2wpkh => bitcoin::Address::p2wpkh(&compressed_pk, hrp),
        bitcoin::AddressType::P2sh => {
            let wpkh = bitcoin::Address::p2wpkh(&compressed_pk, hrp);
            bitcoin::Address::p2sh(&wpkh.script_pubkey(), network)
                .map_err(|_| PubKeyError::InvalidKeyType)?
        }
        bitcoin::AddressType::P2tr => {
            use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
            let x_only_pk = XOnlyPublicKey::from(compressed_pk.0);
            let secp = Secp256k1::new();
            bitcoin::Address::p2tr(&secp, x_only_pk, None, hrp)
        }
        _ => return Err(PubKeyError::InvalidKeyType),
    };

    Ok(addr)
}

pub fn generate_btc_addresses(
    seed: &SecretBox<[u8; SHA512_SIZE]>,
    account_index: usize,
    network: bitcoin::Network,
    start_index: u32,
    count: u32,
) -> std::result::Result<HashMap<bitcoin::AddressType, AddressChain>, Bip329Errors> {
    let formats: [(bitcoin::AddressType, u32); 4] = [
        (bitcoin::AddressType::P2pkh, DerivationPath::BIP44_PURPOSE),
        (bitcoin::AddressType::P2sh, DerivationPath::BIP49_PURPOSE),
        (bitcoin::AddressType::P2wpkh, DerivationPath::BIP84_PURPOSE),
        (bitcoin::AddressType::P2tr, DerivationPath::BIP86_PURPOSE),
    ];

    let mut result: HashMap<bitcoin::AddressType, AddressChain> = HashMap::with_capacity(4);
    let end = start_index.saturating_add(count);

    for (addr_type, bip) in formats {
        let mut external = Vec::with_capacity(count as usize);
        let mut internal = Vec::with_capacity(count as usize);

        let derive_one =
            |change: usize, idx: u32| -> std::result::Result<BtcAddressEntry, Bip329Errors> {
                let path = DerivationPath::new(
                    slip44::BITCOIN,
                    DerivationType::AddressIndex(account_index, change, idx as usize),
                    bip,
                );
                let sk = crate::bip32::derive_private_key(seed, &path.get_path())?;
                let pk_bytes = sk.public_key().to_sec1_bytes();
                let address = create_btc_address(&pk_bytes, network, addr_type)
                    .map_err(|e| Bip329Errors::InvalidKey(format!("{:?}", e)))?;
                Ok(BtcAddressEntry {
                    address: Address::Secp256k1Bitcoin(address.to_string().into_bytes()),
                    path,
                    history: Vec::new(),
                })
            };

        for idx in start_index..end {
            external.push(derive_one(0, idx)?);
            internal.push(derive_one(1, idx)?);
        }

        result.insert(addr_type, AddressChain { external, internal });
    }

    Ok(result)
}

impl Serialize for BtcAddressEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BtcAddressEntry", 3)?;
        state.serialize_field("address", &self.address.to_string())?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("history", &self.history)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BtcAddressEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Address,
            Path,
            History,
        }

        struct BtcAddressEntryVisitor;

        impl<'de> de::Visitor<'de> for BtcAddressEntryVisitor {
            type Value = BtcAddressEntry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct BtcAddressEntry")
            }

            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut address: Option<String> = None;
                let mut path: Option<DerivationPath> = None;
                let mut history: Option<Vec<bitcoin::Txid>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Address => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        Field::History => {
                            if history.is_some() {
                                return Err(de::Error::duplicate_field("history"));
                            }
                            history = Some(map.next_value()?);
                        }
                    }
                }

                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let path = path.ok_or_else(|| de::Error::missing_field("path"))?;
                let history = history.unwrap_or_default();

                let addr = Address::from_bitcoin_address(&address)
                    .map_err(|e| de::Error::custom(format!("invalid bitcoin address: {}", e)))?;

                Ok(BtcAddressEntry {
                    address: addr,
                    path,
                    history,
                })
            }
        }

        const FIELDS: &[&str] = &["address", "path", "history"];
        deserializer.deserialize_struct("BtcAddressEntry", FIELDS, BtcAddressEntryVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::bip39::EN_WORDS;
    use pqbip39::mnemonic::Mnemonic;
    use secrecy::SecretString;
    use std::collections::HashSet;
    use std::str::FromStr;
    use test_data::ANVIL_MNEMONIC;

    fn test_seed() -> SecretBox<[u8; 64]> {
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(ANVIL_MNEMONIC)).unwrap();
        mnemonic.to_seed(&SecretString::from("")).unwrap()
    }

    const ALL_TYPES: [bitcoin::AddressType; 4] = [
        bitcoin::AddressType::P2pkh,
        bitcoin::AddressType::P2sh,
        bitcoin::AddressType::P2wpkh,
        bitcoin::AddressType::P2tr,
    ];

    #[test]
    fn test_generate_btc_addresses_default_window() {
        let seed = test_seed();
        let map =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT).unwrap();

        assert_eq!(map.len(), 4);
        for t in ALL_TYPES {
            assert!(map.contains_key(&t), "missing type {:?}", t);
        }

        for chain in map.values() {
            assert_eq!(chain.external.len(), GAP_LIMIT as usize);
            assert_eq!(chain.internal.len(), GAP_LIMIT as usize);
        }

        for (addr_type, chain) in &map {
            let expected_bip = DerivationPath::bip_from_address_type(*addr_type);

            for (change, vec) in [(0usize, &chain.external), (1usize, &chain.internal)] {
                for (position, entry) in vec.iter().enumerate() {
                    assert_eq!(entry.path.slip44, slip44::BITCOIN);
                    assert_eq!(entry.path.bip, expected_bip);
                    assert_eq!(
                        entry.path.derivation,
                        DerivationType::AddressIndex(0, change, position),
                    );
                }
            }
        }

        for (addr_type, chain) in &map {
            let prefix: &str = match addr_type {
                bitcoin::AddressType::P2pkh => "1",
                bitcoin::AddressType::P2sh => "3",
                bitcoin::AddressType::P2wpkh => "bc1q",
                bitcoin::AddressType::P2tr => "bc1p",
                _ => unreachable!(),
            };
            for entry in chain.external.iter().chain(chain.internal.iter()) {
                let s = entry.address.to_string();
                assert!(
                    s.starts_with(prefix),
                    "type={:?} expected prefix {:?}, got {}",
                    addr_type,
                    prefix,
                    s,
                );
            }
        }

        assert_eq!(
            map[&bitcoin::AddressType::P2wpkh].external[0]
                .address
                .to_string(),
            "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te",
        );

        let mut seen: HashSet<String> = HashSet::new();
        for chain in map.values() {
            for entry in chain.external.iter().chain(chain.internal.iter()) {
                seen.insert(entry.address.to_string());
            }
        }
        assert_eq!(seen.len(), 160);

        for (addr_type, chain) in &map {
            assert_ne!(
                chain.external[0].address, chain.internal[0].address,
                "type={:?}: external[0] must differ from internal[0]",
                addr_type,
            );
        }
    }

    #[test]
    fn test_generate_btc_addresses_pagination() {
        let seed = test_seed();
        let page_a =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT).unwrap();
        let page_b =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, GAP_LIMIT, GAP_LIMIT)
                .unwrap();
        let combined =
            generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT * 2).unwrap();

        for addr_type in ALL_TYPES {
            let a = &page_a[&addr_type];
            let b = &page_b[&addr_type];
            let c = &combined[&addr_type];

            for (a_vec, b_vec, c_vec) in [
                (&a.external, &b.external, &c.external),
                (&a.internal, &b.internal, &c.internal),
            ] {
                assert_eq!(a_vec.len(), GAP_LIMIT as usize);
                assert_eq!(b_vec.len(), GAP_LIMIT as usize);
                assert_eq!(c_vec.len(), (GAP_LIMIT * 2) as usize);

                for (i, entry) in a_vec.iter().enumerate() {
                    assert_eq!(entry.address, c_vec[i].address);
                }
                for (i, entry) in b_vec.iter().enumerate() {
                    assert_eq!(entry.address, c_vec[GAP_LIMIT as usize + i].address);
                }
            }

            for (i, entry) in b.external.iter().enumerate() {
                assert_eq!(entry.path.get_index(), GAP_LIMIT as usize + i);
            }
            for (i, entry) in b.internal.iter().enumerate() {
                assert_eq!(entry.path.get_index(), GAP_LIMIT as usize + i);
            }
        }

        let empty = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 0).unwrap();
        assert_eq!(empty.len(), 4);
        for chain in empty.values() {
            assert!(chain.external.is_empty());
            assert!(chain.internal.is_empty());
        }
    }

    fn dummy_txid() -> bitcoin::Txid {
        bitcoin::Txid::from_str("76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f")
            .unwrap()
    }

    #[test]
    fn test_get_external_returns_last_unused() {
        let seed = test_seed();
        let mut map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 3).unwrap();
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        chain.external[0].history = vec![dummy_txid()];

        let result = chain.get_external().unwrap();
        assert_eq!(result.path.get_index(), 2);
        assert!(result.history.is_empty());
    }

    #[test]
    fn test_get_internal_returns_last_unused() {
        let seed = test_seed();
        let mut map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 3).unwrap();
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        chain.internal[0].history = vec![dummy_txid()];
        chain.internal[1].history = vec![dummy_txid()];

        let result = chain.get_internal().unwrap();
        assert_eq!(result.path.get_index(), 2);
        assert!(result.history.is_empty());
    }

    #[test]
    fn test_get_external_errors_when_all_used() {
        let seed = test_seed();
        let mut map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 3).unwrap();
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        for entry in &mut chain.external {
            entry.history = vec![dummy_txid()];
        }

        let err = chain.get_external().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_external_errors_when_empty_chain() {
        let seed = test_seed();
        let map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 0).unwrap();
        let chain = map.get(&bitcoin::AddressType::P2wpkh).unwrap();

        let err = chain.get_external().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_internal_errors_when_all_used() {
        let seed = test_seed();
        let mut map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 3).unwrap();
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        for entry in &mut chain.internal {
            entry.history = vec![dummy_txid()];
        }

        let err = chain.get_internal().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_internal_errors_when_empty_chain() {
        let seed = test_seed();
        let map = generate_btc_addresses(&seed, 0, bitcoin::Network::Bitcoin, 0, 0).unwrap();
        let chain = map.get(&bitcoin::AddressType::P2wpkh).unwrap();

        let err = chain.get_internal().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }
}
