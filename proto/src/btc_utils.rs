use config::sha::SHA512_SIZE;
use crypto::bip49::{DerivationPath, DerivationType};
use crypto::slip44;
use errors::bip32::Bip329Errors;
use errors::keypair::PubKeyError;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::address::Address;

type Result<T> = std::result::Result<T, PubKeyError>;

pub const GAP_LIMIT: u32 = 20;
pub const POOL_SIZE_EXTERNAL: u32 = 100;
const POOL_LOW_WATERMARK: usize = GAP_LIMIT as usize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcAccountXpubsInput {
    pub bip44_xpub: bitcoin::bip32::Xpub,
    pub bip49_xpub: bitcoin::bip32::Xpub,
    pub bip84_xpub: bitcoin::bip32::Xpub,
    pub bip86_xpub: bitcoin::bip32::Xpub,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
}

impl From<electrum_client::ListUnspentRes> for Utxo {
    fn from(res: electrum_client::ListUnspentRes) -> Self {
        Self {
            txid: res.tx_hash,
            vout: u32::try_from(res.tx_pos).unwrap_or(u32::MAX),
            value: res.value,
            height: u32::try_from(res.height).unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BtcAddressEntry {
    pub address: Address,
    pub path: DerivationPath,
    pub history: Vec<bitcoin::Txid>,
    pub utxos: Vec<Utxo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddressChain {
    pub external: Vec<BtcAddressEntry>,
    pub internal: Vec<BtcAddressEntry>,
}

impl AddressChain {
    #[must_use]
    pub fn unused_external_count(&self) -> usize {
        self.external.iter().filter(|e| e.history.is_empty()).count()
    }

    #[must_use]
    pub fn unused_internal_count(&self) -> usize {
        self.internal.iter().filter(|e| e.history.is_empty()).count()
    }

    #[must_use]
    pub fn pool_watermark_reached(&self) -> bool {
        self.unused_external_count() < POOL_LOW_WATERMARK
            || self.unused_internal_count() < POOL_LOW_WATERMARK / 2
    }

    pub fn get_external(&self) -> Result<&BtcAddressEntry> {
        self.external
            .iter()
            .filter(|e| e.history.is_empty())
            .min_by_key(|e| e.path.get_address_index())
            .ok_or(PubKeyError::NoUnusedAddress)
    }

    pub fn get_internal(&self) -> Result<&BtcAddressEntry> {
        self.internal
            .iter()
            .filter(|e| e.history.is_empty())
            .min_by_key(|e| e.path.get_address_index())
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
            &_ => u8::MAX,
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
            use bitcoin::secp256k1::{SECP256K1, XOnlyPublicKey};
            let x_only_pk = XOnlyPublicKey::from(compressed_pk.0);
            let secp = &SECP256K1;
            bitcoin::Address::p2tr(secp, x_only_pk, None, hrp)
        }
        _ => return Err(PubKeyError::InvalidKeyType),
    };

    Ok(addr)
}

impl BtcAccountXpubsInput {
    pub fn from_seed(
        seed: &SecretBox<[u8; SHA512_SIZE]>,
        account_index: u32,
        network: bitcoin::Network,
    ) -> std::result::Result<Self, Bip329Errors> {
        use bitcoin::bip32::{ChildNumber, DerivationPath as BtcPath, Xpriv, Xpub};
        use bitcoin::secp256k1::SECP256K1;
        use secrecy::ExposeSecret;

        let secp = &SECP256K1;
        let master = Xpriv::new_master(network, seed.expose_secret())
            .map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?;

        let account_path = |purpose: u32| -> std::result::Result<BtcPath, Bip329Errors> {
            let parts = [
                ChildNumber::from_hardened_idx(purpose)
                    .map_err(|e| Bip329Errors::InvalidChild(e.to_string()))?,
                ChildNumber::from_hardened_idx(slip44::BITCOIN)
                    .map_err(|e| Bip329Errors::InvalidChild(e.to_string()))?,
                ChildNumber::from_hardened_idx(account_index)
                    .map_err(|e| Bip329Errors::InvalidChild(e.to_string()))?,
            ];
            Ok(BtcPath::from(&parts[..]))
        };

        let derive = |purpose: u32| -> std::result::Result<Xpub, Bip329Errors> {
            let path = account_path(purpose)?;
            let xpriv = master
                .derive_priv(secp, &path)
                .map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?;
            Ok(Xpub::from_priv(secp, &xpriv))
        };

        Ok(Self {
            bip44_xpub: derive(DerivationPath::BIP44_PURPOSE)?,
            bip49_xpub: derive(DerivationPath::BIP49_PURPOSE)?,
            bip84_xpub: derive(DerivationPath::BIP84_PURPOSE)?,
            bip86_xpub: derive(DerivationPath::BIP86_PURPOSE)?,
        })
    }

    pub fn xpub_for(&self, addr_type: bitcoin::AddressType) -> Option<&bitcoin::bip32::Xpub> {
        match addr_type {
            bitcoin::AddressType::P2pkh => Some(&self.bip44_xpub),
            bitcoin::AddressType::P2sh => Some(&self.bip49_xpub),
            bitcoin::AddressType::P2wpkh => Some(&self.bip84_xpub),
            bitcoin::AddressType::P2tr => Some(&self.bip86_xpub),
            _ => None,
        }
    }
}

pub fn derive_btc_chain_from_xpub(
    account_xpub: &bitcoin::bip32::Xpub,
    account_index: usize,
    addr_type: bitcoin::AddressType,
    network: bitcoin::Network,
    start_index: u32,
    count: u32,
    chain: &mut AddressChain,
) -> std::result::Result<(), Bip329Errors> {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::secp256k1::SECP256K1;

    let secp = &SECP256K1;
    let bip = DerivationPath::bip_from_address_type(addr_type);
    let end = start_index.saturating_add(count);

    let external_xpub = account_xpub
        .ckd_pub(secp, ChildNumber::Normal { index: 0 })
        .map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?;
    let internal_xpub = account_xpub
        .ckd_pub(secp, ChildNumber::Normal { index: 1 })
        .map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?;

    chain.external.reserve(count as usize);
    chain.internal.reserve(count as usize);

    let make_entry = |branch_xpub: &bitcoin::bip32::Xpub,
                      change: usize,
                      idx: u32|
     -> std::result::Result<BtcAddressEntry, Bip329Errors> {
        let child = branch_xpub
            .ckd_pub(secp, ChildNumber::Normal { index: idx })
            .map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?;
        let pk_bytes = child.public_key.serialize();
        let address = create_btc_address(&pk_bytes, network, addr_type)
            .map_err(|e| Bip329Errors::InvalidKey(format!("{:?}", e)))?;
        let path = DerivationPath::new(
            slip44::BITCOIN,
            DerivationType::AddressIndex(account_index, change, idx as usize),
            bip,
        );
        Ok(BtcAddressEntry {
            address: Address::Secp256k1Bitcoin(address.to_string().into_bytes()),
            path,
            history: Vec::new(),
            utxos: Vec::new(),
        })
    };

    for idx in start_index..end {
        chain.external.push(make_entry(&external_xpub, 0, idx)?);
        chain.internal.push(make_entry(&internal_xpub, 1, idx)?);
    }
    Ok(())
}

pub fn extend_address_pool(
    chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
    xpubs: &BtcAccountXpubsInput,
    account_index: usize,
    network: bitcoin::Network,
) -> std::result::Result<(), Bip329Errors> {
    const TYPES: [bitcoin::AddressType; 4] = [
        bitcoin::AddressType::P2pkh,
        bitcoin::AddressType::P2sh,
        bitcoin::AddressType::P2wpkh,
        bitcoin::AddressType::P2tr,
    ];

    for addr_type in TYPES {
        let Some(chain) = chains.get_mut(&addr_type) else {
            continue;
        };
        let start_index = u32::try_from(chain.external.len())
            .map_err(|_| Bip329Errors::InvalidKey("address pool overflow".to_string()))?;
        let xpub = xpubs
            .xpub_for(addr_type)
            .ok_or_else(|| {
                Bip329Errors::InvalidKey(format!("no xpub for {addr_type:?}"))
            })?;
        derive_btc_chain_from_xpub(
            xpub,
            account_index,
            addr_type,
            network,
            start_index,
            POOL_SIZE_EXTERNAL,
            chain,
        )?;
    }
    Ok(())
}

pub fn derive_btc_addresses_from_xpubs(
    xpubs: &BtcAccountXpubsInput,
    account_index: usize,
    network: bitcoin::Network,
    start_index: u32,
    count: u32,
    chains: &mut HashMap<bitcoin::AddressType, AddressChain>,
) -> std::result::Result<(), Bip329Errors> {
    const TYPES: [bitcoin::AddressType; 4] = [
        bitcoin::AddressType::P2pkh,
        bitcoin::AddressType::P2sh,
        bitcoin::AddressType::P2wpkh,
        bitcoin::AddressType::P2tr,
    ];

    for addr_type in TYPES {
        let xpub = xpubs
            .xpub_for(addr_type)
            .ok_or_else(|| {
                Bip329Errors::InvalidKey(format!("no xpub for {addr_type:?}"))
            })?;
        let chain = chains.entry(addr_type).or_insert_with(|| AddressChain {
            external: Vec::new(),
            internal: Vec::new(),
        });
        derive_btc_chain_from_xpub(
            xpub,
            account_index,
            addr_type,
            network,
            start_index,
            count,
            chain,
        )?;
    }
    Ok(())
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

    fn test_xpubs() -> (BtcAccountXpubsInput, SecretBox<[u8; 64]>) {
        let seed = test_seed();
        let xpubs = BtcAccountXpubsInput::from_seed(&seed, 0, bitcoin::Network::Bitcoin).unwrap();
        (xpubs, seed)
    }

    fn generate_test_addresses(
        xpubs: &BtcAccountXpubsInput,
        account_index: usize,
        network: bitcoin::Network,
        start_index: u32,
        count: u32,
    ) -> HashMap<bitcoin::AddressType, AddressChain> {
        let mut map = HashMap::new();
        derive_btc_addresses_from_xpubs(
            xpubs,
            account_index,
            network,
            start_index,
            count,
            &mut map,
        )
        .unwrap();
        map
    }

    const ALL_TYPES: [bitcoin::AddressType; 4] = [
        bitcoin::AddressType::P2pkh,
        bitcoin::AddressType::P2sh,
        bitcoin::AddressType::P2wpkh,
        bitcoin::AddressType::P2tr,
    ];

    #[test]
    fn test_generate_btc_addresses_default_window() {
        let (xpubs, _) = test_xpubs();
        let map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, GAP_LIMIT);

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
        let (xpubs, _) = test_xpubs();
        let net = bitcoin::Network::Bitcoin;
        let page_a = generate_test_addresses(&xpubs, 0, net, 0, GAP_LIMIT);
        let page_b = generate_test_addresses(&xpubs, 0, net, GAP_LIMIT, GAP_LIMIT);
        let combined = generate_test_addresses(&xpubs, 0, net, 0, GAP_LIMIT * 2);

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
        }

        let empty = generate_test_addresses(&xpubs, 0, net, 0, 0);
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
    fn test_get_external_returns_first_unused() {
        let (xpubs, _) = test_xpubs();
        let mut map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 3);
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        chain.external[0].history = vec![dummy_txid()];

        let result = chain.get_external().unwrap();
        assert_eq!(result.path.get_address_index(), Some(1));
        assert!(result.history.is_empty());
    }

    #[test]
    fn test_get_internal_returns_first_unused() {
        let (xpubs, _) = test_xpubs();
        let mut map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 3);
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        chain.internal[0].history = vec![dummy_txid()];
        chain.internal[1].history = vec![dummy_txid()];

        let result = chain.get_internal().unwrap();
        assert_eq!(result.path.get_address_index(), Some(2));
        assert!(result.history.is_empty());
    }

    #[test]
    fn test_get_external_picks_lowest_index_among_multiple_unused() {
        let (xpubs, _) = test_xpubs();
        let mut map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 5);
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        let result = chain.get_external().unwrap();
        assert_eq!(result.path.get_address_index(), Some(0));
    }

    #[test]
    fn test_get_external_errors_when_all_used() {
        let (xpubs, _) = test_xpubs();
        let mut map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 3);
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        for entry in &mut chain.external {
            entry.history = vec![dummy_txid()];
        }

        let err = chain.get_external().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_external_errors_when_empty_chain() {
        let (xpubs, _) = test_xpubs();
        let map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 0);
        let chain = map.get(&bitcoin::AddressType::P2wpkh).unwrap();

        let err = chain.get_external().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_internal_errors_when_all_used() {
        let (xpubs, _) = test_xpubs();
        let mut map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 3);
        let chain = map.get_mut(&bitcoin::AddressType::P2wpkh).unwrap();

        for entry in &mut chain.internal {
            entry.history = vec![dummy_txid()];
        }

        let err = chain.get_internal().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }

    #[test]
    fn test_get_internal_errors_when_empty_chain() {
        let (xpubs, _) = test_xpubs();
        let map = generate_test_addresses(&xpubs, 0, bitcoin::Network::Bitcoin, 0, 0);
        let chain = map.get(&bitcoin::AddressType::P2wpkh).unwrap();

        let err = chain.get_internal().unwrap_err();
        assert_eq!(err, PubKeyError::NoUnusedAddress);
    }
}
