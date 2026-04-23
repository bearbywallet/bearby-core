use std::fmt;

use errors::bip32::Bip329Errors;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DerivationType {
    Root,
    Account(usize),
    AccountChange(usize, usize),
    AddressIndex(usize, usize, usize),
}

#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    pub slip44: u32,
    pub bip: u32,
    pub derivation: DerivationType,
}

pub fn split_path(path: &str) -> Result<Vec<u32>, Bip329Errors> {
    if path.is_empty() {
        return Ok(Vec::new());
    }

    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|component| {
            let (numeric_part, is_hardened) = if let Some(stripped) = component.strip_suffix('\'') {
                (stripped, true)
            } else {
                (component, false)
            };

            let mut value = numeric_part
                .parse::<u32>()
                .map_err(|_| Bip329Errors::InvalidComponent(component.to_string()))?;

            if is_hardened {
                value = value.wrapping_add(0x80000000);
            }

            Ok(value)
        })
        .collect()
}

pub fn components_to_derivation_path(components: &[u32]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(1 + components.len() * 4);

    buffer.push(components.len() as u8);

    for component in components {
        buffer.extend_from_slice(&component.to_be_bytes());
    }

    buffer
}

impl DerivationPath {
    pub const HARDENED: u32 = 0x80000000;
    pub const BIP44_PURPOSE: u32 = 44;
    pub const BIP49_PURPOSE: u32 = 49;
    pub const BIP84_PURPOSE: u32 = 84;
    pub const BIP86_PURPOSE: u32 = 86;

    pub fn with_index(slip44: u32, params: (usize, usize, usize)) -> Self {
        let derivation = match slip44 {
            super::slip44::SOLANA => DerivationType::AccountChange(params.2, 0),
            _ => DerivationType::AddressIndex(params.0, params.1, params.2),
        };
        let bip = match slip44 {
            super::slip44::BITCOIN => Self::BIP86_PURPOSE,
            _ => Self::BIP44_PURPOSE,
        };

        Self {
            slip44,
            bip,
            derivation,
        }
    }

    pub fn new(slip44: u32, derivation: DerivationType, bip: u32) -> Self {
        Self {
            slip44,
            bip,
            derivation,
        }
    }

    pub fn get_path(&self) -> String {
        match self.derivation {
            DerivationType::Root => {
                format!("m/{}'/{}'", self.bip, self.slip44)
            }
            DerivationType::Account(idx) => {
                format!("m/{}'/{}'/{}'", self.bip, self.slip44, idx)
            }
            DerivationType::AccountChange(account, change) => {
                format!("m/{}'/{}'/{}'/{}'", self.bip, self.slip44, account, change)
            }
            DerivationType::AddressIndex(account, change, index) => {
                format!(
                    "m/{}'/{}'/{}'/{}/{}",
                    self.bip, self.slip44, account, change, index
                )
            }
        }
    }

    pub fn get_index(&self) -> usize {
        match self.derivation {
            DerivationType::Root => 0,
            DerivationType::Account(idx) => idx,
            DerivationType::AccountChange(account, _) => account,
            DerivationType::AddressIndex(_, _, index) => index,
        }
    }

    pub fn get_address_type(&self) -> bitcoin::AddressType {
        match self.bip {
            Self::BIP44_PURPOSE => bitcoin::AddressType::P2pkh,
            Self::BIP49_PURPOSE => bitcoin::AddressType::P2sh,
            Self::BIP84_PURPOSE => bitcoin::AddressType::P2wpkh,
            Self::BIP86_PURPOSE => bitcoin::AddressType::P2tr,
            _ => bitcoin::AddressType::P2wpkh,
        }
    }

    pub fn default_bip(slip44: u32) -> u32 {
        match slip44 {
            super::slip44::BITCOIN => Self::BIP86_PURPOSE,
            _ => Self::BIP44_PURPOSE,
        }
    }

    pub fn bip_from_address_type(address_type: bitcoin::AddressType) -> u32 {
        match address_type {
            bitcoin::AddressType::P2pkh => Self::BIP44_PURPOSE,
            bitcoin::AddressType::P2sh => Self::BIP49_PURPOSE,
            bitcoin::AddressType::P2wpkh => Self::BIP84_PURPOSE,
            bitcoin::AddressType::P2tr => Self::BIP86_PURPOSE,
            _ => Self::BIP44_PURPOSE,
        }
    }
}

impl TryFrom<&str> for DerivationPath {
    type Error = Bip329Errors;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let tail = path
            .strip_prefix("m/")
            .ok_or_else(|| Bip329Errors::InvalidPath(path.to_string()))?;
        let components = split_path(tail)?;

        if components.len() < 2 {
            return Err(Bip329Errors::InvalidPath(path.to_string()));
        }

        let bip = components[0] & !Self::HARDENED;
        let slip44 = components[1] & !Self::HARDENED;

        let derivation = match &components[2..] {
            [] => DerivationType::Root,
            [a] => DerivationType::Account((a & !Self::HARDENED) as usize),
            [a, c] => DerivationType::AccountChange(
                (a & !Self::HARDENED) as usize,
                (c & !Self::HARDENED) as usize,
            ),
            [a, c, i, ..] => DerivationType::AddressIndex(
                (a & !Self::HARDENED) as usize,
                (c & !Self::HARDENED) as usize,
                (i & !Self::HARDENED) as usize,
            ),
        };

        Ok(Self {
            slip44,
            bip,
            derivation,
        })
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slip44;

    #[test]
    fn test_ethereum_path() {
        let eth_path = DerivationPath::new(
            slip44::ETHEREUM,
            DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_zilliqa_path() {
        let zil_path = DerivationPath::new(
            slip44::ZILLIQA,
            DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        assert_eq!(zil_path.get_path(), "m/44'/313'/0'/0/0");
    }

    #[test]
    fn test_different_indexes() {
        let eth_path = DerivationPath::new(
            slip44::ETHEREUM,
            DerivationType::AddressIndex(0, 0, 5),
            DerivationPath::BIP44_PURPOSE,
        );
        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/5");
        assert_eq!(eth_path.get_index(), 5);
    }

    #[test]
    fn test_display() {
        let eth_path = DerivationPath::new(
            slip44::ETHEREUM,
            DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        assert_eq!(eth_path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_split_path_logic() {
        assert_eq!(
            split_path("44'/60'/123/456/789").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
                123,
                456,
                789,
            ]
        );

        assert_eq!(
            split_path("44'/60'/0'/0/0").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
                0u32.wrapping_add(0x80000000),
                0,
                0,
            ]
        );

        assert_eq!(split_path("0/1/2").unwrap(), vec![0, 1, 2]);

        assert_eq!(split_path("").unwrap(), vec![]);

        assert_eq!(
            split_path("44'//60'").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
            ]
        );

        let err = split_path("44'/abc/0").unwrap_err();
        assert_eq!(err, Bip329Errors::InvalidComponent("abc".to_string()));

        let err = split_path("4294967296").unwrap_err();
        assert_eq!(
            err,
            Bip329Errors::InvalidComponent("4294967296".to_string())
        );
    }

    #[test]
    fn test_components_to_derivation_path() {
        let components_eth = vec![
            44u32.wrapping_add(0x80000000), // 44'
            60u32.wrapping_add(0x80000000), // 60'
            0u32.wrapping_add(0x80000000),  // 0'
            0,
            0,
        ];
        let buffer_eth = components_to_derivation_path(&components_eth);
        let expected_hex_eth = "058000002c8000003c800000000000000000000000";
        assert_eq!(
            hex::encode(buffer_eth),
            expected_hex_eth,
            "Standard ETH path failed"
        );

        let components_empty: Vec<u32> = vec![];
        let buffer_empty = components_to_derivation_path(&components_empty);
        let expected_hex_empty = "00";
        assert_eq!(
            hex::encode(buffer_empty),
            expected_hex_empty,
            "Empty path failed"
        );

        let components_non_hardened = vec![0, 1, 2];
        let buffer_non_hardened = components_to_derivation_path(&components_non_hardened);
        let expected_hex_non_hardened = "03000000000000000100000002";
        assert_eq!(
            hex::encode(buffer_non_hardened),
            expected_hex_non_hardened,
            "Non-hardened path failed"
        );

        let components_single_hardened = vec![123u32.wrapping_add(0x80000000)];
        let buffer_single_hardened = components_to_derivation_path(&components_single_hardened);
        let expected_hex_single_hardened = "018000007b";
        assert_eq!(
            hex::encode(buffer_single_hardened),
            expected_hex_single_hardened,
            "Single hardened path failed"
        );
    }

    #[test]
    fn test_solana_root_path() {
        let path = DerivationPath::new(
            slip44::SOLANA,
            DerivationType::Root,
            DerivationPath::BIP44_PURPOSE,
        );
        assert_eq!(path.get_path(), "m/44'/501'");
    }

    #[test]
    fn test_solana_account_paths() {
        for i in 0..10 {
            let path = DerivationPath::new(
                slip44::SOLANA,
                DerivationType::Account(i),
                DerivationPath::BIP44_PURPOSE,
            );
            assert_eq!(path.get_path(), format!("m/44'/501'/{}'", i));
            assert_eq!(path.get_index(), i);
        }
    }

    #[test]
    fn test_solana_account_change_paths() {
        for i in 0..10 {
            let path = DerivationPath::new(
                slip44::SOLANA,
                DerivationType::AccountChange(i, 0),
                DerivationPath::BIP44_PURPOSE,
            );
            assert_eq!(path.get_path(), format!("m/44'/501'/{}'/0'", i));
            assert_eq!(path.get_index(), i);
        }
    }

    #[test]
    fn test_try_from_round_trip() {
        let cases = [
            DerivationPath::new(
                slip44::SOLANA,
                DerivationType::Root,
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::SOLANA,
                DerivationType::Account(0),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::SOLANA,
                DerivationType::Account(5),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::SOLANA,
                DerivationType::AccountChange(0, 0),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::SOLANA,
                DerivationType::AccountChange(3, 1),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::ETHEREUM,
                DerivationType::AddressIndex(0, 0, 0),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::ETHEREUM,
                DerivationType::AddressIndex(0, 0, 5),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::ETHEREUM,
                DerivationType::AddressIndex(1, 0, 10),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::ZILLIQA,
                DerivationType::AddressIndex(0, 0, 0),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::TRON,
                DerivationType::AddressIndex(0, 0, 3),
                DerivationPath::BIP44_PURPOSE,
            ),
            DerivationPath::new(
                slip44::BITCOIN,
                DerivationType::AddressIndex(0, 0, 0),
                DerivationPath::BIP86_PURPOSE,
            ),
            DerivationPath::new(
                slip44::BITCOIN,
                DerivationType::AddressIndex(0, 0, 0),
                DerivationPath::BIP49_PURPOSE,
            ),
            DerivationPath::new(
                slip44::BITCOIN,
                DerivationType::AddressIndex(0, 0, 0),
                DerivationPath::BIP84_PURPOSE,
            ),
        ];

        for dp in &cases {
            let parsed = DerivationPath::try_from(dp.get_path().as_str()).unwrap();
            assert_eq!(parsed.bip, dp.bip);
            assert_eq!(parsed.slip44, dp.slip44);
            assert_eq!(parsed.derivation, dp.derivation);
        }
    }

    #[test]
    fn test_try_from_specific_paths() {
        let dp = DerivationPath::try_from("m/44'/501'").unwrap();
        assert_eq!(dp.bip, 44);
        assert_eq!(dp.slip44, slip44::SOLANA);
        assert_eq!(dp.derivation, DerivationType::Root);

        let dp = DerivationPath::try_from("m/44'/501'/0'").unwrap();
        assert_eq!(dp.derivation, DerivationType::Account(0));

        let dp = DerivationPath::try_from("m/44'/501'/7'").unwrap();
        assert_eq!(dp.derivation, DerivationType::Account(7));

        let dp = DerivationPath::try_from("m/44'/501'/0'/0'").unwrap();
        assert_eq!(dp.derivation, DerivationType::AccountChange(0, 0));

        let dp = DerivationPath::try_from("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(dp.derivation, DerivationType::AddressIndex(0, 0, 0));

        let dp = DerivationPath::try_from("m/44'/60'/0'/0/99").unwrap();
        assert_eq!(dp.derivation, DerivationType::AddressIndex(0, 0, 99));

        let dp = DerivationPath::try_from("m/86'/0'/0'/0/0").unwrap();
        assert_eq!(dp.bip, 86);
        assert_eq!(dp.slip44, slip44::BITCOIN);
        assert_eq!(dp.derivation, DerivationType::AddressIndex(0, 0, 0));
    }

    #[test]
    fn test_try_from_errors() {
        assert!(DerivationPath::try_from("").is_err());
        assert!(DerivationPath::try_from("bad").is_err());
        assert!(DerivationPath::try_from("44'/60'/0'").is_err());
        assert!(DerivationPath::try_from("m/44'").is_err());
        assert!(DerivationPath::try_from("m/44'/abc/0'").is_err());
        assert!(DerivationPath::try_from("m/44'/60'/0'/0/overflow99999999999").is_err());
    }
}
