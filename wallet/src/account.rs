use crate::account_type::AccountType;
use crypto::bip49::DerivationPath;
use errors::account::AccountErrors;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use storage::codec::Codec;

type Result<T> = std::result::Result<T, AccountErrors>;

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct AccountV1 {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: PubKey,
    pub chain_hash: u64,
    pub chain_id: u64,
    pub slip_44: u32,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct AccountV2 {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: Option<PubKey>,
}

impl Codec for AccountV1 {}
impl Codec for AccountV2 {}

impl From<AccountV1> for AccountV2 {
    fn from(v1: AccountV1) -> Self {
        let pub_key = match v1.account_type {
            AccountType::Ledger(_) => Some(v1.pub_key),
            _ if v1.slip_44 == crypto::slip44::ZILLIQA => Some(v1.pub_key),
            _ => None,
        };
        Self {
            pub_key,
            name: v1.name,
            account_type: v1.account_type,
            addr: v1.addr,
        }
    }
}

impl AccountV2 {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        <Self as Codec>::from_bytes(encoded).map_err(|e| AccountErrors::BincodeError(e.to_string()))
    }

    pub fn from_ledger(pub_key: PubKey, name: String, index: usize) -> Result<Self> {
        let addr = pub_key.get_addr()?;
        let account_type = AccountType::Ledger(index);
        let pub_key = match pub_key {
            PubKey::Secp256k1Sha256(_) => Some(pub_key),
            _ => None,
        };

        Ok(Self {
            account_type,
            addr,
            name,
            pub_key,
        })
    }

    pub fn from_secret_key(
        sk: SecretKey,
        name: String,
        storage_key: usize,
        slip44: u32,
    ) -> Result<Self> {
        let keypair = KeyPair::from_secret_key(sk)?;
        let addr = keypair.get_addr()?;
        let pub_key = if slip44 == crypto::slip44::ZILLIQA {
            Some(keypair.get_pubkey()?)
        } else {
            None
        };
        let account_type = AccountType::PrivateKey(storage_key);

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
        })
    }

    pub fn from_hd(
        mnemonic_seed: &SecretBox<[u8; 64]>,
        name: String,
        bip49: &DerivationPath,
        net: Option<bitcoin::Network>,
    ) -> Result<Self> {
        let keypair = KeyPair::from_bip39_seed(mnemonic_seed, bip49, net)?;
        let addr = keypair.get_addr()?;
        let pub_key = if bip49.slip44 == crypto::slip44::ZILLIQA {
            Some(keypair.get_pubkey()?)
        } else {
            None
        };
        let account_type = AccountType::Bip39HD(bip49.get_index());

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Codec::to_bytes(self).map_err(|e| AccountErrors::BincodeError(e.to_string()))
    }

    pub fn get_zilliqa_addr_pair(&self) -> Result<(Address, Address)> {
        if let Some(pk) = &self.pub_key {
            match pk {
                PubKey::Secp256k1Sha256(bytes) => {
                    let zil_addr = pk.get_addr()?;
                    let eth_addr = PubKey::Secp256k1Keccak256(*bytes).get_addr()?;

                    Ok((zil_addr, eth_addr))
                }
                PubKey::Secp256k1Keccak256(bytes) => {
                    let eth_addr = pk.get_addr()?;
                    let zil_addr = PubKey::Secp256k1Sha256(*bytes).get_addr()?;

                    Ok((zil_addr, eth_addr))
                }
                _ => Err(AccountErrors::InvalidPubKeyType),
            }
        } else {
            Err(AccountErrors::InvalidPubKeyType)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{address::ADDR_LEN, bip39::EN_WORDS};
    use crypto::slip44;
    use pqbip39::mnemonic::Mnemonic;
    use rand::Rng;
    use secrecy::SecretString;

    #[test]
    fn test_from_zil_sk_ser() {
        let mut rng = rand::rng();

        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let acc = AccountV2::from_secret_key(sk, name.to_string(), 0, slip44::ZILLIQA).unwrap();

        for _ in 0..100 {
            let mut nft_addr = [0u8; ADDR_LEN];
            let mut ft_addr = [0u8; ADDR_LEN];

            rng.fill_bytes(&mut nft_addr);
            rng.fill_bytes(&mut ft_addr);
        }

        let buf = acc.to_bytes().unwrap();
        let res = AccountV2::from_bytes(&buf).unwrap();

        assert_eq!(res.pub_key, acc.pub_key);
        assert_eq!(res.addr, acc.addr);
        assert_eq!(res, acc);
    }

    #[test]
    fn test_init_from_bip39() {
        let mut rng = rand::rng();

        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let name = "Account 0";
        let m = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(mnemonic_str)).unwrap();
        let bip49 = DerivationPath::new(
            slip44::ZILLIQA,
            crypto::bip49::DerivationType::AddressIndex(0, 0, 0),
            DerivationPath::BIP44_PURPOSE,
        );
        let seed = m.to_seed(&SecretString::from("")).unwrap();
        let acc = AccountV2::from_hd(&seed, name.to_owned(), &bip49, None).unwrap();

        for _ in 0..100 {
            let mut nft_addr = [0u8; ADDR_LEN];
            let mut ft_addr = [0u8; ADDR_LEN];

            rng.fill_bytes(&mut nft_addr);
            rng.fill_bytes(&mut ft_addr);
        }

        let buf = acc.to_bytes().unwrap();
        let res = AccountV2::from_bytes(&buf).unwrap();

        assert_eq!(res.pub_key, acc.pub_key);
        assert_eq!(res.addr, acc.addr);
        assert_eq!(res, acc);
    }

    #[test]
    fn test_from_btc_sk() {
        use test_data::anvil_accounts::PRIVATE_KEY_0;

        let sk_hex = PRIVATE_KEY_0.trim_start_matches("0x");
        let sk_bytes_vec = hex::decode(sk_hex).unwrap();
        let sk_bytes: [u8; 32] = sk_bytes_vec.try_into().unwrap();

        let sk_segwit = SecretKey::Secp256k1Bitcoin((
            sk_bytes,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));

        let acc_segwit =
            AccountV2::from_secret_key(sk_segwit, "Bitcoin SegWit".to_string(), 0, slip44::BITCOIN)
                .unwrap();

        let addr_str = acc_segwit.addr.auto_format();
        assert!(addr_str.starts_with("bc1q"));

        let sk_legacy = SecretKey::Secp256k1Bitcoin((
            sk_bytes,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2pkh,
        ));

        let acc_legacy =
            AccountV2::from_secret_key(sk_legacy, "Bitcoin Legacy".to_string(), 0, slip44::BITCOIN)
                .unwrap();

        let addr_legacy_str = acc_legacy.addr.auto_format();
        assert!(addr_legacy_str.starts_with("1"));

        let sk_taproot = SecretKey::Secp256k1Bitcoin((
            sk_bytes,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2tr,
        ));

        let acc_taproot = AccountV2::from_secret_key(
            sk_taproot,
            "Bitcoin Taproot".to_string(),
            0,
            slip44::BITCOIN,
        )
        .unwrap();

        let addr_taproot_str = acc_taproot.addr.auto_format();
        assert!(addr_taproot_str.starts_with("bc1p"));

        let buf = acc_segwit.to_bytes().unwrap();
        let res = AccountV2::from_bytes(&buf).unwrap();

        assert_eq!(res.addr, acc_segwit.addr);
        assert_eq!(res, acc_segwit);
    }
}
