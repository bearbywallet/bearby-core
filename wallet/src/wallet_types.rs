use errors::wallet::WalletErrors;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use storage::codec::Codec;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum WalletTypes {
    Ledger(Vec<u8>), // Ledger product_id or uuid
    // Cipher for entropy secret words storage_key / passphrase
    SecretPhrase((usize, bool)),
    SecretKey,
}

impl Codec for WalletTypes {}

impl WalletTypes {
    pub fn code(&self) -> u8 {
        match self {
            Self::Ledger(_) => 0,
            Self::SecretPhrase(_) => 1,
            Self::SecretKey => 2,
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            Self::Ledger(bytes) => format!("ledger.{:?}", String::from_utf8_lossy(bytes)),
            Self::SecretPhrase((_, pass)) => format!("SecretPhrase.{:?}", pass),
            Self::SecretKey => "SecretKey".to_string(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletErrors> {
        Codec::to_bytes(self).map_err(|e| WalletErrors::WalletTypeSerialize(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletErrors> {
        <Self as Codec>::from_bytes(bytes)
            .map_err(|e| WalletErrors::WalletTypeDeserialize(e.to_string()))
    }
}

impl std::fmt::Display for WalletTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: unwrap should ever call in prod!
        let hex_str = hex::encode(self.to_bytes().unwrap());
        write!(f, "{}", hex_str)
    }
}

impl FromStr for WalletTypes {
    type Err = WalletErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| WalletErrors::InvalidHexToWalletType)?;

        WalletTypes::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests_wallet_type {
    use rand::Rng;

    use super::*;

    #[test]
    fn tests_wallet_type_convert() {
        let mut rng = rand::rng();
        let mut ledger_uuid = vec![0u8; 128];

        rng.fill_bytes(&mut ledger_uuid);

        let ledger_type = WalletTypes::Ledger(ledger_uuid);
        let secret_phrase_type = WalletTypes::SecretPhrase((69, true));
        let secret_key_type = WalletTypes::SecretKey;

        let ledger_type_bytes = ledger_type.to_bytes().unwrap();
        let secret_phrase_type_bytes = secret_phrase_type.to_bytes().unwrap();
        let secret_key_type_bytes = secret_key_type.to_bytes().unwrap();

        let res_ledger_type = WalletTypes::from_bytes(&ledger_type_bytes).unwrap();
        let res_secret_phrase_type = WalletTypes::from_bytes(&secret_phrase_type_bytes).unwrap();
        let res_secret_key_type = WalletTypes::from_bytes(&secret_key_type_bytes).unwrap();

        assert_eq!(res_ledger_type, ledger_type);
        assert_eq!(res_secret_phrase_type, secret_phrase_type);
        assert_eq!(res_secret_key_type, res_secret_key_type);

        let ledger_type_hex = ledger_type.to_string();
        let secret_phrase_type_hex = secret_phrase_type.to_string();
        let secret_key_type_hex = secret_key_type.to_string();

        let res_ledger_type = WalletTypes::from_str(&ledger_type_hex).unwrap();
        let res_secret_phrase_type = WalletTypes::from_str(&secret_phrase_type_hex).unwrap();
        let res_secret_key_type = WalletTypes::from_str(&secret_key_type_hex).unwrap();

        assert_eq!(res_ledger_type, ledger_type);
        assert_eq!(res_secret_phrase_type, secret_phrase_type);
        assert_eq!(res_secret_key_type, res_secret_key_type);
    }
}
