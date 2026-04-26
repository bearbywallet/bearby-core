use errors::storage::LocalStorageError;
use std::borrow::Cow;
use std::mem::size_of;

type Result<T> = std::result::Result<T, LocalStorageError>;

#[derive(Debug)]
pub struct DataWarp {
    pub payload: Vec<u8>,
    // Storage verions
    pub version: u16,
}

impl PartialEq for DataWarp {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl DataWarp {
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let mut bytes: Vec<u8> =
            Vec::with_capacity(size_of::<usize>() + payload_len + size_of::<u16>());

        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.version.to_le_bytes());

        bytes
    }

    pub fn from_bytes(bytes: Cow<[u8]>) -> Result<Self> {
        if bytes.len() < size_of::<usize>() + size_of::<u16>() {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());

        let payload_len = usize::from_le_bytes(
            len_bytes
                .as_ref()
                .try_into()
                .map_err(|_| LocalStorageError::PayloadLengthError)?,
        );
        let remains_len = payload_len
            .checked_add(size_of::<u16>())
            .ok_or(LocalStorageError::InvalidBytesSizeOverflow)?;

        if rest.len() < remains_len {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (payload, version_bytes) = rest.split_at(payload_len);
        let version = u16::from_le_bytes(
            version_bytes[..size_of::<u16>()]
                .try_into()
                .or(Err(LocalStorageError::PayloadVersionParseError))?,
        );

        Ok(Self {
            payload: payload.to_vec(),
            version,
        })
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_datawarp_serialization_deserialization() {
        let data = DataWarp {
            payload: b"Hello, World!".to_vec(),
            version: 1,
        };

        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), size_of::<usize>() + 13 + size_of::<u16>());

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());
        assert_eq!(usize::from_le_bytes(len_bytes.try_into().unwrap()), 13);

        let (payload_bytes, version_bytes) = rest.split_at(13);
        assert_eq!(payload_bytes, b"Hello, World!");
        assert_eq!(u16::from_le_bytes(version_bytes.try_into().unwrap()), 1);

        let res_data: DataWarp = DataWarp::from_bytes(bytes.into()).unwrap();

        assert_eq!(res_data, data);
    }

    #[test]
    fn test_datawarp_roundtrip() {
        let original = DataWarp {
            payload: b"Test data".to_vec(),
            version: 42,
        };

        let bytes = original.to_bytes();
        let deserialized = DataWarp::from_bytes(bytes.into()).unwrap();

        assert_eq!(original.payload, deserialized.payload);
        assert_eq!(original.version, deserialized.version);
    }

    #[test]
    fn test_datawarp_invalid_payload() {
        let invalid_bytes = vec![255; 10]; // Invalid UTF-8
        let result = DataWarp::from_bytes(invalid_bytes.into());

        assert!(matches!(
            result,
            Err(LocalStorageError::InvalidBytesSizeOverflow)
        ));
    }

    #[test]
    fn test_datawarp_invalid_version() {
        let mut bytes = b"Valid payload".to_vec();
        bytes.push(0); // Add only one byte for version instead of two
        let result = DataWarp::from_bytes(bytes.into());
        assert!(matches!(result, Err(LocalStorageError::InsufficientBytes)));
    }

    #[test]
    fn test_datawarp_version_preserved_through_sled() {
        let dir = format!("/tmp/zilpay_datawarp_v_{}", rand_num());
        let db = sled::open(&dir).unwrap();

        let v0 = DataWarp {
            payload: b"bincode_data".to_vec(),
            version: 0,
        };
        let v1 = DataWarp {
            payload: b"msgpack_data".to_vec(),
            version: 1,
        };

        db.insert(b"key_v0", sled::IVec::from(v0.to_bytes()))
            .unwrap();
        db.insert(b"key_v1", sled::IVec::from(v1.to_bytes()))
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let db = sled::open(&dir).unwrap();

        let raw_v0 = db.get(b"key_v0").unwrap().unwrap().to_vec();
        let restored_v0 = DataWarp::from_bytes(raw_v0.into()).unwrap();
        assert_eq!(restored_v0.version, 0);
        assert_eq!(restored_v0.payload, b"bincode_data");

        let raw_v1 = db.get(b"key_v1").unwrap().unwrap().to_vec();
        let restored_v1 = DataWarp::from_bytes(raw_v1.into()).unwrap();
        assert_eq!(restored_v1.version, 1);
        assert_eq!(restored_v1.payload, b"msgpack_data");
    }

    #[test]
    fn test_datawarp_sled_bincode_to_msgpack_migration() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
        struct TokenV1 {
            name: String,
            symbol: String,
            decimals: u8,
        }

        #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
        #[serde(default)]
        struct TokenV2 {
            name: String,
            symbol: String,
            decimals: u8,
            logo: String,
            native: bool,
        }

        impl Default for TokenV2 {
            fn default() -> Self {
                Self {
                    name: String::new(),
                    symbol: String::new(),
                    decimals: 0,
                    logo: String::new(),
                    native: false,
                }
            }
        }

        let dir = format!("/tmp/zilpay_datawarp_migrate_{}", rand_num());
        let db = sled::open(&dir).unwrap();
        let key = b"token_data";

        let token_v1 = TokenV1 {
            name: "ZilPay".to_string(),
            symbol: "ZLP".to_string(),
            decimals: 18,
        };

        let bincode_payload = bincode::serialize(&token_v1).unwrap();
        let warp_v0 = DataWarp {
            payload: bincode_payload,
            version: 0,
        };
        db.insert(key, sled::IVec::from(warp_v0.to_bytes()))
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let db = sled::open(&dir).unwrap();
        let raw = db.get(key).unwrap().unwrap().to_vec();
        let warp = DataWarp::from_bytes(raw.into()).unwrap();
        assert_eq!(warp.version, 0);

        let restored: TokenV1 = bincode::deserialize(&warp.payload).unwrap();
        assert_eq!(restored, token_v1);

        let msgpack_payload = rmp_serde::to_vec_named(&restored).unwrap();
        let warp_v1 = DataWarp {
            payload: msgpack_payload,
            version: 1,
        };
        db.insert(key, sled::IVec::from(warp_v1.to_bytes()))
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let db = sled::open(&dir).unwrap();
        let raw = db.get(key).unwrap().unwrap().to_vec();
        let warp = DataWarp::from_bytes(raw.into()).unwrap();
        assert_eq!(warp.version, 1);

        let as_v2: TokenV2 = rmp_serde::from_slice(&warp.payload).unwrap();
        assert_eq!(as_v2.name, "ZilPay");
        assert_eq!(as_v2.symbol, "ZLP");
        assert_eq!(as_v2.decimals, 18);
        assert_eq!(as_v2.logo, "");
        assert!(!as_v2.native);
    }

    #[test]
    fn test_datawarp_sled_multiple_versions_coexist() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
        struct Settings {
            theme: String,
            locale: String,
        }

        #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
        #[serde(default)]
        struct SettingsV2 {
            theme: String,
            locale: String,
            notifications: bool,
        }

        impl Default for SettingsV2 {
            fn default() -> Self {
                Self {
                    theme: String::new(),
                    locale: String::new(),
                    notifications: true,
                }
            }
        }

        let dir = format!("/tmp/zilpay_datawarp_coexist_{}", rand_num());
        let db = sled::open(&dir).unwrap();

        let settings_old = Settings {
            theme: "dark".to_string(),
            locale: "en".to_string(),
        };
        let bincode_payload = bincode::serialize(&settings_old).unwrap();
        let warp_old = DataWarp {
            payload: bincode_payload,
            version: 0,
        };
        db.insert(b"settings_wallet_a", sled::IVec::from(warp_old.to_bytes()))
            .unwrap();

        let settings_new = SettingsV2 {
            theme: "light".to_string(),
            locale: "fr".to_string(),
            notifications: false,
        };
        let msgpack_payload = rmp_serde::to_vec_named(&settings_new).unwrap();
        let warp_new = DataWarp {
            payload: msgpack_payload,
            version: 1,
        };
        db.insert(b"settings_wallet_b", sled::IVec::from(warp_new.to_bytes()))
            .unwrap();

        db.flush().unwrap();
        drop(db);

        let db = sled::open(&dir).unwrap();

        let raw_a = db.get(b"settings_wallet_a").unwrap().unwrap().to_vec();
        let warp_a = DataWarp::from_bytes(raw_a.into()).unwrap();
        assert_eq!(warp_a.version, 0);
        let restored_a: Settings = bincode::deserialize(&warp_a.payload).unwrap();
        assert_eq!(restored_a.theme, "dark");
        assert_eq!(restored_a.locale, "en");

        let raw_b = db.get(b"settings_wallet_b").unwrap().unwrap().to_vec();
        let warp_b = DataWarp::from_bytes(raw_b.into()).unwrap();
        assert_eq!(warp_b.version, 1);
        let restored_b: SettingsV2 = rmp_serde::from_slice(&warp_b.payload).unwrap();
        assert_eq!(restored_b.theme, "light");
        assert_eq!(restored_b.locale, "fr");
        assert!(!restored_b.notifications);

        let original_a: Settings = crate::codec::deserialize(&warp_a).unwrap();
        assert_eq!(original_a.theme, "dark");

        let migrated_warp = crate::codec::serialize(&original_a).unwrap();
        assert_eq!(migrated_warp.version, 1);
        db.insert(
            b"settings_wallet_a",
            sled::IVec::from(migrated_warp.to_bytes()),
        )
        .unwrap();

        let raw_a2 = db.get(b"settings_wallet_a").unwrap().unwrap().to_vec();
        let warp_a2 = DataWarp::from_bytes(raw_a2.into()).unwrap();
        assert_eq!(warp_a2.version, 1);
        let upgraded_a: SettingsV2 = crate::codec::deserialize(&warp_a2).unwrap();
        assert_eq!(upgraded_a.theme, "dark");
        assert_eq!(upgraded_a.locale, "en");
        assert!(upgraded_a.notifications);
    }

    #[test]
    fn test_datawarp_empty_payload() {
        let warp = DataWarp {
            payload: Vec::new(),
            version: 0,
        };

        let bytes = warp.to_bytes();
        let restored = DataWarp::from_bytes(bytes.into()).unwrap();
        assert_eq!(restored.payload.len(), 0);
        assert_eq!(restored.version, 0);
    }

    #[test]
    fn test_datawarp_large_payload() {
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let warp = DataWarp {
            payload: payload.clone(),
            version: 1,
        };

        let bytes = warp.to_bytes();
        let restored = DataWarp::from_bytes(bytes.into()).unwrap();
        assert_eq!(restored.payload, payload);
        assert_eq!(restored.version, 1);
    }

    fn rand_num() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
