use crate::data_warp::DataWarp;
use errors::storage::LocalStorageError;
use serde::{de::DeserializeOwned, Serialize};

type Result<T> = std::result::Result<T, LocalStorageError>;

pub const FORMAT_VERSION_BINCODE: u16 = 0;
pub const FORMAT_VERSION_MSGPACK: u16 = 1;

pub trait Codec: Serialize + DeserializeOwned {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let warp = serialize(self)?;
        Ok(warp.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let warp = DataWarp::from_bytes(bytes.into())?;
        deserialize(&warp)
    }
}

pub fn serialize<T: Serialize>(value: &T) -> Result<DataWarp> {
    let payload = rmp_serde::to_vec_named(value)
        .map_err(|e| LocalStorageError::SerializeError(e.to_string()))?;
    Ok(DataWarp {
        payload,
        version: FORMAT_VERSION_MSGPACK,
    })
}

pub fn deserialize<T: DeserializeOwned>(data: &DataWarp) -> Result<T> {
    match data.version {
        FORMAT_VERSION_BINCODE => bincode::deserialize(&data.payload)
            .map_err(|e| LocalStorageError::DeserializeError(e.to_string())),
        FORMAT_VERSION_MSGPACK => rmp_serde::from_slice(&data.payload)
            .map_err(|e| LocalStorageError::DeserializeError(e.to_string())),
        v => Err(LocalStorageError::UnsupportedVersion(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct ChainConfigV1 {
        name: String,
        chain: String,
        chain_ids: [u64; 2],
        rpc: Vec<String>,
        slip_44: u32,
        fallback_enabled: bool,
    }

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    #[serde(default)]
    struct ChainConfigV2 {
        name: String,
        chain: String,
        chain_ids: [u64; 2],
        rpc: Vec<String>,
        slip_44: u32,
        fallback_enabled: bool,
        batch_requests: bool,
        max_batch_size: u32,
        custom_label: String,
    }

    impl Default for ChainConfigV2 {
        fn default() -> Self {
            Self {
                name: String::new(),
                chain: String::new(),
                chain_ids: [0, 0],
                rpc: Vec::new(),
                slip_44: 0,
                fallback_enabled: false,
                batch_requests: true,
                max_batch_size: 100,
                custom_label: "default".to_string(),
            }
        }
    }

    #[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
    #[serde(default)]
    struct ChainConfigV3 {
        name: String,
        chain_ids: [u64; 2],
        slip_44: u32,
    }

    fn sample_v1() -> ChainConfigV1 {
        ChainConfigV1 {
            name: "Ethereum".to_string(),
            chain: "ETH".to_string(),
            chain_ids: [1, 0],
            rpc: vec!["https://eth.rpc".to_string()],
            slip_44: 60,
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_msgpack_roundtrip_same_struct() {
        let v1 = sample_v1();
        let warp = serialize(&v1).unwrap();
        assert_eq!(warp.version, FORMAT_VERSION_MSGPACK);

        let restored: ChainConfigV1 = deserialize(&warp).unwrap();
        assert_eq!(restored, v1);
    }

    #[test]
    fn test_msgpack_v1_to_v2_add_fields() {
        let v1 = sample_v1();
        let warp = serialize(&v1).unwrap();

        let v2: ChainConfigV2 = deserialize(&warp).unwrap();
        assert_eq!(v2.name, "Ethereum");
        assert_eq!(v2.chain, "ETH");
        assert_eq!(v2.chain_ids, [1, 0]);
        assert_eq!(v2.rpc, vec!["https://eth.rpc".to_string()]);
        assert_eq!(v2.slip_44, 60);
        assert!(v2.fallback_enabled);
        assert!(v2.batch_requests);
        assert_eq!(v2.max_batch_size, 100);
        assert_eq!(v2.custom_label, "default");
    }

    #[test]
    fn test_msgpack_v2_to_v1_remove_fields() {
        let v2 = ChainConfigV2 {
            name: "BSC".to_string(),
            chain: "BNB".to_string(),
            chain_ids: [56, 0],
            rpc: vec!["https://bsc.rpc".to_string()],
            slip_44: 60,
            fallback_enabled: false,
            batch_requests: true,
            max_batch_size: 50,
            custom_label: "custom".to_string(),
        };
        let warp = serialize(&v2).unwrap();

        let v1: ChainConfigV1 = deserialize(&warp).unwrap();
        assert_eq!(v1.name, "BSC");
        assert_eq!(v1.chain, "BNB");
        assert_eq!(v1.chain_ids, [56, 0]);
        assert!(!v1.fallback_enabled);
    }

    #[test]
    fn test_msgpack_v2_to_v3_removed_and_kept_fields() {
        let v2 = ChainConfigV2 {
            name: "Polygon".to_string(),
            chain: "MATIC".to_string(),
            chain_ids: [137, 0],
            rpc: vec!["https://polygon.rpc".to_string()],
            slip_44: 60,
            fallback_enabled: true,
            batch_requests: false,
            max_batch_size: 200,
            custom_label: "poly".to_string(),
        };
        let warp = serialize(&v2).unwrap();

        let v3: ChainConfigV3 = deserialize(&warp).unwrap();
        assert_eq!(v3.name, "Polygon");
        assert_eq!(v3.chain_ids, [137, 0]);
        assert_eq!(v3.slip_44, 60);
    }

    #[test]
    fn test_bincode_v0_migration_to_msgpack() {
        let v1 = sample_v1();
        let bincode_bytes = bincode::serialize(&v1).unwrap();
        let warp = DataWarp {
            payload: bincode_bytes,
            version: FORMAT_VERSION_BINCODE,
        };

        let restored: ChainConfigV1 = deserialize(&warp).unwrap();
        assert_eq!(restored, v1);

        let new_warp = serialize(&restored).unwrap();
        assert_eq!(new_warp.version, FORMAT_VERSION_MSGPACK);

        let final_restored: ChainConfigV1 = deserialize(&new_warp).unwrap();
        assert_eq!(final_restored, v1);
    }

    #[test]
    fn test_bincode_v0_cannot_add_fields() {
        let v1 = sample_v1();
        let bincode_bytes = bincode::serialize(&v1).unwrap();
        let warp = DataWarp {
            payload: bincode_bytes,
            version: FORMAT_VERSION_BINCODE,
        };

        let result: std::result::Result<ChainConfigV2, _> = deserialize(&warp);
        assert!(result.is_err());
    }

    #[test]
    fn test_msgpack_vec_forward_compat() {
        let items = vec![sample_v1(), sample_v1()];
        let warp = serialize(&items).unwrap();

        let restored: Vec<ChainConfigV2> = deserialize(&warp).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].name, "Ethereum");
        assert!(restored[0].batch_requests);
        assert_eq!(restored[0].max_batch_size, 100);
    }

    #[test]
    fn test_unsupported_version() {
        let warp = DataWarp {
            payload: vec![1, 2, 3],
            version: 99,
        };

        let result: std::result::Result<ChainConfigV1, _> = deserialize(&warp);
        assert!(matches!(
            result,
            Err(LocalStorageError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_full_storage_roundtrip() {
        use crate::LocalStorage;

        let dir = format!("/tmp/zilpay_codec_test_{}", rand_num());
        let storage = LocalStorage::from(&dir).unwrap();
        let key = b"test_chain_config";

        let v1 = sample_v1();
        storage.set_versioned(key, &v1).unwrap();

        let restored: ChainConfigV2 = storage.get_versioned(key).unwrap();
        assert_eq!(restored.name, "Ethereum");
        assert!(restored.batch_requests);
        assert_eq!(restored.max_batch_size, 100);
    }

    #[test]
    fn test_bincode_legacy_storage_migration() {
        use crate::LocalStorage;

        let dir = format!("/tmp/zilpay_codec_legacy_{}", rand_num());
        let storage = LocalStorage::from(&dir).unwrap();
        let key = b"test_legacy_config";

        let v1 = sample_v1();
        let bincode_bytes = bincode::serialize(&v1).unwrap();
        let legacy_warp = DataWarp {
            payload: bincode_bytes,
            version: FORMAT_VERSION_BINCODE,
        };
        storage.set_raw(key, &legacy_warp.to_bytes()).unwrap();

        let restored: ChainConfigV1 = storage.get_versioned(key).unwrap();
        assert_eq!(restored, v1);

        storage.set_versioned(key, &restored).unwrap();

        let final_restored: ChainConfigV1 = storage.get_versioned(key).unwrap();
        assert_eq!(final_restored, v1);
    }

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct CodecTestStruct {
        name: String,
        value: u64,
    }

    impl Codec for CodecTestStruct {}

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    #[serde(default)]
    struct CodecTestStructV2 {
        name: String,
        value: u64,
        extra: bool,
    }

    impl Default for CodecTestStructV2 {
        fn default() -> Self {
            Self {
                name: String::new(),
                value: 0,
                extra: true,
            }
        }
    }

    impl Codec for CodecTestStructV2 {}

    #[test]
    fn test_codec_trait_roundtrip() {
        let original = CodecTestStruct {
            name: "test".to_string(),
            value: 42,
        };
        let bytes = original.to_bytes().unwrap();
        let restored = CodecTestStruct::from_bytes(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn test_codec_trait_forward_compat() {
        let v1 = CodecTestStruct {
            name: "hello".to_string(),
            value: 99,
        };
        let bytes = v1.to_bytes().unwrap();
        let v2 = CodecTestStructV2::from_bytes(&bytes).unwrap();
        assert_eq!(v2.name, "hello");
        assert_eq!(v2.value, 99);
        assert!(v2.extra);
    }

    #[test]
    fn test_codec_trait_bincode_legacy() {
        let v1 = CodecTestStruct {
            name: "legacy".to_string(),
            value: 7,
        };
        let bincode_bytes = bincode::serialize(&v1).unwrap();
        let warp = DataWarp {
            payload: bincode_bytes,
            version: FORMAT_VERSION_BINCODE,
        };
        let warp_bytes = warp.to_bytes();
        let restored = CodecTestStruct::from_bytes(&warp_bytes).unwrap();
        assert_eq!(restored, v1);
    }

    fn rand_num() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
