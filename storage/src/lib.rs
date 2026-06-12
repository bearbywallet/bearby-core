pub mod codec;
pub mod data_warp;

use config::storage::STORAGE_VERSION;
use data_warp::DataWarp;
use directories::ProjectDirs;
use errors::storage::LocalStorageError;
use serde::{de::DeserializeOwned, Serialize};
use sled::{Db, IVec};

type Result<T> = std::result::Result<T, LocalStorageError>;

pub struct LocalStorage {
    tree: Db,
    version: u16,
    path: String,
}

impl std::fmt::Display for LocalStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let size = self.get_db_size().to_string();
        let path = self.get_path();

        write!(f, "size: {}, path: {:?}", size, path)
    }
}

impl LocalStorage {
    pub fn from(path: &str) -> Result<Self> {
        let tree =
            sled::open(path).map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let version = STORAGE_VERSION;

        Ok(LocalStorage {
            tree,
            version,
            path: path.to_owned(),
        })
    }

    pub fn new(qualifier: &str, organization: &str, application: &str) -> Result<Self> {
        let path = ProjectDirs::from(qualifier, organization, application)
            .ok_or(LocalStorageError::StoragePathError)?;
        let tree = sled::open(path.data_dir())
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let version = STORAGE_VERSION;

        Ok(LocalStorage {
            tree,
            version,
            path: path.data_dir().to_str().unwrap_or("").to_string(),
        })
    }

    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    pub fn get_db_size(&self) -> u64 {
        self.tree.size_on_disk().unwrap_or(0)
    }

    pub fn exists(&self, key: &[u8]) -> Result<bool> {
        self.tree
            .contains_key(key)
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))
    }

    pub fn get(&self, key: &[u8]) -> Result<Vec<u8>> {
        let some_value = self
            .tree
            .get(key)
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let value = some_value
            .ok_or(LocalStorageError::StorageDataNotFound)?
            .to_vec();
        let data = DataWarp::from_bytes(value.into())?;

        Ok(data.payload)
    }

    pub fn set(&self, key: &[u8], payload: &[u8]) -> Result<()> {
        let data = DataWarp {
            payload: payload.into(),
            version: self.version,
        };
        let vec = IVec::from(data.to_bytes());

        self.tree
            .insert(key, vec)
            .map_err(|e| LocalStorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }

    pub fn set_raw(&self, key: &[u8], raw_bytes: &[u8]) -> Result<()> {
        let vec = IVec::from(raw_bytes);

        self.tree
            .insert(key, vec)
            .map_err(|e| LocalStorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }

    pub fn remove(&self, key: &[u8]) -> Result<()> {
        self.tree
            .remove(key)
            .map_err(|e| LocalStorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.tree
            .flush()
            .map_err(|e| LocalStorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }

    pub fn keys(&self) -> Result<Vec<Vec<u8>>> {
        self.tree
            .iter()
            .keys()
            .map(|result| {
                result
                    .map(|key| key.to_vec())
                    .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))
            })
            .collect()
    }

    pub fn get_versioned<T: DeserializeOwned>(&self, key: &[u8]) -> Result<T> {
        let some_value = self
            .tree
            .get(key)
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let value = some_value
            .ok_or(LocalStorageError::StorageDataNotFound)?
            .to_vec();
        let data = DataWarp::from_bytes(value.into())?;

        codec::deserialize(&data)
    }

    pub fn set_versioned<T: Serialize>(&self, key: &[u8], value: &T) -> Result<()> {
        let data = codec::serialize(value)?;
        let vec = IVec::from(data.to_bytes());

        self.tree
            .insert(key, vec)
            .map_err(|e| LocalStorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_read_write() {
        const KEY: &[u8] = b"TEST_KEY_FOR_STORAGE";

        let payload = b"Hello, World!".to_vec();
        let db = LocalStorage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();

        db.set(KEY, &payload).unwrap();

        let out = db.get(KEY).unwrap();

        assert_eq!(out, payload);
    }
}
