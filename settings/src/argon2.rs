use argon2::{Config, ThreadMode, Variant, Version};
use config::sha::SHA256_SIZE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ArgonParams {
    pub memory: u32,
    pub iterations: u32,
    pub threads: u32,
    pub secret: [u8; SHA256_SIZE],
}

impl ArgonParams {
    pub fn new(memory: u32, iterations: u32, threads: u32, secret: [u8; SHA256_SIZE]) -> Self {
        Self {
            memory,
            iterations,
            threads,
            secret,
        }
    }

    pub fn hash_secret(value: &str) -> [u8; SHA256_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let result = hasher.finalize();
        result.into()
    }

    pub fn into_config(&self) -> Config<'_> {
        Config {
            ad: &[],
            hash_length: 64,
            lanes: self.threads,
            thread_mode: ThreadMode::from_threads(self.threads),
            mem_cost: self.memory,
            secret: &self.secret,
            time_cost: self.iterations,
            variant: Variant::Argon2id,
            version: Version::Version13,
        }
    }

    pub fn owasp_default() -> Self {
        Self {
            memory: 6553,
            iterations: 2,
            threads: 1,
            secret: [0u8; SHA256_SIZE],
        }
    }

    pub fn low_memory() -> Self {
        Self {
            memory: 64 * 1024,
            iterations: 3,
            threads: 1,
            secret: [0u8; SHA256_SIZE],
        }
    }

    pub fn secure() -> Self {
        Self {
            memory: 256 * 1024,
            iterations: 4,
            threads: 4,
            secret: [0u8; SHA256_SIZE],
        }
    }
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self::owasp_default()
    }
}
