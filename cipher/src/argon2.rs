use argon2::{self, Config, Variant, Version};
use config::argon::{APP_ID, KEY_SIZE, WALLET_SALT};
use errors::cipher::CipherErrors;

type Result<T> = std::result::Result<T, CipherErrors>;
pub type Argon2Seed = [u8; KEY_SIZE]; //TODO: make it secret

pub const ARGON2_DEFAULT_CONFIG: Config = Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 65536,
    time_cost: 1,
    lanes: 1,
    secret: &[],
    ad: APP_ID,
    hash_length: 64,
};

pub fn derive_key(password: &[u8], salt: &[u8], config: &Config) -> Result<Argon2Seed> {
    let salt_len = salt.len() + WALLET_SALT.len();
    let mut combined_salt = Vec::with_capacity(salt_len);

    combined_salt.extend_from_slice(salt);
    combined_salt.extend_from_slice(WALLET_SALT);

    let output_key_material: Argon2Seed = argon2::hash_raw(password, &combined_salt, config)
        .map_err(CipherErrors::ArgonKeyDerivingError)?
        .try_into()
        .or(Err(CipherErrors::Argon2HashSizeNotValid))?;

    Ok(output_key_material)
}

#[cfg(test)]
mod tests {
    use argon2::{Config, Variant, Version};
    use config::argon::APP_ID;

    use super::derive_key;

    #[test]
    fn test_derive_key() {
        let password = b"test_password";
        let config = Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 65536,
            time_cost: 1,
            lanes: 2,
            secret: &[],
            ad: APP_ID,
            hash_length: 64,
        };
        let key = derive_key(password, b"some_salt", &config).unwrap();

        assert_eq!(
            key,
            [
                241, 5, 105, 168, 214, 152, 5, 38, 199, 60, 34, 215, 245, 198, 217, 49, 108, 140,
                86, 183, 92, 152, 168, 92, 64, 48, 241, 204, 238, 247, 198, 88, 18, 126, 75, 177,
                211, 74, 244, 234, 39, 92, 32, 255, 148, 131, 9, 175, 213, 251, 48, 220, 238, 146,
                16, 147, 132, 15, 46, 51, 176, 134, 238, 69
            ]
        )
    }
}
