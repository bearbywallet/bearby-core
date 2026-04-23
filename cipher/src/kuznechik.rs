use errors::cipher::KuznechikErrors;
use kuznechik::{AlgOfb, KeyStore, Kuznechik};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

type Result<T> = std::result::Result<T, KuznechikErrors>;

pub const KUZNECHIK_KEY_SIZE: usize = 32;
pub const KUZNECHIK_GAMMA_SIZE: usize = 32;
pub type KuznechikKey = [u8; KUZNECHIK_KEY_SIZE];

pub fn kuznechik_encrypt(key: &KuznechikKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_hex = hex::encode(key);
    let kuz = KeyStore::with_password(&key_hex);

    let mut gamma = vec![0u8; KUZNECHIK_GAMMA_SIZE];
    let mut rng = ChaChaRng::from_rng(&mut rand::rng());
    rng.fill_bytes(&mut gamma);

    let mut cipher = AlgOfb::new(&kuz).gamma(gamma.clone());
    let mut ciphertext = cipher.encrypt(plaintext.to_vec());

    ciphertext.extend_from_slice(&gamma);

    Ok(ciphertext)
}

pub fn kuznechik_decrypt(key: &KuznechikKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() <= KUZNECHIK_GAMMA_SIZE {
        return Err(KuznechikErrors::InvalidCiphertextLength);
    }

    let key_hex = hex::encode(key);
    let kuz = KeyStore::with_password(&key_hex);

    let gamma_start = ciphertext.len() - KUZNECHIK_GAMMA_SIZE;
    let gamma = &ciphertext[gamma_start..];
    let actual_ciphertext = &ciphertext[..gamma_start];

    let mut cipher = AlgOfb::new(&kuz).gamma(gamma.to_vec());
    let plaintext = cipher.decrypt(actual_ciphertext.to_vec());

    Ok(plaintext)
}

#[cfg(test)]
mod tests_kuznechik {
    use super::*;
    use rand::Rng;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut plaintext = [0u8; 100];
        let mut key = [0u8; KUZNECHIK_KEY_SIZE];

        rng.fill_bytes(&mut plaintext);
        rng.fill_bytes(&mut key);

        let ciphertext = kuznechik_encrypt(&key, &plaintext).unwrap();
        let plaintext_restore = kuznechik_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext_restore, plaintext);
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let key = [0u8; KUZNECHIK_KEY_SIZE];
        let short_ciphertext = [0u8; KUZNECHIK_GAMMA_SIZE - 1];

        let result = kuznechik_decrypt(&key, &short_ciphertext);
        assert!(result.is_err());

        match result {
            Err(KuznechikErrors::InvalidCiphertextLength) => {}
            _ => panic!("Expected InvalidCiphertextLength error"),
        }
    }
}
