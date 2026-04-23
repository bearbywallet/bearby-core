use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use errors::cipher::AesGCMErrors;

type Result<T> = std::result::Result<T, AesGCMErrors>;
pub type AESKey = [u8; AES_GCM_KEY_SIZE];

pub const AES_GCM_KEY_SIZE: usize = 32;
pub const AES_GCM_NONCE_SIZE: usize = 12;

pub fn aes_gcm_encrypt(key: &AESKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut bytes = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AesGCMErrors::EncryptError(e.to_string()))?;

    bytes.extend(nonce);

    Ok(bytes)
}

pub fn aes_gcm_decrypt(key: &AESKey, cipher_nonce: &[u8]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(key);
    let ciphertext = &cipher_nonce[..cipher_nonce.len() - AES_GCM_NONCE_SIZE];
    let nonce = &cipher_nonce[cipher_nonce.len() - AES_GCM_NONCE_SIZE..];
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AesGCMErrors::DecryptError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{aes_gcm_decrypt, aes_gcm_encrypt, AES_GCM_KEY_SIZE};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut plaintext = [0u8; 100];
        let mut key = [0u8; AES_GCM_KEY_SIZE];

        rng.fill_bytes(&mut plaintext);
        rng.fill_bytes(&mut key);

        let ciphertext = aes_gcm_encrypt(&key, &plaintext).unwrap();
        let plaintext_restore = aes_gcm_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext_restore, plaintext);
    }
}
