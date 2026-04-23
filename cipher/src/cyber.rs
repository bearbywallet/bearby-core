use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use errors::cipher::CyberErrors;
use pq_safe_kyber::{decapsulate, encapsulate, keypair, Keypair, KyberError};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

type Result<T> = std::result::Result<T, CyberErrors>;

pub const CYBER_NONCE_SIZE: usize = 12;

pub fn cyber_generate_keypair() -> Keypair {
    let mut rng = ChaChaRng::from_rng(&mut rand::rng());
    keypair(&mut rng)
}

pub fn cyber_generate_keypair_from_seed(seed: &[u8]) -> Result<Keypair> {
    if seed.len() < 32 {
        return Err(CyberErrors::InvalidSeedLength);
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed[0..32]);

    let mut rng = ChaChaRng::from_seed(seed_array);

    Ok(keypair(&mut rng))
}

pub fn cyber_encapsulate_and_encrypt(public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut rng = ChaChaRng::from_rng(&mut rand::rng());

    let (kyber_ciphertext, shared_secret) =
        encapsulate(public_key, &mut rng).map_err(map_kyber_error)?;

    let key: &Key<Aes256Gcm> = shared_secret.as_slice().into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let aes_ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CyberErrors::EncryptionError(e.to_string()))?;

    let mut result =
        Vec::with_capacity(kyber_ciphertext.len() + CYBER_NONCE_SIZE + aes_ciphertext.len());

    result.extend_from_slice(&kyber_ciphertext);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&aes_ciphertext);

    Ok(result)
}

pub fn cyber_decapsulate_and_decrypt(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let kyber_ciphertext_size = pq_safe_kyber::KYBER_CIPHERTEXTBYTES;

    if ciphertext.len() <= kyber_ciphertext_size + CYBER_NONCE_SIZE {
        return Err(CyberErrors::InvalidCiphertextLength);
    }

    let kyber_ciphertext = &ciphertext[..kyber_ciphertext_size];

    let nonce_start = kyber_ciphertext_size;
    let nonce_end = nonce_start + CYBER_NONCE_SIZE;
    let nonce = Nonce::from_slice(&ciphertext[nonce_start..nonce_end]);

    let aes_ciphertext = &ciphertext[nonce_end..];

    let shared_secret = decapsulate(kyber_ciphertext, secret_key).map_err(map_kyber_error)?;

    let key: &Key<Aes256Gcm> = shared_secret.as_slice().into();
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, aes_ciphertext)
        .map_err(|e| CyberErrors::DecryptionError(e.to_string()))?;

    Ok(plaintext)
}

pub fn cyber_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = ChaChaRng::from_rng(&mut rand::rng());

    let (ciphertext, shared_secret) = encapsulate(public_key, &mut rng).map_err(map_kyber_error)?;

    Ok((ciphertext.to_vec(), shared_secret.to_vec()))
}

pub fn cyber_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let shared_secret = decapsulate(ciphertext, secret_key).map_err(map_kyber_error)?;

    Ok(shared_secret.to_vec())
}

fn map_kyber_error(err: KyberError) -> CyberErrors {
    match err {
        KyberError::InvalidInput => CyberErrors::InvalidInput,
        KyberError::Decapsulation => CyberErrors::DecapsulationError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_safe_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};
    use rand::Rng;

    #[test]
    fn test_keypair_generation() {
        let keypair = cyber_generate_keypair();

        assert_eq!(keypair.public.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(keypair.secret.len(), KYBER_SECRETKEYBYTES);
    }

    #[test]
    fn test_encapsulate_and_decrypt() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut plaintext = [0u8; 100];

        rng.fill_bytes(&mut plaintext);

        let keypair = cyber_generate_keypair();
        let ciphertext = cyber_encapsulate_and_encrypt(&keypair.public, &plaintext).unwrap();
        let decrypted = cyber_decapsulate_and_decrypt(&keypair.secret, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_deterministic_keys() {
        let seed = [42u8; 32];

        let keypair1 = cyber_generate_keypair_from_seed(&seed).unwrap();
        let keypair2 = cyber_generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(keypair1.public, keypair2.public);
        assert_eq!(keypair1.secret, keypair2.secret);
    }

    #[test]
    fn test_pure_kem() {
        let keypair = cyber_generate_keypair();

        let (ciphertext, shared_secret1) = cyber_encapsulate(&keypair.public).unwrap();
        let shared_secret2 = cyber_decapsulate(&ciphertext, &keypair.secret).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }
}
