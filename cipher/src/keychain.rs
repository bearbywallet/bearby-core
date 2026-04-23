use crate::{
    aes::{aes_gcm_decrypt, aes_gcm_encrypt, AES_GCM_KEY_SIZE},
    argon2::{derive_key, Argon2Seed},
    cyber::{
        cyber_decapsulate_and_decrypt, cyber_encapsulate_and_encrypt,
        cyber_generate_keypair_from_seed,
    },
    kuznechik::{kuznechik_decrypt, kuznechik_encrypt, KuznechikKey},
    ntrup::{ntru_decrypt, ntru_encrypt, ntru_keys_from_seed},
    options::CipherOrders,
};
use argon2::Config as Argon2Config;
use config::argon::KEY_SIZE;
use config::sha::SHA256_SIZE;
use errors::keychain::KeyChainErrors;
use ntrulp::{
    key::{priv_key::PrivKey, pub_key::PubKey},
    params::params::{PUBLICKEYS_BYTES, SECRETKEYS_BYTES},
};
use pq_safe_kyber::Keypair as CyberKeypair;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEYCHAIN_BYTES_SIZE: usize = PUBLICKEYS_BYTES + SECRETKEYS_BYTES + AES_GCM_KEY_SIZE;

pub struct KeyChain {
    pub ntrup_keys: (PubKey, PrivKey),
    pub aes_key: [u8; AES_GCM_KEY_SIZE],
    pub kuznechik: KuznechikKey,
    pub cyber: CyberKeypair,
}

impl Zeroize for KeyChain {
    fn zeroize(&mut self) {
        self.aes_key.zeroize();
        self.kuznechik.zeroize();

        let mut pk_bytes = self.ntrup_keys.0.to_bytes();
        let mut sk_bytes = self.ntrup_keys.1.to_bytes();
        pk_bytes.zeroize();
        sk_bytes.zeroize();
    }
}

impl ZeroizeOnDrop for KeyChain {}

fn derive_key_from_seed(seed: &[u8], idx: u8) -> [u8; SHA256_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([idx]);
    let res = hasher.finalize();

    let mut output = [0u8; SHA256_SIZE];
    for i in 0..SHA256_SIZE {
        output[i] = res[i];
    }
    output
}

impl KeyChain {
    pub fn from_bytes(bytes: &[u8; KEYCHAIN_BYTES_SIZE]) -> Result<Self, KeyChainErrors> {
        let pq_pk_bytes: [u8; PUBLICKEYS_BYTES] = bytes[..PUBLICKEYS_BYTES]
            .try_into()
            .or(Err(KeyChainErrors::AESKeySliceError))?;
        let pq_sk_bytes: [u8; SECRETKEYS_BYTES] = bytes
            [PUBLICKEYS_BYTES..PUBLICKEYS_BYTES + SECRETKEYS_BYTES]
            .try_into()
            .or(Err(KeyChainErrors::AESKeySliceError))?;
        let pq_pk = PubKey::import(&pq_pk_bytes);
        let pq_sk =
            PrivKey::import(&pq_sk_bytes).map_err(KeyChainErrors::NTRUPrimePubKeyImportError)?;

        let mut aes_key = [0u8; AES_GCM_KEY_SIZE];
        aes_key.copy_from_slice(
            &bytes[PUBLICKEYS_BYTES + SECRETKEYS_BYTES
                ..PUBLICKEYS_BYTES + SECRETKEYS_BYTES + AES_GCM_KEY_SIZE],
        );

        let kuznechik_key = derive_key_from_seed(&aes_key, 1);
        let cyber_seed = derive_key_from_seed(&aes_key, 2);
        let cyber_keypair = cyber_generate_keypair_from_seed(&cyber_seed)?;

        Ok(Self {
            ntrup_keys: (pq_pk, pq_sk),
            aes_key,
            kuznechik: kuznechik_key,
            cyber: cyber_keypair,
        })
    }

    // TODO: repalce with secrecy
    pub fn from_seed(seed_bytes: &Argon2Seed) -> Result<Self, KeyChainErrors> {
        let (pk, sk) = ntru_keys_from_seed(seed_bytes)?;

        let aes_key = derive_key_from_seed(seed_bytes, 0);
        let kuznechik_key = derive_key_from_seed(seed_bytes, 1);
        let cyber_seed = derive_key_from_seed(seed_bytes, 2);
        let cyber_keypair = cyber_generate_keypair_from_seed(&cyber_seed)?;

        Ok(Self {
            ntrup_keys: (pk, sk),
            aes_key,
            kuznechik: kuznechik_key,
            cyber: cyber_keypair,
        })
    }

    pub fn from_pass(
        password: &[u8],
        fingerprint: &[u8],
        argon_config: &Argon2Config,
    ) -> Result<Self, KeyChainErrors> {
        let seed_bytes = derive_key(password, fingerprint, argon_config)
            .map_err(KeyChainErrors::Argon2CipherErrors)?;

        Self::from_seed(&seed_bytes)
    }

    pub fn to_bytes(&self) -> [u8; KEYCHAIN_BYTES_SIZE] {
        let mut res = [0u8; KEYCHAIN_BYTES_SIZE];
        let pq_pk = self.ntrup_keys.0.to_bytes();
        let pq_sk = self.ntrup_keys.1.to_bytes();

        res[..PUBLICKEYS_BYTES].copy_from_slice(&pq_pk);
        res[PUBLICKEYS_BYTES..PUBLICKEYS_BYTES + SECRETKEYS_BYTES].copy_from_slice(&pq_sk);
        res[PUBLICKEYS_BYTES + SECRETKEYS_BYTES..].copy_from_slice(&self.aes_key);

        res
    }

    pub fn decrypt(
        &self,
        mut ciphertext: Vec<u8>,
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        for o in options.iter().rev() {
            match o {
                CipherOrders::AESGCM256 => {
                    ciphertext = aes_gcm_decrypt(&self.aes_key, &ciphertext)?
                }
                CipherOrders::KUZNECHIK => {
                    ciphertext = kuznechik_decrypt(&self.kuznechik, &ciphertext)?
                }
                CipherOrders::NTRUP1277 => {
                    ciphertext = ntru_decrypt(self.ntrup_keys.1.clone(), ciphertext)
                        .map_err(KeyChainErrors::NTRUPrimeDecryptError)?
                }
                CipherOrders::CYBER => {
                    ciphertext = cyber_decapsulate_and_decrypt(&self.cyber.secret, &ciphertext)?
                }
            };
        }

        Ok(ciphertext)
    }

    pub fn encrypt(
        &self,
        mut plaintext: Vec<u8>,
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        for o in options {
            match o {
                CipherOrders::AESGCM256 => plaintext = aes_gcm_encrypt(&self.aes_key, &plaintext)?,
                CipherOrders::KUZNECHIK => {
                    plaintext = kuznechik_encrypt(&self.kuznechik, &plaintext)?
                }
                CipherOrders::NTRUP1277 => {
                    plaintext = ntru_encrypt(self.ntrup_keys.0.clone(), &plaintext)?
                }
                CipherOrders::CYBER => {
                    plaintext = cyber_encapsulate_and_encrypt(&self.cyber.public, &plaintext)?
                }
            };
        }

        Ok(plaintext)
    }

    pub fn make_proof(
        &self,
        seed: &[u8; KEY_SIZE],
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        let cipher = self.encrypt(seed.to_vec(), options)?;

        Ok(cipher)
    }

    pub fn get_proof(
        &self,
        cipher_proof: &[u8],
        options: &[CipherOrders],
    ) -> Result<[u8; KEY_SIZE], KeyChainErrors> {
        let origin_seed: [u8; KEY_SIZE] = self
            .decrypt(cipher_proof.to_vec(), options)?
            .try_into()
            .or(Err(KeyChainErrors::FailSlicedProofCipher))?;

        Ok(origin_seed)
    }
}

#[cfg(test)]
mod keychain_tests {
    use core::panic;

    use crate::argon2::{derive_key, ARGON2_DEFAULT_CONFIG};

    use super::{CipherOrders, KeyChain};
    use config::cipher::PROOF_SIZE;
    use errors::{cipher::AesGCMErrors, keychain::KeyChainErrors};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_init_keychain() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut password = [0u8; 32];

        rng.fill_bytes(&mut password);

        let keychain = KeyChain::from_pass(&password, b"", &ARGON2_DEFAULT_CONFIG);

        assert!(keychain.is_ok());
    }

    #[test]
    fn test_bytes() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut password = [0u8; 32];
        let mut plaintext = [0u8; 1024];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut plaintext);

        let keychain = KeyChain::from_pass(&password, b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let bytes = keychain.to_bytes();
        let restore_keychain = KeyChain::from_bytes(&bytes).unwrap();

        assert_eq!(restore_keychain.aes_key, keychain.aes_key);
        assert_eq!(
            restore_keychain.ntrup_keys.0.to_bytes(),
            keychain.ntrup_keys.0.to_bytes()
        );
        assert_eq!(
            restore_keychain.ntrup_keys.1.to_bytes(),
            keychain.ntrup_keys.1.to_bytes()
        );
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut password = [0u8; 32];
        let mut plaintext = [0u8; 1024];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut plaintext);

        let keychain = KeyChain::from_pass(&password, b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        let ciphertext = keychain.encrypt(plaintext.to_vec(), &options).unwrap();
        let res_plaintext = keychain.decrypt(ciphertext.clone(), &options).unwrap();

        assert_eq!(res_plaintext, plaintext);

        let invalid_options = [CipherOrders::NTRUP1277, CipherOrders::AESGCM256];

        match keychain.decrypt(ciphertext, &invalid_options) {
            Ok(_) => panic!("invalid options should be fail decrypt"),
            Err(e) => match e {
                KeyChainErrors::AesGCMErrors(AesGCMErrors::DecryptError(err)) => {
                    assert_eq!("aead::Error", err);
                }
                _ => panic!("should be fall with AESDecryptError"),
            },
        };
    }

    #[test]
    fn test_make_verify_proof() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut password = [0u8; 32];

        rng.fill_bytes(&mut password);

        let options = [CipherOrders::NTRUP1277, CipherOrders::AESGCM256];
        let seed_bytes = derive_key(&password, b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&seed_bytes).unwrap();
        let origin_proof =
            derive_key(&seed_bytes[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
        let proof_cipher = keychain.make_proof(&origin_proof, &options).unwrap();
        let proof = keychain.get_proof(&proof_cipher, &options).unwrap();

        assert_eq!(origin_proof, proof);
    }
}
