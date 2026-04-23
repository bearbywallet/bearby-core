use config::sha::{SHA256_SIZE, SHA512_SIZE};
use errors::ntru::NTRULPCipherErrors;
use ntrulp::{
    key::{priv_key::PrivKey, pub_key::PubKey},
    ntru,
    poly::{r3::R3, rq::Rq},
    rng::{random_small, short_random},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::sync::Arc;

type Result<T> = std::result::Result<T, NTRULPCipherErrors>;

pub fn ntru_keys_from_seed(seed_bytes: &[u8; SHA512_SIZE]) -> Result<(PubKey, PrivKey)> {
    let seed_pq: [u8; SHA256_SIZE] = seed_bytes[..SHA256_SIZE]
        .try_into()
        .or(Err(NTRULPCipherErrors::InvalidSeedPQBytesSize))?;
    let mut pq_rng = ChaChaRng::from_seed(seed_pq);
    let f: Rq = Rq::from(short_random(&mut pq_rng).map_err(NTRULPCipherErrors::FailToInitF)?);

    let mut g: R3;
    let sk = loop {
        let r = random_small(&mut pq_rng);
        g = R3::from(r);

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).map_err(NTRULPCipherErrors::ComputePubKeyError)?;

    Ok((pk, sk))
}

pub fn ntru_encrypt(pk: PubKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut pq_rng = ChaChaRng::from_rng(&mut rand::rng());

    ntru::std_cipher::bytes_encrypt(&mut pq_rng, plaintext, pk)
        .map_err(NTRULPCipherErrors::EncryptError)
}

pub fn ntru_decrypt(sk: PrivKey, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
    let ciphertext = Arc::new(ciphertext);

    ntru::std_cipher::bytes_decrypt(&ciphertext, sk).map_err(NTRULPCipherErrors::DecryptError)
}

#[cfg(test)]
mod tests {
    use super::{ntru_keys_from_seed, SHA512_SIZE};
    use crate::ntrup::{ntru_decrypt, ntru_encrypt};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut rng = ChaChaRng::from_rng(&mut rand::rng());
        let mut password = [0u8; 2000];
        let mut plaintext = vec![0u8; 255];
        let mut seed = [0u8; SHA512_SIZE];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut plaintext);

        let (pk, sk) = ntru_keys_from_seed(&seed).unwrap();
        let ciphertext = ntru_encrypt(pk, &plaintext).unwrap();
        let res = ntru_decrypt(sk, ciphertext).unwrap();

        assert_eq!(res, plaintext);
    }
}
