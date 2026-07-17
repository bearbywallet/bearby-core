//! BIP-137 Bitcoin signed messages (`"\x18Bitcoin Signed Message:\n"` magic).

use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::sign_message::signed_msg_hash;
use errors::tx::TransactionErrors;
use k256::ecdsa::SigningKey;

/// BIP-137 message signature: base64 `[header(1) | r(32) | s(32)]`.
///
/// Header encodes recovery id + address kind (P2PKH compressed 31–34,
/// P2SH-P2WPKH 35–38, P2WPKH 39–42). P2TR keeps the P2WPKH range (common
/// wallet practice — BIP-137 predates taproot).
pub fn sign_message_bip137(
    secret_key: &SecretKey,
    message: &[u8],
    addr_type: bitcoin::AddressType,
) -> Result<String, TransactionErrors> {
    let msg = std::str::from_utf8(message).map_err(|_| TransactionErrors::InvalidSignature)?;
    let msg_hash = signed_msg_hash(msg);

    let signing_key = SigningKey::from_slice(&secret_key.secret_bytes())
        .map_err(|_| TransactionErrors::InvalidSecretKey)?;
    let (sig, rec_id) = signing_key
        .sign_prehash_recoverable(msg_hash.as_byte_array())
        .map_err(|_| TransactionErrors::InvalidSignature)?;

    // P2SH → nested-segwit header (35). The wallet only creates P2SH-P2WPKH
    // (BIP49), never bare multisig P2SH, so this mapping is correct for v1.
    let base = match addr_type {
        bitcoin::AddressType::P2pkh => 31u8, // compressed P2PKH
        bitcoin::AddressType::P2sh => 35u8,  // P2SH-P2WPKH
        _ => 39u8,                           // P2WPKH / P2TR
    };

    let mut out = [0u8; 65];
    out[0] = base.saturating_add(u8::from(rec_id.to_byte()));
    out[1..].copy_from_slice(&sig.to_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Double-SHA256 of the BIP-137 prefixed message (hex, no `0x`).
pub fn bip137_message_hash_hex(message: &str) -> String {
    hex::encode(signed_msg_hash(message).to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SECP256K1};
    use bitcoin::{Address, CompressedPublicKey, Network};
    use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

    fn recover_pubkey(message: &str, sig_b64: &str) -> PublicKey {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .expect("base64");
        assert_eq!(bytes.len(), 65);
        let header = bytes[0];
        assert!(header >= 27);
        let rec_id = RecoveryId::from_byte((header - 27) & 0x03).expect("rec id");
        let sig = K256Signature::from_slice(&bytes[1..]).expect("sig");
        let msg_hash = signed_msg_hash(message);
        let vk = VerifyingKey::recover_from_prehash(msg_hash.as_byte_array(), &sig, rec_id)
            .expect("recover");
        let enc = vk.to_encoded_point(true);
        PublicKey::from_slice(enc.as_bytes()).expect("pk")
    }

    #[test]
    fn bip137_sign_recovers_p2pkh_address() {
        let sk = SecretKey::from_slice(&[0x11u8; 32]).expect("sk");
        let pk = PublicKey::from_secret_key(SECP256K1, &sk);
        let compressed = CompressedPublicKey(pk);
        let addr = Address::p2pkh(compressed, Network::Bitcoin);

        let message = b"Hello Bitcoin";
        let sig = sign_message_bip137(&sk, message, bitcoin::AddressType::P2pkh).expect("sign");

        let recovered = recover_pubkey(
            std::str::from_utf8(message).expect("utf8"),
            &sig,
        );
        let recovered_addr =
            Address::p2pkh(CompressedPublicKey(recovered), Network::Bitcoin);
        assert_eq!(recovered_addr.to_string(), addr.to_string());

        // Header in compressed-P2PKH range 31–34.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .expect("b64");
        assert!((31..=34).contains(&raw[0]));
    }

    #[test]
    fn bip137_p2wpkh_header_range() {
        let sk = SecretKey::from_slice(&[0x22u8; 32]).expect("sk");
        let sig = sign_message_bip137(&sk, b"segwit msg", bitcoin::AddressType::P2wpkh)
            .expect("sign");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .expect("b64");
        assert!((39..=42).contains(&raw[0]));
    }

    #[test]
    fn bip137_message_hash_is_sha256d_of_prefixed() {
        let hash = signed_msg_hash("test");
        assert_eq!(
            bip137_message_hash_hex("test"),
            hex::encode(hash.to_byte_array())
        );
        // Stable across runs — double-SHA256 of BIP-137-prefixed "test".
        assert_eq!(
            bip137_message_hash_hex("test"),
            "9ce428d58e8e4caf619dc6fc7b2c2c28f0561654d1f80f322c038ad5e67ff8a6"
        );
        let _ = Secp256k1::new();
    }

    #[test]
    fn bip137_rejects_non_utf8_message() {
        let sk = SecretKey::from_slice(&[0x33u8; 32]).expect("sk");
        let bad = [0xffu8, 0xfe, 0xfd];
        let err = sign_message_bip137(&sk, &bad, bitcoin::AddressType::P2pkh);
        assert!(err.is_err());
    }
}
