use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::AppError;

const KEY_PREFIX: &str = "opaq_";

const KDF_MEM_KIB: u32 = 64 * 1024;
const KDF_TIME_COST: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_master_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let params = Params::new(KDF_MEM_KIB, KDF_TIME_COST, KDF_PARALLELISM, Some(32))
        .map_err(|_| AppError::internal("invalid argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|_| AppError::internal("argon2 derivation failed"))?;
    Ok(out)
}

pub fn random_bytes(n: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn generate_api_key() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *bytes);
    Zeroizing::new(format!("{}{}", KEY_PREFIX, hex::encode(*bytes)))
}

pub fn hash_key(api_key: &str, pepper: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper)
        .map_err(|_| AppError::internal("hmac init failed"))?;
    mac.update(api_key.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| AppError::internal("cipher init failed"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AppError::internal("encryption failed"))?;
    Ok((ct, nonce_bytes.to_vec()))
}

pub fn decrypt_value(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| AppError::internal("cipher init failed"))?;
    if nonce.len() != 12 {
        return Err(AppError::internal("invalid nonce length"));
    }
    let nonce = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::internal("decryption failed"))?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
pub fn generate_master_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pepper() -> Vec<u8> {
        b"test-pepper-32-bytes-padding!!!!".to_vec()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = generate_master_key();
        let plaintext = b"hunter2";
        let (ct, nonce) = encrypt_value(&key, plaintext).expect("encrypt");
        let pt = decrypt_value(&key, &ct, &nonce).expect("decrypt");
        assert_eq!(&**pt, plaintext);
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let key = generate_master_key();
        let (mut ct, nonce) = encrypt_value(&key, b"hunter2").expect("encrypt");
        ct[0] ^= 0x01;
        assert!(decrypt_value(&key, &ct, &nonce).is_err());
    }

    #[test]
    fn hash_key_is_deterministic_with_pepper() {
        let api_key = "opaq_deadbeef";
        let h1 = hash_key(api_key, &test_pepper()).expect("h1");
        let h2 = hash_key(api_key, &test_pepper()).expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_key_differs_per_pepper() {
        let api_key = "opaq_deadbeef";
        let h1 = hash_key(api_key, b"pepper-a").expect("h1");
        let h2 = hash_key(api_key, b"pepper-b").expect("h2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn generate_master_key_is_random() {
        let a = generate_master_key();
        let b = generate_master_key();
        assert_ne!(*a, *b);
    }
}
