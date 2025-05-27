// use base64::{Engine, prelude::BASE64_STANDARD};
// use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
// use rand_core::{OsRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
// use sha2::{Digest, Sha256};
// use sha256::digest;

pub fn rsa_encrypt(data: &[u8], pub_key: RsaPublicKey) -> Vec<u8> {
    let mut rng = rand::thread_rng(); // rand@0.8
    pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("failed to encrypt")
}

pub fn rsa_decrypt(enc_data: &[u8], priv_key: RsaPrivateKey) -> Vec<u8> {
    priv_key
        .decrypt(Pkcs1v15Encrypt, enc_data)
        .expect("failed to decrypt")
}

pub fn rsa_get_key_pair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng(); // rand@0.8
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // println!("priv_key: {priv_key:?}");
    let pub_key = RsaPublicKey::from(&priv_key);
    // println!("pub_key: {pub_key:?}");
    (priv_key, pub_key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rsa_encrypt() {
        let (_, pub_key) = rsa_get_key_pair();
        let data = b"hello world";
        let encrypted = rsa_encrypt(data, pub_key);
        println!("encrypted: {encrypted:?}");
    }

    #[test]
    fn test_rsa_decrypt() {
        let (priv_key, pub_key) = rsa_get_key_pair();
        let data = b"hello world";
        let encrypted = rsa_encrypt(data, pub_key);
        println!("encrypted: {encrypted:?}");
        let decrypted = rsa_decrypt(&encrypted, priv_key);
        println!("decrypted: {decrypted:?}");
        assert_eq!(data.to_vec(), decrypted)
    }
}
