use base64::{Engine, prelude::BASE64_STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
// use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
// use sha2::{Digest, Sha256};
// use sha256::digest;

pub fn generate_keypair() -> (String, String) {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);

    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();
    // println!("{:?}", signing_key);
    // println!("{:?}", verifying_key);

    let private_key_base64 = BASE64_STANDARD.encode(signing_key.to_bytes());
    let public_key_base64 = BASE64_STANDARD.encode(verifying_key.to_bytes());

    (private_key_base64, public_key_base64)
}

pub fn sign_message(private_key_base64: &str, message: &[u8]) -> String {
    let private_key_bytes = BASE64_STANDARD
        .decode(private_key_base64)
        .expect("Invalid base64 private key");
    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap());
    let signature = signing_key.sign(message);
    BASE64_STANDARD.encode(signature.to_bytes())
}

pub fn verify_message(public_key_base64: &str, message: &[u8], signature_base64: &str) -> bool {
    let public_key_bytes = BASE64_STANDARD
        .decode(public_key_base64)
        .expect("Invalid base64 public key");
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Bad public key length"))
            .expect("Invalid pubkey");
    let signature_bytes = BASE64_STANDARD
        .decode(signature_base64)
        .expect("Invalid base64 signature");
    let signature =
        Signature::from_bytes(&signature_bytes.try_into().expect("Bad signature length"));
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (priv_b64, pub_b64) = generate_keypair();
        let msg = b"hello";
        let sig = sign_message(&priv_b64, msg);
        let verified = verify_message(&pub_b64, msg, &sig);
        assert!(verified);
    }

    #[test]
    fn test_invalid_signature() {
        let (priv_b64, pub_b64) = generate_keypair();
        let msg = b"hello";
        let tampered = b"bye";
        let sig = sign_message(&priv_b64, msg);
        let verified = verify_message(&pub_b64, tampered, &sig);
        assert!(!verified);
    }
}
