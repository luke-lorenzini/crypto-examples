use rust_cryptography::{eddsa_examples, rsa_examples, sha_examples};

fn main() {
    // Sha256 encode
    let e = "hello, crypto";
    let res = sha_examples::sha256(e);
    println!("{res:?}");
    let res = sha_examples::sha2_256(e);
    println!("{res:?}");

    // RSA Message encrypt
    let data = b"hello world";
    let (private_key, public_key) = rsa_examples::rsa_get_key_pair();
    let encrypted = rsa_examples::rsa_encrypt(data, public_key);
    println!("{encrypted:?}");
    let decrypted = rsa_examples::rsa_decrypt(&encrypted, private_key);
    println!("{decrypted:?}");

    // EdDSA
    let data = b"hello world";
    let (private_key, public_key) = eddsa_examples::generate_keypair();
    println!("key_pair: {:?}", (&private_key, &public_key));
    let signature = eddsa_examples::sign_message(&private_key, data);
    println!("signed_message: {signature:?}");
    let result = eddsa_examples::verify_message(&public_key, data, &signature);
    println!("result: {result:?}");
}
