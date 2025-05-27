use sha2::{Digest, Sha256};
use sha256::digest;

pub fn sha256(input: &str) -> String {
    // println!("input: {input:?}");
    let val = digest(input);
    // println!("val: {val:?}");
    val
}

pub fn sha2_256(_input: &str) -> [u8; 32] {
    // let val = Sha256::digest(input);
    // val.into()

    let mut hasher = Sha256::new();
    hasher.update(b"hello, ");
    hasher.update(b"crypto");
    let hash256 = hasher.finalize();
    hash256.into()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha256() {
        let res = sha256("hello, crypto");
        assert_eq!(
            res,
            "97a985aaefe16cbfa32aa66bcd6b06ade0cb9de77ca1c734bb3c751d4f44006c"
        );
    }

    #[test]
    fn test_sha2_256() {
        let res = sha256("hello, crypto");
        assert_eq!(
            res,
            "97a985aaefe16cbfa32aa66bcd6b06ade0cb9de77ca1c734bb3c751d4f44006c"
        );
    }
}
