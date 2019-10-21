use super::constants::*;
use tiny_keccak::Keccak;

pub struct Hash160b(pub [u8; HASH_160_SIZE]);
pub struct Hash256b(pub [u8; HASH_256_SIZE]);

pub fn hash160b(x: &[u8]) -> Hash160b {
    let mut h256: [u8; HASH_256_SIZE] = [0; HASH_256_SIZE];
    Keccak::keccak256(&x[..], &mut h256);

    let mut res: [u8; HASH_160_SIZE] = [0; HASH_160_SIZE];
    for i in 0..HASH_160_SIZE {
        res[i] = h256[HASH_256_SIZE - HASH_160_SIZE + i]
    }
    Hash160b(res)
}

pub fn hash256b(x: &[u8]) -> Hash256b {
    let mut res: [u8; HASH_256_SIZE] = [0; HASH_256_SIZE];
    Keccak::keccak256(&x[..], &mut res);
    Hash256b(res)
}

pub fn bytes_to_hash160(bytes: &[u8]) -> Hash160b {
    let mut b: &[u8] = bytes;
    let mut res: [u8; HASH_160_SIZE] = [0; HASH_160_SIZE];
    if b.len() > HASH_160_SIZE {
        b = &b[b.len() - HASH_160_SIZE..];
    }
    for i in 0..b.len() {
        res[HASH_160_SIZE - b.len() + i] = b[i]
    }
    Hash160b(res)
}

pub fn bytes_to_hash256(bytes: &[u8]) -> Hash256b {
    let mut b: &[u8] = bytes;
    let mut res: [u8; HASH_256_SIZE] = [0; HASH_256_SIZE];
    if bytes.len() > HASH_256_SIZE {
        b = &b[b.len() - HASH_256_SIZE..];
    }
    for i in 0..b.len() {
        res[HASH_256_SIZE - b.len() + i] = b[i]
    }
    Hash256b(res)
}

#[test]
fn test_hash() {
    let tests: [(&str, &str); 2] = [
        (
            "",
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        ),
        (
            "abc",
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        ),
    ];
    for test in tests.iter() {
        let h = hash256b(test.0.as_bytes());
        assert_eq!(hex::encode(h.0), test.1.to_string());

        let h = hash160b(test.0.as_bytes());
        assert_eq!(hex::encode(h.0), test.1[24..]);
    }
}
