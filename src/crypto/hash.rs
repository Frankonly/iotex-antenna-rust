use tiny_keccak::Keccak;

pub fn hash160b(x: &[u8]) -> [u8; 20] {
    let mut h256: [u8; 32] = [0; 32];
    Keccak::keccak256(x, &mut h256);

    let mut res: [u8; 20] = [0; 20];
    for i in 0..20 {
        res[i] = h256[12 + i]
    }
    res
}

pub fn hash256b(x: &[u8]) -> [u8; 32] {
    let mut res: [u8; 32] = [0; 32];
    Keccak::keccak256(x, &mut res);
    res
}
mod tests {
    extern crate hex;
    use super::*;
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
            assert_eq!(hex::encode(h), test.1.to_string());

            let h = hash160b(test.0.as_bytes());
            assert_eq!(hex::encode(h), test.1[24..]);
        }
    }
}
