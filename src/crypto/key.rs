use hex;
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, SecretKey};

use super::SECP256K1;

pub trait PrivateKey {
    fn hex_string(&self) -> String;
    fn public_key(&self) -> String;
    fn sign(&self, data: &[u8]) -> [u8; 65];
}

struct PrivKey {
    bytes: [u8; 32],
}

pub struct Signature(pub [u8; 64]);

impl PrivKey {
    pub fn from_slice(raw: &[u8; 32]) -> Self {
        PrivKey {
            bytes: *raw,
        }
    }

    pub fn new() -> Self {
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, public_key) = &SECP256K1.generate_keypair(&mut rng);
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(secret_key.to_string(), &mut bytes as &mut [u8]);
        PrivKey {
            bytes,
        }
    }

    pub fn hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn public_key(&self) -> String {
        let secret_key = SecretKey::from_slice(&self.bytes).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);
        hex::encode(&public_key.serialize_uncompressed()[0..65])
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 65] {
        let secret_key = SecretKey::from_slice(&self.bytes).expect("32 bytes, within curve order");

        let message = Message::from_slice(data).expect("32 bytes");

        let sig = &SECP256K1.sign_recoverable(&message, &secret_key);

        let (recid, signed) = sig.serialize_compact();
        let mut sign = [0u8; 65];
        sign[0..64].copy_from_slice(&signed[0..64]);
        sign[64] = recid.to_i32() as u8;
        sign
    }
}

#[test]
fn test_from_slice() {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f", &mut bytes as &mut [u8]);
    let key = PrivKey::from_slice(&bytes);

    assert_eq!(
        key.hex_string(),
        String::from("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f")
    );

    assert_eq!(
        key.public_key(),
        String::from("044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9")
    );

    hex::decode_to_slice("2cddfe87fe695e09ee430b7f60b4c585a3063613872130baf414537f46732501", &mut bytes as &mut [u8]);
    assert_eq!(
        hex::encode(&key.sign(&bytes)[..]),
        String::from("99f4ef1005ae6c43548520e08dd11477e9ea59317087f9c6f33bc79eb701b14b043ff0d177bc419e585c0ecae42420fabb837e602c8a3578ea17dd1a8ed862e301")
    );
}

#[test]
fn test_new() {
    let key = PrivKey::new();
    assert_eq!(key.public_key().len(), 130)
}
