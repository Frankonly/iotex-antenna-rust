use super::hash;
use hex;
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, SecretKey, Signature};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};

use super::{Error, SECP256K1, SECP256K1_VERIFY};

pub trait PrivateKey {
    fn hex_string(&self) -> String;
    fn public_key(&self) -> String;
    fn sign(&self, data: &[u8]) -> [u8; 65];
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct PrivKey {
    bytes: [u8; 32],
}

impl PrivKey {
    pub fn from_slice(raw: &[u8; 32]) -> Self {
        PrivKey { bytes: *raw }
    }

    pub fn new() -> Self {
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, _public_key) = &SECP256K1.generate_keypair(&mut rng);
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(secret_key.to_string(), &mut bytes as &mut [u8]).unwrap();
        PrivKey { bytes }
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
        let hash = hash::hash256b(data);

        let secret_key = SecretKey::from_slice(&self.bytes).expect("32 bytes, within curve order");

        let message = Message::from_slice(&hash.0).expect("32 bytes");

        let sig = &SECP256K1.sign_recoverable(&message, &secret_key);

        let (recid, signed) = sig.serialize_compact();
        let mut sign = [0u8; 65];
        sign[0..64].copy_from_slice(&signed[0..64]);
        sign[64] = recid.to_i32() as u8;
        sign
    }

    pub fn recover(&self, message: &[u8], signature: &[u8]) -> [u8; 65] {
        let secret_key = SecretKey::from_slice(&self.bytes).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);
        let pubkey_raw = &public_key.serialize_uncompressed()[0..65];

        let mut pubkey_rec = [0u8; 65];

        let msg = Message::from_slice(&message).unwrap();
        for i in 0..4 {
            let rec_id = RecoveryId::from_i32(i as i32).unwrap();
            let sig = RecoverableSignature::from_compact(&signature, rec_id).expect("convert to recoverable wrong");
            if let Ok(rec_pubkey) = &SECP256K1.recover(&msg, &sig) {
                let rec_pubkey_raw = &rec_pubkey.serialize_uncompressed()[0..65];
                if rec_pubkey_raw == pubkey_raw {
                    pubkey_rec[0..65].copy_from_slice(&rec_pubkey_raw[0..65]);
                    break;
                }
            } else {
                continue;
                }
        }
        pubkey_rec
    }
}

pub fn verify_sig(data: &[u8], sig: &[u8], public_key_string: String) -> Result<bool, Error> {
    let hash = hash::hash256b(data);
    let message = Message::from_slice(&hash.0).expect("32 bytes");
    let signature = match Signature::from_compact(&sig[..64]) {
        Ok(r) => r,
        Err(_) => return Err(Error::InvalidSignature),
    };
    let public_key = match hex::decode(public_key_string) {
        Ok(r) => r,
        Err(_) => return Err(Error::InvalidPublicKey),
    };
    let pubkey = match PublicKey::from_slice(&public_key[..]) {
        Ok(r) => r,
        Err(_) => return Err(Error::InvalidPublicKey),
    };
    match SECP256K1_VERIFY.verify(&message, &signature, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn public_key_hash(pubkey: String) -> Result<hash::Hash160b, Error> {
    let bytes = match hex::decode(pubkey) {
        Ok(r) => r,
        Err(_) => return Err(Error::InvalidPublicKey),
    };
    Ok(hash::hash160b(&bytes[1..]))
}

pub fn hex_string_to_private(hex_string: String) -> Result<PrivKey, Error> {
    let mut data: [u8; 32] = [0; 32];
    match hex::decode_to_slice(hex_string, &mut data) {
        Ok(_) => Ok(PrivKey { bytes: data }),
        Err(_) => Err(Error::InvalidPrivateKey),
    }
}

#[test]
fn test_from_slice() {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(
        "0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f",
        &mut bytes as &mut [u8],
    )
    .unwrap();
    let key = PrivKey::from_slice(&bytes);

    assert_eq!(
        key.hex_string(),
        String::from("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f")
    );

    assert_eq!(
        key.public_key(),
        String::from("044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9")
    );

    assert_eq!(
        hex::encode(public_key_hash(key.public_key()).unwrap().0),
        String::from("3f9c20bcec9de520d88d98cbe07ee7b5ded0dac4"),
    );

    hex::decode_to_slice(
        "2cddfe87fe695e09ee430b7f60b4c585a3063613872130baf414537f46732501",
        &mut bytes as &mut [u8],
    )
    .unwrap();
    let sig = key.sign(&bytes);
    assert_eq!(
        hex::encode(&sig[..]),
        String::from("eadf42d2ed96045b6d0060d952d40292a3f04e49867b4b3f96ef14d9d727640d72e4b350b889739330e818eff7341343cc8c9e6d6560513113dde9bfe0d9efa700")
    );
    assert_eq!(verify_sig(&bytes, &sig, key.public_key()).unwrap(), true);
}

#[test]
fn test_new() {
    let key1 = PrivKey::new();
    assert_eq!(key1.public_key().len(), 130);
    let key2 = PrivKey::new();
    assert_ne!(key1.bytes, key2.bytes);
}
