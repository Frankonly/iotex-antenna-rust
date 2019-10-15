pub mod constants;
pub mod hash;

use rand::rngs::OsRng;
use secp256k1::{key, Secp256k1, Signature as secpSignature};
use std::fmt;

pub trait PublicKey {
    fn bytes(&self) -> &[u8];
    fn hex_string(&self) -> String;
    fn hash(&self) -> &[u8];
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool;
}

pub trait PrivateKey {
    fn bytes(&self) -> &[u8];
    fn hex_string(&self) -> String;
    fn publicKey(&self) -> dyn PublicKey;
    fn sign(&self, data: &[u8]) -> &[u8];
    fn zero(&self);
}

struct PrivKey(key::SecretKey);

impl fmt::Display for PrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

struct PubKey(key::PublicKey);

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

pub struct Signature(pub [u8; 64]);

impl PrivKey {
    pub fn public_key(&self) -> PubKey {
        let secp = Secp256k1::signing_only();
        PubKey(key::PublicKey::from_secret_key(&secp, &self.0))
    }

    pub fn from_slice(raw: &[u8]) -> Self {
        let key = key::SecretKey::from_slice(raw).expect("invalid private key");
        PrivKey(key)
    }

    pub fn sign(&self, hash: &hash::Hash256b) -> Signature {
        let secp = Secp256k1::signing_only();
        let hash = &secp256k1::Message::from_slice(&hash.0).expect("invalid 256 bits hash");
        let sig = secp.sign(hash, &self.0);
        Signature(secpSignature::serialize_compact(&sig))
    }
}

pub fn generate_key() -> Box<dyn PrivateKey> {
    let mut rng = OsRng::new().expect("filed to get OsRng");
    // PrivKey(key::SecretKey::new(&mut rng))
    // TODO: impl PrivateKey for PrivKey
}
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_key() {
        let x = generate_key();
        let y = generate_key();
        assert!(x.0 != y.0);
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (private_key, public_key) = secp.generate_keypair(&mut rng);
        let pri_key = PrivateKey(private_key);
        let pub_key = PublicKey(public_key);
        assert_eq!(pri_key.public_key().0, pub_key.0);
        let key_string = "905636ba107ecfc8b8c1479bf91adeb8bc4fa03405a869a0bd3feb91d3a3e808";
        let key = hex::decode(key_string).expect("invalid private key");
        let key = PrivateKey::from_slice(&key[..]);
        println!("{}", key.public_key());
        // TODO: the public key printed from ioctl is different, which is
        // '04ea4a33700e707a2b823e3aed6d98c372b37f707a3868303ca8d45c296e473bd2e2096ac9a9fb94e90ed71de5e6f567c674b62023b634d1142d13045f38d0ecf3'
    }
}
