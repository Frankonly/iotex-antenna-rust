use lazy_static::lazy_static;
use secp256k1::Error as secpError;

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref SECP256K1_VERIFY: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub mod constants;
pub mod hash;
pub mod key;

pub enum Error {
    InvalidMessageLen(usize),
    InvalidSignature,
    InvalidPublicKey,
}
