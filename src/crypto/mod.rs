use lazy_static::lazy_static;
use std::{error, fmt};

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref SECP256K1_VERIFY: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub mod constants;
pub mod hash;
pub mod key;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    InvalidMessageLen(usize),
    InvalidSignature,
    InvalidPrivateKey,
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidMessageLen(n) => write!(f, "invalid message length ({})", n),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::InvalidPrivateKey => write!(f, "invalid private key"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidMessageLen(_) => "invalid message length",
            Error::InvalidSignature => "invalid signature",
            Error::InvalidPrivateKey => "Invalid private key",
            Error::InvalidPublicKey => "invalid public key",
        }
    }
}
