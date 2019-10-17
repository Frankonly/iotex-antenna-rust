use lazy_static::lazy_static;

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub mod constants;
pub mod hash;
pub mod key;