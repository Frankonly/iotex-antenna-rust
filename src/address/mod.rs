use std::{error::Error, fmt};
pub mod v1;

// MAINNET_PREFIX is the prefix added to the human readable address of mainnet
const MAINNET_PREFIX: &str = "io";
// TESTNET_PREFIX is the prefix added to the human readable address of testnet
const TESTNET_PREFIX: &str = "it";

// ZERO_ADDRESS is the IoTeX address whose hash160 is all zero
const ZERO_ADDRESS: &str = "io1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqd39ym7";

static mut IS_TEST_NET: bool = false;

pub fn set_network(is_test_net: bool) {
    unsafe {
        IS_TEST_NET = is_test_net;
    }
}

pub trait Address {
    fn string(&self) -> String;
    fn bytes(&self) -> &[u8];
}

pub fn from_string(encoded_addr: &str) -> Result<v1::AddrV1, AddrError> {
    v1::_V1.from_string(encoded_addr)
}

pub fn from_bytes(bytes: &[u8]) -> Result<v1::AddrV1, AddrError> {
    v1::_V1.from_bytes(bytes)
}

fn prefix() -> &'static str {
    let mut prefix = MAINNET_PREFIX;
    unsafe {
        if IS_TEST_NET {
            prefix = TESTNET_PREFIX;
        }
    }
    prefix
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum AddrError {
    BechError(bech32::Error),
    InvalidAddrLen(usize),
    AddrPrefixNotMatch,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddrError::BechError(e) => write!(f, "bech32 error, {})", e.description()),
            AddrError::InvalidAddrLen(n) => write!(f, "invalid address length ({})", n),
            AddrError::AddrPrefixNotMatch => write!(f, "address's prefix doesn't match"),
        }
    }
}

impl Error for AddrError {
    fn description(&self) -> &str {
        match *self {
            AddrError::BechError(_) => "bech32 error",
            AddrError::InvalidAddrLen(_) => "invalid address length",
            AddrError::AddrPrefixNotMatch => "address's prefix doesn't match",
        }
    }
}
