use super::*;
use crate::crypto::hash;
use bech32::{self, ToBase32};

// _V1 is a singleton and defines V1 address metadata
pub const _V1: V1 = V1 { address_length: 20 };

pub struct V1 {
    pub address_length: usize,
}

impl V1 {
    // from_string decodes an encoded address string into an address struct
    pub fn from_string(&self, encoded_addr: &str) -> Result<AddrV1, Error> {
        let payload = match self.decode_bech32(encoded_addr) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        self.from_bytes(&payload[..])
    }
    // from_bytes converts a byte array into an address struct
    pub fn from_bytes(&self, bytes: &[u8]) -> Result<AddrV1, Error> {
        if bytes.len() != self.address_length {
            return Err(Error::InvalidAddrLen(bytes.len()));
        };
        let addr = AddrV1 {
            payload: hash::bytes_to_hash160(&bytes[..20]),
        };
        Ok(addr)
    }
    fn decode_bech32(&self, encoded_addr: &str) -> Result<Vec<u8>, Error> {
        let (hrp, grouped) = match bech32::decode(encoded_addr) {
            Ok(r) => r,
            Err(e) => return Err(Error::BechError(e)),
        };
        if hrp != prefix() {
            return Err(Error::AddrPrefixNotMatch);
        }
        match bech32::convert_bits(&grouped[..], 5, 8, false) {
            Ok(r) => Ok(r),
            Err(e) => Err(Error::BechError(e)),
        }
    }
}

pub struct AddrV1 {
    payload: hash::Hash160b,
}

impl Address for AddrV1 {
    // TODO: fix string()'s wrong output
    fn string(&self) -> String {
        let payload = self.payload.0;
        bech32::encode(prefix(), payload.to_base32())
            .expect("Error when encoding bytes into a base32 string.")
    }

    fn bytes(&self) -> &[u8] {
        &self.payload.0
    }
}

#[test]
fn test_address() {
    set_network(false);
    let bytes = match hex::decode("3f9c20bcec9de520d88d98cbe07ee7b5ded0dac4") {
        Ok(r) => r,
        Err(e) => panic!(e),
    };
    let addr1 = match _V1.from_bytes(&bytes[..]) {
        Ok(r) => r,
        Err(e) => panic!(e),
    };
    let addr2 = match _V1.from_string("io187wzp08vnhjjpkydnr97qlh8kh0dpkkytfam8j") {
        Ok(r) => r,
        Err(e) => panic!(e),
    };
    assert_eq!(addr1.bytes(), addr2.bytes());
    assert_eq!(
        hex::encode(addr1.bytes()),
        String::from("3f9c20bcec9de520d88d98cbe07ee7b5ded0dac4")
    );
    assert_eq!(
        addr1.string(),
        String::from("io187wzp08vnhjjpkydnr97qlh8kh0dpkkytfam8j")
    )
}
