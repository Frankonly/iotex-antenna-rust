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
    pub fn from_string(&self, encodedAddr: &str) -> Result<AddrV1, Error> {
        let payload = match self.decode_bech32(encodedAddr) {
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
            payload: hash::hash160b(bytes),
        };
        Ok(addr)
    }
    fn decode_bech32(&self, encodedAddr: &str) -> Result<Vec<u8>, Error> {
        let (hrp, grouped) = match bech32::decode(encodedAddr) {
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
    fn string(&self) -> String {
        let payload = self.payload.0;
        let grouped = bech32::convert_bits(&payload[..], 8, 5, true)
            .expect("Error when grouping the payload into 5 bit groups.");
        bech32::encode(prefix(), grouped.to_base32())
            .expect("Error when encoding bytes into a base32 string.")
    }

    fn bytes(&self) -> &[u8] {
        &self.payload.0
    }
}

// TODO: write several test after crypto part is finished
