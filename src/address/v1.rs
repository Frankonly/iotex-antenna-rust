use super::*;
use crate::crypto::hash;
use bech32;
use std::error;

// _v1 is a singleton and defines V1 address metadata
pub const _v1: V1 = V1 { address_length: 20 };

pub enum Error {
    BechError(bech32::Error),
    InvalidAddrLen(usize),
    AddrPrefixNotMatch,
}

pub struct V1 {
    pub address_length: usize,
}

impl V1 {
    // from_string decodes an encoded address string into an address struct
    fn from_string(&self, encodedAddr: &str) -> Result<AddrV1, Error> {
        let payload = match self.decode_bech32(encodedAddr) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        self.from_bytes(payload)
    }
    // from_bytes converts a byte array into an address struct
    fn from_bytes(&self, bytes: Vec<u8>) -> Result<AddrV1, Error> {
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

impl AddrV1 {}

// func (v *v1) FromString(encodedAddr string) (*AddrV1, error) {
// 	payload, err := v.decodeBech32(encodedAddr)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return v.FromBytes(payload)
// }

// FromBytes converts a byte array into an address struct
// func (v *v1) FromBytes(bytes []byte) (*AddrV1, error) {
// 	if len(bytes) != v.address_length {
// 		return nil, errors.Wrapf(ErrInvalidAddr, "invalid address length in bytes: %d", len(bytes))
// 	}
// 	return &AddrV1{
// 		payload: hash.BytesToHash160(bytes),
// 	}, nil
// }
