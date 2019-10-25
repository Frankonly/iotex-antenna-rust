use super::{
    address,
    crypto::{self, key},
};

pub mod accounts;

pub struct account {
    private: key::PrivKey,
    address: address::v1::AddrV1,
}

impl account {
    // new_account generates a new account
    pub fn new_account() -> Result<account, AccountError> {
        let new_key = key::PrivKey::new();
        let hash = match key::public_key_hash(new_key.public_key()) {
            Ok(r) => r.0,
            Err(e) => panic!(e),
        };
        let addr = match address::from_bytes(&hash) {
            Ok(r) => r,
            Err(e) => return Err(AccountError::AddressError(e)),
        };
        Ok(account {
            private: new_key,
            address: addr,
        })
    }
    // hex_string_to_account generates an account from private key string
    pub fn hex_string_to_account(private_string: String) -> Result<account, AccountError> {
        match key::hex_string_to_private(private_string) {
            Ok(key) => Ok(account::private_to_account(key)),
            Err(r) => Err(AccountError::CryptoError(r)),
        }
    }
    // private_to_account generates an account from an existing private key
    pub fn private_to_account(key: key::PrivKey) -> account {
        let hash = match key::public_key_hash(key.public_key()) {
            Ok(r) => r,
            Err(e) => panic!(e),
        };
        let addr = match address::from_bytes(&hash.0) {
            Ok(r) => r,
            Err(e) => panic!(e),
        };
        account {
            private: key,
            address: addr,
        }
    }
    // address returns the IoTeX address
    pub fn address(&self) -> address::v1::AddrV1 {
        self.address
    }
    // private_key return the embedded private key
    pub fn private_key(&self) -> key::PrivKey {
        self.private
    }
    // public_key returns the embedded public key string
    pub fn public_key(&self) -> String {
        self.private.public_key()
    }
    // sign signs the message using the private key
    pub fn sign(&self, data: &[u8]) -> [u8; 65] {
        self.private.sign(data)
    }
    // verify verifies the message using the public key
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, AccountError> {
        match key::verify_sig(data, sig, self.private.public_key()) {
            Ok(r) => Ok(r),
            Err(e) => Err(AccountError::CryptoError(e)),
        }
    }
}

pub enum AccountError {
    AddressError(address::AddrError),
    CryptoError(crypto::Error),
}
