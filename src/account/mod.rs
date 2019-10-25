use super::{address, crypto::key};

pub mod accounts;

pub struct account {
    private: key::PrivKey,
    address: address::v1::AddrV1,
}

impl account {
    // new_account generates a new account
    pub fn new_account() -> Result<account, AccountError> {
        let new_key = key::PrivKey::new();
        let hash = match key::pubkey_hash(new_key.public_key()) {
            Ok(r) => r.0,
            Err(e) => panic!(e),
        };
        let addr = match address::from_bytes(&hash) {
            Ok(r) => r,
            Err(e) => return Err(AccountError::GenerateAccountFail(e)),
        };
        Ok(account {
            private: new_key,
            address: addr,
        })
    }
    // hex_string_to_account generates an account from private key string
    pub fn hex_string_to_account(private_string: String) -> Result<account, AccountError> {}
}

pub enum AccountError {
    GenerateAccountFail(address::AddrError),
}
