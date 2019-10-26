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
            Ok(key) => Ok(account::private_key_to_account(key)),
            Err(r) => Err(AccountError::CryptoError(r)),
        }
    }
    // private_key_to_account generates an account from an existing private key
    pub fn private_key_to_account(key: key::PrivKey) -> account {
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

#[cfg(test)]
mod test {
    use super::{account, address::Address, crypto::hash};
    #[test]
    fn test_account() {
        let text = "IoTeX is the auto-scalable and privacy-centric blockchain.";
        let h = hash::hash160b(text.as_bytes());
        assert_eq!(hex::encode(h.0), "93988dc3d2d879f703c7d3f54dcc1b473b27d015");

        let h = hash::hash256b(text.as_bytes());
        assert_eq!(
            hex::encode(h.0),
            "aada23f93a5ed1829ebf1c0693988dc3d2d879f703c7d3f54dcc1b473b27d015"
        );

        let addr = String::from("io187wzp08vnhjjpkydnr97qlh8kh0dpkkytfam8j");
        let private_key =
            String::from("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f");
        let public_key = String::from("044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9");
        let act = match account::hex_string_to_account(String::from(private_key)) {
            Ok(r) => r,
            Err(e) => panic!(e),
        };
        assert_eq!(act.address().string(), addr);
        assert_eq!(act.public_key(), public_key);

        let act1 = account::private_key_to_account(act.private_key());
        let sig1 = act1.sign(text.as_bytes()); // TODO: refactor sign in crate crypo::key
        let sig2 =match hex::decode("482da72c8faa48ee1ac2cf9a5f9ecd42ee3258be5ddd8d6b496c7171dc7bfe8e75e5d16e7129c88d99a21a912e5c082fa1baab6ba87d2688ebd7d27bb1ab090701"){
            Ok(r)=>r,
            Err(e)=>panic!(e),
        };
        assert_eq!(&sig1[..], &sig2[..]);
    }
    // impl PartialEq for [u8; 65] {}
}
