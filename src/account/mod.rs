use super::{
    address,
    crypto::{self, key},
};

pub mod accounts;

#[derive(Copy, Clone, Debug, PartialEq)]
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

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum AccountError {
    AddressError(address::AddrError),
    CryptoError(crypto::Error),
    AccountExist(account),
    AccountNotExist(address::v1::AddrV1),
}

#[cfg(test)]
mod test {
    use super::{account, accounts::accounts, address::Address, crypto::hash};
    const TEXT: &str = "IoTeX is the auto-scalable and privacy-centric blockchain.";
    const ADDR: &str = "io187wzp08vnhjjpkydnr97qlh8kh0dpkkytfam8j";
    const PUBLIC_KEY: &str = "044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9";
    const PRIVATE_KEY: &str = "0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f";
    #[test]
    fn test_account() {
        let h = hash::hash160b(TEXT.as_bytes());
        assert_eq!(hex::encode(h.0), "93988dc3d2d879f703c7d3f54dcc1b473b27d015");

        let h = hash::hash256b(TEXT.as_bytes());
        assert_eq!(
            hex::encode(h.0),
            "aada23f93a5ed1829ebf1c0693988dc3d2d879f703c7d3f54dcc1b473b27d015"
        );

        let act = match account::hex_string_to_account(String::from(PRIVATE_KEY)) {
            Ok(r) => r,
            Err(e) => panic!(e),
        };
        assert_eq!(act.address().string(), ADDR);
        assert_eq!(act.public_key(), PUBLIC_KEY);

        let act1 = account::private_key_to_account(act.private_key());
        let sig = act1.sign(TEXT.as_bytes());
        println!("{}", hex::encode(h.0));
        assert_eq!(
            hex::encode(&sig[..]),
            String::from("482da72c8faa48ee1ac2cf9a5f9ecd42ee3258be5ddd8d6b496c7171dc7bfe8e75e5d16e7129c88d99a21a912e5c082fa1baab6ba87d2688ebd7d27bb1ab090701")
        );
        assert_eq!(act1.verify(TEXT.as_bytes(), &sig).unwrap(), true);

        let act2 = account::new_account().unwrap();
        let act3 = account::new_account().unwrap();
        assert_ne!(act2.private_key(), act3.private_key())
    }
    #[test]
    fn test_accounts() {
        let mut acts = accounts::new_accounts();
        let act1 = acts.create().unwrap();
        let act2 = acts.create().unwrap();
        assert_ne!(act1, act2);

        match acts.get_account(act1.address) {
            Some(acc) => assert_eq!(acc.private_key(), act1.private_key()),
            None => panic!("failed to get account just created"),
        }

        let act3 = match account::hex_string_to_account(String::from(PRIVATE_KEY)) {
            Ok(r) => r,
            Err(e) => panic!(e),
        };
        match acts.add_account(act3) {
            Some(e) => panic!(e),
            None => (),
        }
        let act4 = acts.get_account(act3.address()).unwrap();
        assert_eq!(act3, act4);

        acts.remove_account(act4.address());
        match acts.get_account(act3.address()) {
            Some(_) => panic!("account should have been removed"),
            None => (),
        }
    }
}
