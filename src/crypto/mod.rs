mod hash;

use rand::rngs::OsRng;
use secp256k1::{key, Secp256k1};
use std::fmt;

pub struct Private_key {
    private_key: key::SecretKey,
}

impl fmt::Display for Private_key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.private_key, f)
    }
}

pub struct Public_key {
    public_key: key::PublicKey,
}

// impl Private_key {
//     pub fn public_key(&self) -> Public_key{
//         let pub_key = Public_key{
//             public_key:key::PublicKey::from_secret_key()};
//     }
// }

pub fn generate_key() -> Private_key {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let new_key = Private_key {
        private_key: key::SecretKey::new(&mut rng),
    };
    new_key
}

mod tests {
    use super::*;
    #[test]
    fn test_generate_keys() {
        let x = generate_key();
        let y = generate_key();
        assert!(x.private_key != y.private_key);
    }
}
