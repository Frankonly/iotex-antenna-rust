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

// pub fn from_string(encodedAddr &str) -> Result<dyn Address, Error>

fn prefix() -> &'static str {
    let mut prefix = MAINNET_PREFIX;
    unsafe {
        if IS_TEST_NET {
            prefix = TESTNET_PREFIX;
        }
    }
    prefix
}
