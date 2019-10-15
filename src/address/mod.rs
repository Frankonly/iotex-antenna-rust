pub mod v1;

// MainnetPrefix is the prefix added to the human readable address of mainnet
const MainnetPrefix: &str = "io";
// TestnetPrefix is the prefix added to the human readable address of testnet
const TestnetPrefix: &str = "it";

// ZeroAddress is the IoTeX address whose hash160 is all zero
const ZeroAddress: &str = "io1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqd39ym7";

static IsTestNet: bool = false;

pub fn setNetwork(isTestNet: bool) {
    IsTestNet = isTestNet;
}

pub trait Address {
    fn string(&self) -> String;
    fn bytes(&self) -> &[u8];
}

// pub fn from_string(encodedAddr &str) -> Result<dyn Address, Error>

fn prefix() -> &'static str {
    let prefix = MainnetPrefix;
    if IsTestNet {
        prefix = TestnetPrefix;
    }
    prefix
}
