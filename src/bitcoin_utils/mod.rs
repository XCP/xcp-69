//! Bitcoin utilities: vanity grinding, PSBT building, key management, tapscript

pub mod vanity;
pub mod psbt;
pub mod keys;
pub mod tapscript;
pub mod tagged;

pub use vanity::*;
pub use psbt::*;
pub use keys::*;
pub use tapscript::*;
pub use tagged::*;