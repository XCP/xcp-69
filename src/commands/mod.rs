//! Command handlers for each subcommand

pub mod setup;
pub mod patch_funding;
pub mod prepare_funding;
pub mod finalize_parents;

pub use setup::*;
pub use patch_funding::*;
pub use prepare_funding::*;
pub use finalize_parents::*;