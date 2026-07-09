//! Shared primitives for Tana Rust CLIs.
//!
//! This crate intentionally exposes only the pieces that are ready to be shared:
//! the common token file and linkhash `whoami` resolution.

pub mod token_file;
pub mod whoami;

pub use token_file::{SecretToken, TokenStore};
pub use whoami::{Identity, LinkhashClient, Principal};
