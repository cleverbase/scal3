#![doc = include_str!("README.md")]
//! # Examples
//!
//! All [provider] functions are pure, enabling a mostly stateless server
//! implementation.
//!
//! ## Enrollment
//!
//! Aborting upon failure, the [provider] and [subscriber] execute their
//! assigned functions in this order:
//!
//! 1. [provider]: derive [Randomness], [provider::vouch], and send a [Voucher];
//! 2. [subscriber::redeem] and send a [Redemption];
//! 3. [provider::process], derive a [Mask], [provider::validate], and send
//!    [Validation];
//! 4. [subscriber]: derive a [Mask], [subscriber::enroll], and send an
//!    [Identifier];
//! 5. [provider::authorize].
//!
//! ## Authentication
//!
//! Aborting upon failure:
//!
//! 1. [provider]: derive [Randomness], [provider::challenge], and send a
//!    [Challenge];
//! 2. [subscriber]: derive a [Mask], [subscriber::authenticate], create a
//!    device signature, [subscriber::pass], and send a [Pass];
//! 3. [provider::prove], and log [Evidence].
//!
//! ## Auditing
//!
//! The [subscriber] or any other party with access can [verify] the [Evidence].

mod api;
mod group;
mod domain;
mod program;

pub use api::*;
