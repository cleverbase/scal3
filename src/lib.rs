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
//!
//! # Risks
//!
//! - Not all hash functions are checked for proper domain separation. This risk
//!   could be limited by centralizing all hash function definitions for easier
//!   review.
//! - This library does not apply its dependencies everywhere in an idiomatic
//!   way. For example, where dependency constructors are not exposed, the
//!   implementation now relies on serialization/deserialization. Also,
//!   sometimes too low-level types are used, such as `Scalar` instead of
//!   `SecretKey` and `ProjectivePoint` instead of `PublicKey`, which
//!   potentially means missing out on some security features.
//! - The implementation may still be vulnerability to side channel attacks,
//!   such as timing attacks and reading memory that was not zeroized in time.
//!   The security dependencies offer functions to implement this properly.

mod api;
mod group;
mod domain;
mod program;

pub use api::*;
