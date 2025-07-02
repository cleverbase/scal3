#![cfg_attr(all(target_os = "linux", target_env = "musl"), no_std)]
#![doc = include_str!("README.md")]

#[cfg(test)]
extern crate std;

extern crate alloc;

#[cfg(all(target_os = "linux", target_env = "musl"))]
mod runtime;

pub(crate) mod api;
mod dispatch;
mod domain;
mod ffi;
mod handle;
mod kem;
mod program;
mod rng;

use api::*;
use core::num::NonZeroU32;
pub use dispatch::dispatch;
pub use ffi::*;
use getrandom::register_custom_getrandom;

const CUSTOM_ERROR_CODE: u32 = getrandom::Error::CUSTOM_START + 0;
fn stub_get_random(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::from(
        NonZeroU32::new(CUSTOM_ERROR_CODE).unwrap(),
    ))
}

register_custom_getrandom!(stub_get_random);
