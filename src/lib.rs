#![doc = include_str!("README.md")]

pub(crate) mod api;
mod dispatch;
mod domain;
mod ffi;
mod handle;
mod kem;
mod program;
mod rng;

use api::*;
pub use dispatch::dispatch;
pub use ffi::*;
use getrandom::register_custom_getrandom;
use std::num::NonZeroU32;

const CUSTOM_ERROR_CODE: u32 = getrandom::Error::CUSTOM_START + 0;
fn stub_get_random(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::from(
        NonZeroU32::new(CUSTOM_ERROR_CODE).unwrap(),
    ))
}

register_custom_getrandom!(stub_get_random);
