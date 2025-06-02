#![doc = include_str!("README.md")]

mod program;
mod domain;
mod kem;
mod rng;
pub(crate) mod api;
mod dispatch;
mod ffi;
mod handle;

use std::num::NonZeroU32;
use getrandom::register_custom_getrandom;
pub use api::*;

const CUSTOM_ERROR_CODE: u32 = getrandom::Error::CUSTOM_START + 0;
fn stub_get_random(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::from(NonZeroU32::new(CUSTOM_ERROR_CODE).unwrap()))
}

register_custom_getrandom!(stub_get_random);
