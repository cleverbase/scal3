//! User with a device under full control, subscribing to provider services.

use std::ptr::null_mut;
use crate::api::*;
use crate::domain;

/// Process handle for passing a [Challenge].
pub struct Authentication(domain::Authentication);

/// Enrolls the subscriber by providing a [Mask], creating a [Verifier].
#[export_name = "scal3_subscriber_register"]
pub extern "C" fn register(
    mask: &Mask,
    randomness: &Randomness,
    provider: &Key,
    subscriber: &mut Key,
    verifier: &mut Verifier,
) -> bool {
    match program::subscriber::register(mask, randomness, provider) {
        None => false,
        Some((k, v)) => {
            subscriber.copy_from_slice(&k);
            verifier.copy_from_slice(&v);
            true
        }
    }
}

/// Starts passing a [Challenge].
#[export_name = "scal3_subscriber_authenticate"]
pub extern "C" fn authenticate(
    mask: &Mask,
    randomness: &Randomness,
    provider: &Key,
    subscriber: &Key,
    verifier: &Verifier,
    challenge: &Challenge,
    client_data_hash: &Digest,
    digest: &mut Digest,
) -> *mut Authentication {
    match program::subscriber::authenticate(
        mask,
        randomness,
        provider,
        subscriber,
        verifier,
        challenge,
        client_data_hash,
    ) {
        None => null_mut(),
        Some((a, d)) => {
            digest.copy_from_slice(&d);
            Box::into_raw(Box::new(Authentication(a)))
        }
    }
}

/// Finishes [Authentication] using a [Proof].
#[export_name = "scal3_subscriber_pass"]
pub extern "C" fn pass(
    authentication: *mut Authentication,
    proof: &Proof,
    key: &mut Key,
    pass: &mut Pass,
) -> bool {
    let authentication = unsafe { Box::from_raw(authentication) };
    match program::subscriber::pass(authentication.0, proof) {
        None => false,
        Some((k, p)) => {
            key.copy_from_slice(&k);
            pass.copy_from_slice(&p);
            true
        }
    }
}
