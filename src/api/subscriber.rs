//! User with a device under full control, subscribing to provider services.

use std::ptr::null_mut;
use crate::api::*;
use crate::domain;

/// Process handle for passing a [Challenge].
pub struct Authentication(domain::Authentication);

/// Enrolls the subscriber by providing a [Mask], creating a [Verifier].
#[no_mangle]
pub extern "C" fn register(
    mask: *const Mask,
    randomness: *const Randomness,
    provider: *const Key,
    subscriber: *mut Key,
    verifier: *mut Verifier,
) -> bool {
    let mask = unsafe { &*mask };
    let randomness = unsafe { &*randomness };
    let provider = unsafe { &*provider };
    let subscriber = unsafe { &mut *subscriber };
    let verifier = unsafe { &mut *verifier };
    match program::subscriber::register(mask, randomness, provider) {
        None => false,
        Some((k, v)) => {
            subscriber.copy_from_slice(&k);
            verifier.copy_from_slice(&v);
            true
        }
    }
}

// pub struct Authentication2 {
//     content: String
// }

// #[export_name = "scal3_authenticate"]
// pub unsafe extern "C" fn authenticate2(
//     // authentication: *mut *mut Authentication2, // risk: the requester allocates memory to store the pointer; better to just return the pointer
//     req_buf: *const u8,
//     res_buf: *mut u8,
// ) -> *mut Authentication2 { // no just return *mut Authentication
//     let a = Authentication2 { content: "hello".to_string() };
//     // assert_ne!(authentication, null_mut());
//     // *authentication = Box::into_raw(Box::new(a));
//     // *authentication
//     Box::into_raw(Box::new(a))
// }
// 
// #[export_name = "scal3_pass"]
// pub unsafe extern "C" fn pass2(
//     authentication: *mut Authentication2,
//     req_buf: *const u8,
//     res_buf: *mut u8,
// ) -> u8 {
//     let a = Box::from_raw(authentication);
//     res_buf.copy_from(a.content.as_ptr(), a.content.len());
//     0
// }

/// Starts passing a [Challenge].
#[no_mangle]
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
#[no_mangle]
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
