//! Central system provider operating under sole control of subscribers.

use crate::api::*;
use crate::program;

/// Upon registration, checks integrity of a [Verifier].
#[no_mangle]
pub extern "C" fn accept(provider: &Key, verifier_secret: &Secret, verifier: &Verifier) -> bool {
    program::provider::accept(provider, verifier_secret, verifier).is_ok()
}

/// Creates a [Challenge] based on [Randomness] derived from challenge metadata.
//#[wasm_bindgen]
#[no_mangle]
pub extern "C" fn challenge(randomness: *const Randomness, challenge: *mut Challenge) {
    assert!(!randomness.is_null());
    assert!(!challenge.is_null());
    let randomness = unsafe { &*randomness };
    let challenge = unsafe { &mut *challenge };
    challenge.copy_from_slice(&program::provider::challenge(randomness));
}

/// Finishes authentication by creating evidence that [Pass] is correct.
#[no_mangle]
pub extern "C" fn prove(
    randomness: *const Randomness,
    provider: *const Key,
    verifier_secret: *const Secret,
    verifier: *const Verifier,
    pk_device: *const Key,
    client_data_hash: *const Digest,
    pass_secret: *const Secret,
    pass: *const Pass,
    authenticator: *mut Authenticator,
    proof: *mut Proof,
    client: *mut Client,
) -> bool {
    let randomness = unsafe { &*randomness };
    let provider = unsafe { &*provider };
    let verifier_secret = unsafe { &*verifier_secret };
    let verifier = unsafe { &*verifier };
    let pk_device = unsafe { &*pk_device };
    let client_data_hash = unsafe { &*client_data_hash };
    let pass_secret = unsafe { &*pass_secret };
    let pass = unsafe { &*pass };
    let authenticator = unsafe { &mut *authenticator };
    let proof = unsafe { &mut *proof };
    let client = unsafe { &mut *client };
    match program::provider::prove(
        randomness,
        provider,
        verifier_secret,
        verifier,
        pk_device,
        client_data_hash,
        pass_secret,
        pass
    ) {
        None => false,
        Some((a, p, c)) => {
            authenticator.copy_from_slice(&a);
            proof.copy_from_slice(&p);
            client.copy_from_slice(&c);
            true
        }
    }
}
