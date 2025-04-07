//! Central system provider operating under sole control of subscribers.

use crate::api::*;
use crate::program;

/// Upon registration, checks integrity of a [Verifier].
#[export_name = "scal3_provider_accept"]
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
#[export_name = "scal3_provider_prove"]
pub extern "C" fn prove(
    randomness: &Randomness,
    provider: &Key,
    verifier_secret: &Secret,
    verifier: &Verifier,
    pk_device: &Key,
    client_data_hash: &Digest,
    pass_secret: &Secret,
    pass: &Pass,
    authenticator: &mut Authenticator,
    proof: &mut Proof,
    client: &mut Client,
) -> bool {
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
