//! Central system provider operating under sole control of subscribers.

use crate::api::*;
use crate::buffer::Buffer;
use crate::program;

struct AcceptRequest {
    interaction: Interaction, // has too much info: also device pk. would be good to verify though
}

/// Upon registration, checks the integrity of a verifier.
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

impl ProveRequest {
    fn handle(&self) -> Option<Option<(Authenticator, Proof, Client)>> {
        Some(program::provider::prove(
            &self.randomness?,
            &self.interaction.provider?,
            &self.interaction.secret?,
            &self.interaction.credential.verifier?,
            &self.interaction.credential.device?,
            &self.client_data_hash?,
            &self.pass_secret?,
            &self.pass?,
        ))
    }
}

impl ProveResponse {
    fn failure() -> Self {
        Self {
            result: None,
            error: None,
        }
    }

    fn result(value: Transcript) -> Self {
        Self {
            result: Some(value),
            error: None,
        }
    }

    fn error(value: &str) -> Self {
        Self {
            result: None,
            error: Some(value.to_string()),
        }
    }
}

/// Finishes authentication by creating evidence that the pass is correct.
#[export_name = "scal3_provider_prove"]
pub extern "C" fn prove(buffer: *mut Buffer) -> VerifyStatus {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return VerifyStatus::InvalidPointer;
    };
    let response = match buffer.deserialize::<ProveRequest>() {
        Ok(request) => match request.handle() {
            None => ProveResponse::error("missing value"),
            Some(Some((a, p, c))) => ProveResponse::result(Transcript {
                authenticator: Some(a),
                proof: Some(p),
                client: Some(c),
            }),
            Some(None) => ProveResponse::failure(),
        },
        Err(_) => ProveResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => VerifyStatus::Done,
        Err(_) => VerifyStatus::SerializationError,
    }
}
