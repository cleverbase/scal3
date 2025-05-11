//! Central system provider operating under sole control of subscribers.

use crate::api::*;
use crate::buffer::Buffer;

/// Upon registration, checks the integrity of a verifier.
/// 
/// # Risks
/// 
/// - Does not verify the device public key.
#[no_mangle]
pub extern "C" fn accept(buffer: *mut Buffer) -> Status {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::InvalidPointer;
    };
    let response = match buffer.deserialize::<ProviderState>() {
        Ok(request) => match request.handle() {
            None => AcceptResponse::error("missing value"),
            Some(Ok(())) => AcceptResponse::result("accepted"),
            Some(Err(_)) => AcceptResponse::result("rejected"),
        }
        Err(_) => AcceptResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => Status::Done,
        Err(_) => Status::SerializationError,
    }
}

/// Creates a challenge based on randomness derived from challenge metadata.
#[no_mangle]
pub extern "C" fn challenge(buffer: *mut Buffer) -> Status {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::InvalidPointer;
    };
    let response = match buffer.deserialize::<ChallengeRequest>() {
        Ok(request) => match request.handle() {
            None => ChallengeResponse::error("missing value"),
            Some(c) => ChallengeResponse::challenge(c),
        }
        Err(_) => ChallengeResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => Status::Done,
        Err(_) => Status::SerializationError,
    }
}

/// Finishes authentication by creating evidence that the pass is correct.
#[export_name = "scal3_provider_prove"]
pub extern "C" fn prove(buffer: *mut Buffer) -> Status {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::InvalidPointer;
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
        Ok(_) => Status::Done,
        Err(_) => Status::SerializationError,
    }
}
