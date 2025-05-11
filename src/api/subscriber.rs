//! User with a device under full control, subscribing to [provider] services.

use crate::api::*;
use crate::domain;
use std::ptr::null_mut;

/// Process handle for passing a challenge.
pub struct Authentication(domain::Authentication);

/// Enrolls the [subscriber] by providing a mask, creating a verifier.
#[export_name = "scal3_subscriber_register"]
pub extern "C" fn register(buffer: *mut Buffer) -> Status {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::BufferError;
    };
    let response = match buffer.deserialize::<SubscriberState>() {
        Ok(request) => match request.handle() {
            None => RegisterResponse::error("missing value"),
            Some(Some(registration)) => RegisterResponse::registration(registration),
            Some(None) => RegisterResponse::error("invalid input"),
        },
        Err(_) => RegisterResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => Status::Ready,
        Err(_) => Status::BufferError,
    }
}

/// Starts passing a challenge.
#[export_name = "scal3_subscriber_authenticate"]
pub extern "C" fn authenticate(buffer: *mut Buffer) -> *mut Authentication {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return null_mut();
    };
    let (authentication, response) = match buffer.deserialize::<AuthenticateRequest>() {
        Ok(request) => match request.handle() {
            None => (null_mut(), AuthenticateResponse::error("missing value")),
            Some(Some((a, d))) => (
                Box::into_raw(Box::new(Authentication(a))),
                AuthenticateResponse::digest(d),
            ),
            Some(None) => (null_mut(), AuthenticateResponse::error("invalid input")),
        },
        Err(_) => (null_mut(), AuthenticateResponse::error("schema mismatch")),
    };
    match buffer.serialize(response) {
        Ok(_) => authentication,
        Err(_) => null_mut(),
    }
}

/// Finishes [Authentication] using a proof.
#[export_name = "scal3_subscriber_pass"]
pub extern "C" fn pass(authentication: *mut Authentication, buffer: *mut Buffer) -> Status {
    let authentication = unsafe { Box::from_raw(authentication) };
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::BufferError;
    };
    let response = match buffer.deserialize::<PassRequest>() {
        Ok(request) => match request.handle(authentication.0) {
            None => PassResponse::error("missing value"),
            Some(Some((k, p))) => PassResponse::result(Attempt {
                sender: Some(k),
                pass: Some(p),
            }),
            Some(None) => PassResponse::error("invalid input"),
        },
        Err(_) => PassResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => Status::Ready,
        Err(_) => Status::BufferError,
    }
}
