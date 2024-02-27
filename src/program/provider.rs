use crate::{api, Challenge, domain, Mask, Randomness, Redemption, Validation, Voucher};
use crate::domain::{Provider, Subscriber, Validating};
use crate::group::Element;

pub(crate) fn vouch(
    randomness: &Randomness,
) -> Voucher {
    let (_, payload) = Provider { randomness: *randomness }.vouch();
    postcard::to_allocvec(&payload)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size")
}

pub(crate) fn process(
    randomness: &Randomness,
    redemption: &Redemption,
) -> Option<Validating> {
    let provider = Provider::from(*randomness);
    let redemption = postcard::from_bytes(redemption).ok()?;
    provider.validate(redemption)
}

pub(crate) fn validate(
    draft: Validating,
    mask: &Mask,
) -> Validation {
    let mask = domain::Mask(*mask);
    let validation = draft.finalize_with_mask(mask);
    postcard::to_allocvec(&validation)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size")
}

#[derive(Debug)]
pub(crate) enum AuthorizationError {
    InvalidInput,
    Unauthorized,
}

pub(crate) fn authorize(
    validation: &api::Validation,
    identifier: &api::Identifier,
) -> Result<(), AuthorizationError> {
    let validation: domain::Validation = postcard::from_bytes(validation)
        .map_err(|_| AuthorizationError::InvalidInput)?;
    let identifier = postcard::from_bytes(identifier)
        .map_err(|_| AuthorizationError::InvalidInput)?;
    if validation.authorize(&identifier) { Ok(()) } else {
        Err(AuthorizationError::Unauthorized)
    }
}

pub(crate) fn challenge(
    randomness: &Randomness,
) -> Challenge {
    let (_, challenge) = Provider { randomness: *randomness }.challenge();
    postcard::to_allocvec(&challenge)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size")
}

#[derive(Debug)]
pub enum ProofError {
    SyntaxError,
    ContentError(domain::ProofError),
}

pub(crate) fn prove(
    randomness: &api::Randomness,
    identifier: &api::Identifier,
    device: &api::Device,
    mask: &api::Mask,
    payload: &api::Payload,
    pass: &api::Pass,
) -> Result<api::Evidence, ProofError> {
    let mask = domain::Mask(*mask);
    let pass = postcard::from_bytes(pass).map_err(|_| ProofError::SyntaxError)?;
    let identifier = postcard::from_bytes(identifier)
        .map_err(|_| ProofError::SyntaxError)?;
    let device: Element = postcard::from_bytes(device)
        .map_err(|_| ProofError::SyntaxError)?;
    let provider = Provider::from(*randomness);
    let subscriber = Subscriber { device_vk: device.into(), identifier };
    let evidence = provider.prove(&subscriber, mask, payload, pass)
        .map_err(|e| ProofError::ContentError(e))?;
    Ok(postcard::to_allocvec(&evidence)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size"))
}
