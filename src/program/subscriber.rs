use std::mem::size_of;
use p256::ecdsa;
use rand::thread_rng;
use crate::{api, Challenge, Device, domain, Identifier, Mask, Pass, Payload, Redemption, Voucher};
use crate::domain::PassDraft;
use crate::subscriber::Signature;

pub(crate) fn redeem(voucher: &Voucher) -> Option<(Redemption, domain::Enrollment)> {
    let voucher = postcard::from_bytes::<domain::Voucher>(voucher).ok()?;
    let (enrollment, redemption) = voucher.redeem(&mut thread_rng())?;
    let redemption: [u8; size_of::<Redemption>()] = postcard::to_allocvec(&redemption)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size");
    Some((redemption, enrollment))
}

pub(crate) fn enroll(
    enrollment: domain::Enrollment,
    validation: &api::Validation,
    mask: &api::Mask,
) -> Option<api::Identifier> {
    let mask = domain::Mask(*mask);
    let validation = postcard::from_bytes(validation).ok()?;
    let identifier = enrollment.complete(validation, mask)?;
    Some(postcard::to_allocvec(&identifier)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size"))
}

pub(crate) fn authenticate(
    identifier: &Identifier,
    device: &Device,
    challenge: &Challenge,
    mask: &Mask,
    payload: &Payload,
) -> Option<PassDraft> {
    let identifier = postcard::from_bytes(identifier).ok()?;
    let challenge = postcard::from_bytes(challenge).ok()?;
    let mask = domain::Mask(*mask);
    let device_vk = ecdsa::VerifyingKey::from_sec1_bytes(device).ok()?;
    let subscriber = domain::Subscriber { device_vk, identifier };
    Some(subscriber.pass(mask, challenge, payload, &mut thread_rng()))
}

pub(crate) fn pass(
    draft: PassDraft,
    device_sig: &Signature,
) -> Option<Pass> {
    let device_sig = ecdsa::Signature::from_bytes(device_sig.into()).ok()?;
    let pass = draft.finalize_with_signature(device_sig);
    let pass: Pass = postcard::to_allocvec(&pass)
        .expect("serialization should not fail")
        .try_into()
        .expect("known size");
    Some(pass)
}
