use crate::{api, domain, group};

pub(crate) mod provider;
pub(crate) mod subscriber;

pub fn verify(
    identifier: &api::Identifier,
    device: &api::Device,
    payload: &api::Payload,
    evidence: &api::Evidence,
) -> Option<domain::Evidence> {
    let identifier: domain::Identifier = postcard::from_bytes(identifier).ok()?;
    let device: group::Element = postcard::from_bytes(device).ok()?;
    let evidence: domain::Evidence = postcard::from_bytes(evidence).ok()?;
    let subscriber = domain::Subscriber { device_vk: device.into(), identifier };
    subscriber.verify(payload, &evidence).then(|| evidence)
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use p256::ecdsa;
    use rand::{random, thread_rng};
    use signature::Signer;
    use crate::program::{provider, subscriber};
    use crate::{Mask, Randomness};

    #[test]
    fn test_all() {
        let mut randomness = [0; size_of::<Randomness>()];
        randomness.fill_with(random);
        let voucher = provider::vouch(&randomness);
        let (redemption, enrollment) = subscriber::redeem(&voucher).unwrap();
        let process = provider::process(&randomness, &redemption).unwrap();
        let mut provider_mask = [0; size_of::<Mask>()];
        provider_mask.fill_with(random);
        let validation = provider::validate(process, &provider_mask);
        let mut subscriber_mask = [0; size_of::<Mask>()];
        subscriber_mask.fill_with(random);
        let identifier = subscriber::enroll(enrollment, &validation, &subscriber_mask).unwrap();
        provider::authorize(&validation, &identifier).unwrap();
        let device = ecdsa::SigningKey::random(&mut thread_rng());
        let device_vk = device.verifying_key().clone().to_encoded_point(true)
            .to_bytes().to_vec().try_into().unwrap();
        randomness.fill_with(random);
        let challenge = provider::challenge(&randomness);
        let payload = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}"
            .to_vec()
            .try_into()
            .unwrap();
        let passing = subscriber::authenticate(
            &identifier,
            &device_vk,
            &challenge,
            &subscriber_mask,
            &payload
        ).unwrap();
        let (device_sig, _) = device.sign(&passing.data_under_device_sig);
        let device_sig = device_sig.to_bytes().try_into().unwrap();
        let pass = subscriber::pass(passing, &device_sig).unwrap();
        let evidence = provider::prove(
            &randomness,
            &identifier,
            &device_vk,
            &provider_mask,
            &payload,
            &pass,
        ).unwrap();
        println!("randomness {:?}", hex::encode(randomness));
        println!("identifier {:?}", hex::encode(identifier));
        println!("device {:?}", hex::encode(device_vk));
        println!("mask {:?}", hex::encode(provider_mask));
        println!("payload {:?}", hex::encode(payload.0));
        println!("pass {:?}", hex::encode(pass));
        println!("evidence {:?}", hex::encode(evidence));
    }
}
