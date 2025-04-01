use crate::api::*;
use crate::domain;
use crate::domain::{challenge_from_bytes, pk_recipient_from_bytes, pk_sender_from_bytes, KemPublicKey};
use hpke::{Deserializable, Serializable};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub(crate) fn register(
    mask: &Mask,
    randomness: &Randomness,
    provider: &Key,
) -> Option<(Key, Verifier)> {
    let provider = p256::PublicKey::from_sec1_bytes(provider).ok()?;
    let pk_kem_provider: KemPublicKey = KemPublicKey::from_bytes(&provider.to_encoded_point(false).as_bytes()).ok()?;
    let mut rng = ChaCha20Rng::from_seed(*randomness);
    let verifier = domain::Verifier::new(&pk_kem_provider, mask, &mut rng);
    let mut subscriber: Key = [0u8; 33];
    subscriber.copy_from_slice(
        p256::PublicKey::from_sec1_bytes(&verifier.pk_kem_subscriber.to_bytes())
            .ok()?
            .to_encoded_point(true)
            .as_bytes(),
    );
    let mut verifier_array = [0u8; 250];
    verifier_array.copy_from_slice(&verifier.to_bytes());
    Some((subscriber, verifier_array))
}

pub(crate) fn authenticate(
    mask: &Mask,
    randomness: &Randomness,
    provider: &Key,
    subscriber: &Key,
    verifier: &Verifier,
    challenge: &Challenge,
    client_data_hash: &Digest,
) -> Option<(domain::Authentication, Digest)> {
    let provider = pk_recipient_from_bytes(provider)?;
    let subscriber = pk_sender_from_bytes(subscriber)?;
    let verifier = domain::Verifier::from_bytes(verifier)?;
    if subscriber.to_bytes() != verifier.pk_kem_subscriber.to_bytes() {
        return None
    }
    let challenge = challenge_from_bytes(challenge)?;
    let mut rng = ChaCha20Rng::from_seed(*randomness);
    let authentication = verifier.authenticate(mask, &challenge, &provider, &mut rng, client_data_hash);
    let digest = authentication.to_device_sign;
    Some((authentication, digest))
}

pub(crate) fn pass(authentication: domain::Authentication, proof: &Proof) -> Option<(Key, Pass)> {
    let bytes = GenericArray::clone_from_slice(proof);
    let signature = p256::ecdsa::Signature::from_bytes(&bytes).ok()?;
    let pass = &authentication.finalize(&signature);
    let key = p256::PublicKey::from_sec1_bytes(&authentication.pk_s.to_bytes()).ok()?;
    let mut buf = [0u8; 33];
    buf.copy_from_slice(key.to_encoded_point(true).as_bytes());
    Some((buf, pass.to_bytes()))
}
