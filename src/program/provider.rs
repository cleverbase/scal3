use crate::api::*;
use crate::domain;
use crate::domain::{pk_recipient_from_bytes, shared_secret_from_bytes, Provider, Result, VerificationError};
use hpke::Serializable;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Write;

pub(crate) fn accept(
    provider: &Key,
    verifier_secret: &Secret,
    verifier: &Verifier,
) -> Result {
    let provider = pk_recipient_from_bytes(provider).ok_or(VerificationError)?;
    let verifier_secret = shared_secret_from_bytes(verifier_secret).ok_or(VerificationError)?;
    let verifier = domain::Verifier::from_bytes(verifier).ok_or(VerificationError)?;
    verifier
        .verify(verifier_secret, &provider)
        .map(|_| ())
        .ok_or(VerificationError)
}

pub(crate) fn challenge(randomness: &Randomness) -> Challenge {
    let provider = domain::Provider {
        randomness: *randomness,
    };
    let (_, commitments) = provider.challenge();
    let mut challenge = [0u8; 66];
    let mut buffer = &mut challenge[..];
    buffer
        .write_all(
            p256::PublicKey::from_sec1_bytes(&commitments.hiding().serialize().unwrap())
                .unwrap()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
    buffer
        .write_all(
            p256::PublicKey::from_sec1_bytes(&commitments.binding().serialize().unwrap())
                .unwrap()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
    challenge
}

pub(crate) fn prove(
    randomness: &Randomness,
    provider: &Key,
    verifier_secret: &Secret,
    verifier: &Verifier,
    pk_device: &Key,
    client_data_hash: &Digest,
    pass_secret: &Secret,
    pass: &Pass,
) -> Option<(Authenticator, Proof, Client)> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(randomness);
    let provider_randomness = Provider { randomness: buf };
    let provider = pk_recipient_from_bytes(provider)?;
    let verifier_secret = shared_secret_from_bytes(verifier_secret)?;
    let verifier = domain::Verifier::from_bytes(verifier)?;
    let pk_device = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_device).ok()?;
    let pass_secret = shared_secret_from_bytes(pass_secret)?;
    let pass = domain::Pass::from_bytes(pass)?;
    let transcript = provider_randomness.prove(&verifier, &pk_device, client_data_hash, &pass, verifier_secret, pass_secret, &provider)?;
    let mut buf_authenticator = [0u8; 48];
    buf_authenticator.copy_from_slice(transcript.authenticator.to_bytes().as_slice());
    let mut buf_proof = [0u8; 64];
    buf_proof.copy_from_slice(transcript.proof.sig_device.to_bytes().as_slice());
    let mut buf_client = [0u8; 129];
    buf_client.copy_from_slice(&transcript.client.to_bytes());
    Some((buf_authenticator, buf_proof, buf_client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge() {
        let randomness = [1u8; 32];
        let challenge = challenge(&randomness);
        println!("{:x?}", challenge);
    }
}
