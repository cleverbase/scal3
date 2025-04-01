use crate::api::*;
use crate::domain;
use crate::domain::{pk_from_bytes, Result, VerificationError};

pub(crate) mod provider;
pub(crate) mod subscriber;

pub(crate) fn verify(
    verifier: &Verifier,
    pk_device: &Key,
    client_data_hash: &Digest,
    authenticator: &Authenticator,
    proof: &Proof,
    client: &Client
) -> Result {
    let verifier = domain::Verifier::from_bytes(verifier).ok_or(VerificationError)?;
    let pk_device = pk_from_bytes(pk_device).ok_or(VerificationError)?;
    let authenticator = domain::AuthenticatorExtensionTranscript::from_bytes(authenticator).ok_or(VerificationError)?;
    let proof = domain::AuthenticatorProof::from_bytes(proof).ok_or(VerificationError)?;
    let client = domain::ClientExtensionTranscript::from_bytes(client).ok_or(VerificationError)?;
    let transcript = domain::Transcript {
        authenticator,
        proof,
        client,
    };
    verifier.verify_transcript(&transcript, &pk_device, &client_data_hash)
}

#[cfg(test)]
mod tests {
    use crate::api::{Key, Proof, Secret};
    use crate::program::{provider, subscriber, verify};
    use crate::rng::ReproducibleRng;
    use hpke::kem::DhP256HkdfSha256;
    use hpke::{Deserializable, Kem, Serializable};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{ecdsa, NistP256, NonZeroScalar};
    use rand_chacha::rand_core::SeedableRng;
    use signature::hazmat::PrehashSigner;

    fn dh(sk_r: &<DhP256HkdfSha256 as Kem>::PrivateKey, pk_s: &Key) -> Secret {
        let pk_s = p256::PublicKey::from_sec1_bytes(pk_s).unwrap();
        let pk_s = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(
            pk_s.to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        let pk = p256::PublicKey::from_sec1_bytes(&pk_s.to_bytes()).unwrap();
        let sk: NonZeroScalar = NonZeroScalar::from_repr(sk_r.to_bytes()).unwrap();
        let secret = p256::ecdh::diffie_hellman::<NistP256>(sk, pk.as_affine());
        let bytes = secret.raw_secret_bytes().clone();
        bytes.into()
    }

    fn pk(pk_s: &<DhP256HkdfSha256 as Kem>::PublicKey) -> Key {
        let key = p256::PublicKey::from_sec1_bytes(&pk_s.to_bytes()).unwrap();
        key.to_encoded_point(true).as_bytes().try_into().unwrap()
    }

    #[test]
    fn end_to_end_test() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let (sk_r, pk_r) = DhP256HkdfSha256::gen_keypair(&mut rng);
        let provider: Key = pk(&pk_r);

        let sk_device = ecdsa::SigningKey::random(&mut ReproducibleRng(&mut rng));
        let pk_device = *sk_device.verifying_key();
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&pk_device.to_encoded_point(true).to_bytes());
        let pk_device: Key = arr;

        let mask = [0u8; 32];
        let randomness = [0u8; 32];
        let (subscriber, verifier) = subscriber::register(&mask, &randomness, &provider).unwrap();

        provider::accept(&provider, &dh(&sk_r, &subscriber), &verifier).unwrap();

        let randomness = [1u8; 32];
        let challenge = provider::challenge(&randomness);

        let mask = [0u8; 32];
        let randomness = [2u8; 32];
        let hash = [3u8; 32];
        let (authentication, digest) = subscriber::authenticate(
            &mask,
            &randomness,
            &provider,
            &subscriber,
            &verifier,
            &challenge,
            &hash,
        )
        .unwrap();
        let (signature, _) = sk_device.sign_prehash(&digest).unwrap();
        let mut proof: Proof = [0u8; 64];
        proof.copy_from_slice(&signature.to_bytes());
        let (sender, pass) = subscriber::pass(authentication, &proof).unwrap();

        let randomness = [1u8; 32];
        let (authenticator, proof, client) = provider::prove(
            &randomness,
            &provider,
            &dh(&sk_r, &subscriber),
            &verifier,
            &pk_device,
            &hash,
            &dh(&sk_r, &sender),
            &pass,
        )
        .unwrap();

        assert_eq!(Ok(()), verify(&verifier, &pk_device, &hash, &authenticator, &proof, &client));
    }
}
