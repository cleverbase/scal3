pub mod buffer;
pub mod provider;
pub mod subscriber;

use crate::buffer::Buffer;
use crate::domain::Authentication;
use crate::{domain, program};
use serde::{Deserialize, Serialize};

/// Enrolled verification data for the [subscriber].
///
/// Contains a joint verifying key, and two encrypted signing shares.
pub(crate) type Verifier = [u8; 32 + 33 + 33 + 136 + 16];

/// Public key for key agreement or signing.
///
/// Contains a compressed P-256 point.
pub(crate) type Key = [u8; 33];

/// Authenticator-generated verification data.
///
/// Contains the first part of a joint signature and an authentication tag
/// protecting integrity of the [subscriber]’s signature share.
pub(crate) type Authenticator = [u8; 32 + 16];

/// Verification data proving authenticator possession.
///
/// Contains an ECDSA P-256 device signature.
pub(crate) type Proof = [u8; 64];

/// Client-generated verification data.
///
/// Contains a P-256 binding public key, an ECDSA P-256 binding signature,
/// and the second part of a joint signature.
pub(crate) type Client = [u8; 33 + 64 + 32];

/// Secret entropy derived from execution context data in a secure area.
pub(crate) type Randomness = [u8; 32];

/// Shared secret between [provider] and alleged [subscriber].
///
/// Contains the P-256 ECDH shared secret generated between server and
/// client: the x-coordinate of the scalar-point multiplication.
pub(crate) type Secret = [u8; 32];

/// Secret entropy derived from application-provided data in a secure area.
///
/// Gets added to the subscriber signing share in the [Verifier].
pub(crate) type Mask = [u8; 32];

/// Authentication challenge data.
///
/// Contains [provider] commitments ([<i>d</i><sub>1</sub>]<i>G</i>, [<i>e</i><sub>1</sub>]<i>G</i>).
pub(crate) type Challenge = [u8; 33 + 33];

/// Response to a [Challenge].
///
/// Contains a binding public key, [subscriber] commitments
/// ([<i>d</i><sub>2</sub>]<i>G</i>, [<i>e</i><sub>2</sub>]<i>G</i>),
/// encrypted [subscriber] signature share <i>z</i><sub>2</sub>], a device signature, and a binding
/// signature.
pub(crate) type Pass = [u8; 33 + 33 + 64 + 33 + 64 + 33 + 32 + 16];

/// Hash digest representing client data or device-signed data.
///
/// Contains a SHA-256 hash digest.
pub(crate) type Digest = [u8; 32];

#[derive(Serialize, Deserialize)]
struct SubscriberState {
    #[serde(with = "serde_bytes", default = "Option::default")]
    mask: Option<Mask>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    randomness: Option<Randomness>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    provider: Option<Key>,
}

impl SubscriberState {
    fn handle(&self) -> Option<Option<Registration>> {
        Some(program::subscriber::register(
            &self.mask?,
            &self.randomness?,
            &self.provider?,
        ).map(|(key, verifier)| Registration {
            subscriber: Some(key),
            verifier: Some(verifier)
        }))
    }
}

#[derive(Serialize, Deserialize)]
struct Registration {
    #[serde(with = "serde_bytes", default = "Option::default")]
    subscriber: Option<Key>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    verifier: Option<Verifier>,
}

#[derive(Serialize, Deserialize)]
struct RegisterResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    registration: Option<Registration>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl RegisterResponse {
    fn registration(value: Registration) -> Self {
        Self {
            registration: Some(value),
            error: None,
        }
    }

    fn error(value: &str) -> Self {
        Self {
            registration: None,
            error: Some(value.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AuthenticateRequest {
    #[serde(flatten)]
    state: SubscriberState,
    #[serde(with = "serde_bytes", default = "Option::default")]
    subscriber: Option<Key>,
    #[serde(flatten)]
    credential: Credential,
    #[serde(with = "serde_bytes", default = "Option::default")]
    challenge: Option<Challenge>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    hash: Option<Digest>,
}

impl AuthenticateRequest {
    fn handle(&self) -> Option<Option<(Authentication, Digest)>> {
        Some(program::subscriber::authenticate(
            &self.state.mask?,
            &self.state.randomness?,
            &self.state.provider?,
            &self.subscriber?,
            &self.credential.verifier?,
            &self.challenge?,
            &self.hash?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct AuthenticateResponse {
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        skip_serializing_if = "Option::is_none"
    )]
    digest: Option<Digest>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AuthenticateResponse {
    fn digest(value: Digest) -> Self {
        Self {
            digest: Some(value),
            error: None,
        }
    }
    fn error(value: &str) -> Self {
        Self {
            digest: None,
            error: Some(value.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PassRequest {
    #[serde(with = "serde_bytes", default = "Option::default")]
    proof: Option<Proof>,
}

impl PassRequest {
    fn handle(&self, authentication: Authentication) -> Option<Option<(Key, Pass)>> {
        Some(program::subscriber::pass(authentication, &self.proof?))
    }
}

#[derive(Serialize, Deserialize)]
struct Attempt {
    #[serde(with = "serde_bytes", default = "Option::default")]
    sender: Option<Key>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    pass: Option<Pass>,
}

#[derive(Serialize, Deserialize)]
struct PassResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<Attempt>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PassResponse {
    fn result(value: Attempt) -> Self {
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

#[derive(Serialize, Deserialize)]
struct ChallengeRequest {
    #[serde(with = "serde_bytes", default = "Option::default")]
    randomness: Option<Randomness>,
}

impl ChallengeRequest {
    fn handle(&self) -> Option<Challenge> {
        Some(program::provider::challenge(&self.randomness?))
    }
}

#[derive(Serialize, Deserialize)]
struct ChallengeResponse {
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        skip_serializing_if = "Option::is_none"
    )]
    challenge: Option<Challenge>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ChallengeResponse {
    fn challenge(value: Challenge) -> Self {
        Self {
            challenge: Some(value),
            error: None,
        }
    }
    fn error(value: &str) -> Self {
        Self {
            challenge: None,
            error: Some(value.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct ProviderState {
    #[serde(with = "serde_bytes", default = "Option::default")]
    provider: Option<Key>,
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        rename = "verifierSecret"
    )]
    secret: Option<Secret>,
    #[serde(flatten)]
    credential: Credential,
}

impl ProviderState {
    fn handle(&self) -> Option<domain::Result> {
        Some(program::provider::accept(
            &self.provider?,
            &self.secret?,
            &self.credential.verifier?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct AcceptResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AcceptResponse {
    fn result(value: &str) -> Self {
        Self {
            result: Some(value.to_string()),
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

#[derive(Serialize, Deserialize)]
struct ProveRequest {
    #[serde(with = "serde_bytes", default = "Option::default")]
    randomness: Option<Randomness>,
    #[serde(flatten)]
    state: ProviderState,
    #[serde(with = "serde_bytes", default = "Option::default")]
    hash: Option<Digest>,
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        rename = "passSecret"
    )]
    pass_secret: Option<Secret>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    pass: Option<Pass>,
}

impl ProveRequest {
    fn handle(&self) -> Option<Option<(Authenticator, Proof, Client)>> {
        Some(program::provider::prove(
            &self.randomness?,
            &self.state.provider?,
            &self.state.secret?,
            &self.state.credential.verifier?,
            &self.state.credential.device?,
            &self.hash?,
            &self.pass_secret?,
            &self.pass?,
        ))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProveResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<Transcript>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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

#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    #[serde(with = "serde_bytes", default = "Option::default")]
    verifier: Option<Verifier>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    device: Option<Key>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Transcript {
    #[serde(with = "serde_bytes", default = "Option::default")]
    authenticator: Option<Authenticator>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    proof: Option<Proof>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    client: Option<Client>,
}

#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    #[serde(flatten)]
    credential: Credential,
    #[serde(with = "serde_bytes", default = "Option::default")]
    hash: Option<Digest>,
    #[serde(flatten)]
    transcript: Transcript,
}

impl VerifyRequest {
    fn handle(&self) -> Option<domain::Result> {
        Some(program::verify(
            &self.credential.verifier?,
            &self.credential.device?,
            &self.hash?,
            &self.transcript.authenticator?,
            &self.transcript.proof?,
            &self.transcript.client?,
        ))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl VerifyResponse {
    fn result(value: &str) -> Self {
        Self {
            result: Some(value.to_string()),
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

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum Status {
    InvalidPointer = -1,
    SerializationError = -2,
    Done = 0,
}

/// Verifies evidence that the identified [subscriber] passed the digest.
#[export_name = "scal3_verify"]
pub extern "C" fn verify(buffer: *mut Buffer) -> Status {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return Status::InvalidPointer;
    };
    let response = match buffer.deserialize::<VerifyRequest>() {
        Ok(request) => match request.handle() {
            None => VerifyResponse::error("missing value"),
            Some(Ok(_)) => VerifyResponse::result("verified"),
            Some(Err(_)) => VerifyResponse::result("falsified"),
        },
        Err(_) => VerifyResponse::error("schema mismatch"),
    };
    match buffer.serialize(response) {
        Ok(_) => Status::Done,
        Err(_) => Status::SerializationError,
    }
}

#[cfg(test)]
mod test {
    use crate::api::*;
    use crate::buffer::Buffer;
    use hmac::digest::{crypto_common, KeyInit};
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::{PublicKey, SecretKey};
    use p256::{NistP256, NonZeroScalar};
    use sha2::{Digest as Sha2Digest, Sha256};
    use signature::hazmat::PrehashSigner;
    use signature::rand_core::{OsRng, RngCore};

    #[test]
    fn example() -> Result<(), Box<dyn std::error::Error>> {
        fn sec1_compressed(pk: PublicKey<NistP256>) -> Key {
            pk.to_encoded_point(true).as_ref().try_into().unwrap()
        }

        fn prf(k: &crypto_common::Key<Hmac<Sha256>>, msg: &[u8]) -> Randomness {
            <Hmac<Sha256> as Mac>::new(k)
                .chain_update(msg)
                .finalize()
                .into_bytes()
                .try_into()
                .unwrap()
        }

        fn randomness() -> Randomness {
            let mut randomness = [0u8; 32];
            OsRng.fill_bytes(&mut randomness);
            randomness
        }

        fn sha256(msg: &[u8]) -> Digest {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(Sha256::digest(msg).as_slice());
            digest
        }

        fn ecdh(sk: &SecretKey<NistP256>, pk: &[u8; 33]) -> Secret {
            let sk = NonZeroScalar::from_repr(sk.to_bytes()).unwrap();
            let pk = p256::PublicKey::from_sec1_bytes(pk).unwrap();
            let secret = p256::ecdh::diffie_hellman::<NistP256>(sk, pk.as_affine());
            let bytes = secret.raw_secret_bytes().clone();
            bytes.into()
        }

        fn sign_prehash(sk: &p256::ecdsa::SigningKey, hash: &Digest) -> Proof {
            let mut proof = [0u8; size_of::<Proof>()];
            let (signature, _) = sk.sign_prehash(hash).unwrap();
            proof.copy_from_slice(&signature.to_bytes());
            proof
        }

        let mut buffer = Buffer::new();

        // Setup

        // Provider keys would be protected by a hardware security module
        let sk_provider = p256::SecretKey::random(&mut OsRng);
        let pk_provider = sec1_compressed(sk_provider.public_key());
        let k_provider = Hmac::<Sha256>::generate_key(&mut OsRng);

        // Enrolment

        // Subscriber keys would be protected by a local secure area, e.g. a StrongBox Keymaster
        let sk_subscriber = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pk_subscriber = sec1_compressed(sk_subscriber.verifying_key().into());
        let k_subscriber = Hmac::<Sha256>::generate_key(&mut OsRng);

        // The subscriber derives a mask from a PIN, e.g. using a local hardware-backed PRF
        buffer.serialize(SubscriberState {
            mask: Some(prf(&k_subscriber, b"123456")),
            randomness: Some(randomness()),
            provider: Some(pk_provider),
        })?;
        assert_eq!(subscriber::register(&mut buffer), Status::Done);
        let response = buffer.deserialize::<RegisterResponse>()?;
        assert!(response.registration.is_some());
        let registration = response.registration.unwrap();

        let credential = Credential {
            verifier: registration.verifier.clone(),
            device: Some(pk_subscriber),
        };
        let provider_state = ProviderState {
            provider: Some(pk_provider),
            secret: Some(ecdh(&sk_provider, &registration.subscriber.unwrap())),
            credential: credential.clone(),
        };
        buffer.serialize(provider_state.clone())?;
        assert_eq!(provider::accept(&mut buffer), Status::Done);
        let response = buffer.deserialize::<AcceptResponse>()?;
        assert_eq!(response.result, Some("accepted".to_string()));

        // Authentication

        let challenge_data = b"ts=1743930934&nonce=000001";
        buffer.serialize(ChallengeRequest {
            randomness: Some(prf(&k_provider, challenge_data)),
        })?;
        let _result = provider::challenge(&mut buffer);
        let response = buffer.deserialize::<ChallengeResponse>()?;

        let client_data = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}";
        let state = SubscriberState {
            mask: Some(prf(&k_subscriber, b"123456")),
            randomness: Some(randomness()),
            provider: Some(pk_provider),
        };
        buffer.serialize(AuthenticateRequest {
            state,
            subscriber: registration.subscriber.clone(),
            credential: credential.clone(),
            challenge: response.challenge,
            hash: Some(sha256(client_data)),
        })?;
        let authentication = subscriber::authenticate(&mut buffer);
        let response = buffer.deserialize::<AuthenticateResponse>()?;
        let to_sign = response.digest.unwrap();

        buffer.serialize(PassRequest { proof: Some(sign_prehash(&sk_subscriber, &to_sign)) })?;
        let _result = subscriber::pass(authentication, &mut buffer);
        let response = buffer.deserialize::<PassResponse>()?;
        let attempt = response.result.unwrap();

        buffer.serialize(ProveRequest {
            randomness: Some(prf(&k_provider, challenge_data)),
            state: provider_state,
            hash: Some(sha256(client_data)),
            pass_secret: Some(ecdh(&sk_provider, &attempt.sender.unwrap())),
            pass: Some(attempt.pass.unwrap()),
        })?;

        let _result = provider::prove(&mut buffer);

        let response = buffer.deserialize::<ProveResponse>()?;
        let transcript = response.result.unwrap();

        buffer.serialize(VerifyRequest {
            credential,
            hash: Some(sha256(client_data)),
            transcript,
        })?;
        let result = verify(&mut buffer);
        assert_eq!(result, Status::Done);
        let response = buffer.deserialize::<VerifyResponse>()?;
        assert_eq!(response.error, None);
        assert_eq!(response.result, Some("verified".to_string()));

        Ok(())
    }
}
