use crate::domain::Authentication;
use crate::handle::insert_authentication;
use crate::{domain, program};
use serde::{Deserialize, Serialize};
use alloc::string::String;

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Error {
    BadRequest,
    MissingValue,
    InvalidInput,
}

#[derive(Serialize)]
pub(crate) struct ErrorResponse {
    pub(crate) error: Error,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Response {
    Challenge(ChallengeResponse),
    Register(Option<Registration>),
    Accept(Acceptance),
    Authenticate(AuthenticateResponse2),
    Pass(Attempt),
    Prove(Option<Transcript>),
    Verify(Verification),
    Error(ErrorResponse),
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SubscriberState {
    #[serde(with = "serde_bytes", default = "Option::default")]
    mask: Option<Mask>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    randomness: Option<Randomness>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    provider: Option<Key>,
}

impl SubscriberState {
    pub(crate) fn handle(&self) -> Option<Option<Registration>> {
        Some(
            program::subscriber::register(&self.mask?, &self.randomness?, &self.provider?).map(
                |(key, verifier)| Registration {
                    subscriber: Some(key),
                    verifier: Some(verifier),
                },
            ),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Registration {
    #[serde(with = "serde_bytes", default = "Option::default")]
    subscriber: Option<Key>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    verifier: Option<Verifier>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RegisterResponse {
    #[serde(flatten)]
    registration: Option<Registration>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AuthenticateRequest {
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

#[derive(Serialize)]
pub(crate) struct AuthenticateResponse2 {
    #[serde(with = "serde_bytes")]
    digest: Digest,
    authentication: u64,
}

impl AuthenticateRequest {
    pub(crate) fn handle(&self) -> Option<Option<(Authentication, Digest)>> {
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

    pub(crate) fn handle2(&self) -> Option<AuthenticateResponse2> {
        match self.handle() {
            None => None,
            Some(None) => None,
            Some(Some((authentication, digest))) => {
                let authentication_id = insert_authentication(authentication);
                Some(AuthenticateResponse2 {
                    digest,
                    authentication: authentication_id,
                })
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AuthenticateResponse {
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        skip_serializing_if = "Option::is_none"
    )]
    digest: Option<Digest>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PassRequest {
    #[serde(with = "serde_bytes", default = "Option::default")]
    proof: Option<Proof>,
    #[serde(default = "Option::default")]
    pub(crate) authentication: Option<u64>,
}

impl PassRequest {
    pub(crate) fn handle(&self, authentication: Authentication) -> Option<Option<(Key, Pass)>> {
        Some(program::subscriber::pass(authentication, &self.proof?))
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Attempt {
    #[serde(with = "serde_bytes", default = "Option::default")]
    pub(crate) sender: Option<Key>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    pub(crate) pass: Option<Pass>,
}

#[derive(Serialize, Deserialize)]
struct PassResponse {
    #[serde(flatten)]
    attempt: Option<Attempt>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ChallengeRequest {
    #[serde(with = "serde_bytes", default = "Option::default")]
    randomness: Option<Randomness>,
}

impl ChallengeRequest {
    pub(crate) fn handle(&self) -> Option<Challenge> {
        Some(program::provider::challenge(&self.randomness?))
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ChallengeResponse {
    #[serde(
        with = "serde_bytes",
        default = "Option::default",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) challenge: Option<Challenge>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ProviderState {
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
    pub(crate) fn handle(&self) -> Option<domain::Result> {
        Some(program::provider::accept(
            &self.provider?,
            &self.secret?,
            &self.credential.verifier?,
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Acceptance {
    Accepted,
    Rejected,
}

#[derive(Serialize, Deserialize)]
struct AcceptResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ProveRequest {
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
    pub(crate) fn handle(&self) -> Option<Option<(Authenticator, Proof, Client)>> {
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
    #[serde(flatten)]
    result: Option<Transcript>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    #[serde(with = "serde_bytes", default = "Option::default")]
    verifier: Option<Verifier>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    device: Option<Key>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Transcript {
    #[serde(with = "serde_bytes", default = "Option::default")]
    pub(crate) authenticator: Option<Authenticator>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    pub(crate) proof: Option<Proof>,
    #[serde(with = "serde_bytes", default = "Option::default")]
    pub(crate) client: Option<Client>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct VerifyRequest {
    #[serde(flatten)]
    credential: Credential,
    #[serde(with = "serde_bytes", default = "Option::default")]
    hash: Option<Digest>,
    #[serde(flatten)]
    transcript: Transcript,
}

impl VerifyRequest {
    pub(crate) fn handle(&self) -> Option<domain::Result> {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Verification {
    Verified,
    Rejected,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyResponse {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
