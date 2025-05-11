pub mod buffer;
pub mod provider;
pub mod subscriber;

use crate::{domain, program};
use serde::{Deserialize, Serialize};

/// Enrolled verification data for the [subscriber].
///
/// Contains a joint verifying key, and two encrypted signing shares.
pub type Verifier = [u8; 32 + 33 + 33 + 136 + 16];

/// Public key for key agreement or signing.
///
/// Contains a compressed P-256 point.
pub type Key = [u8; 33];

/// Authenticator-generated verification data.
///
/// Contains the first part of a joint signature and an authentication tag
/// protecting integrity of the [subscriber]’s signature share.
pub type Authenticator = [u8; 32 + 16];

/// Verification data proving authenticator possession.
///
/// Contains an ECDSA P-256 device signature.
pub type Proof = [u8; 64];

/// Client-generated verification data.
///
/// Contains a P-256 binding public key, an ECDSA P-256 binding signature,
/// and the second part of a joint signature.
pub type Client = [u8; 33 + 64 + 32];

/// Secret entropy derived from execution context data in a secure area.
pub type Randomness = [u8; 32];

/// Shared secret between [provider] and alleged [subscriber].
///
/// Contains the P-256 ECDH shared secret generated between server and
/// client: the x-coordinate of the scalar-point multiplication.
pub type Secret = [u8; 32];

/// Secret entropy derived from application-provided data in a secure area.
///
/// Gets added to the subscriber signing share in the [Verifier].
pub type Mask = [u8; 32];

/// Authentication challenge data.
///
/// Contains [provider] commitments ([<i>d</i><sub>1</sub>]<i>G</i>, [<i>e</i><sub>1</sub>]<i>G</i>).
pub type Challenge = [u8; 33 + 33];

/// Response to a [Challenge].
///
/// Contains a binding public key, [subscriber] commitments
/// ([<i>d</i><sub>2</sub>]<i>G</i>, [<i>e</i><sub>2</sub>]<i>G</i>),
/// encrypted [subscriber] signature share <i>z</i><sub>2</sub>], a device signature, and a binding
/// signature.
pub type Pass = [u8; 33 + 33 + 64 + 33 + 64 + 33 + 32 + 16];

/// Hash digest representing client data or device-signed data.
///
/// Contains a SHA-256 hash digest.
pub type Digest = [u8; 32];

// const BUFFER_SIZE: usize = 1024;
//
// pub struct Instance {
//     buffer: [u8; BUFFER_SIZE],
// }
//
// #[export_name = "scal3_init"]
// pub extern "C" fn init() -> *mut Instance {
//     let instance = Instance {
//         buffer: [0u8; BUFFER_SIZE],
//     };
//     Box::into_raw(Box::new(instance))
// }
//
// #[export_name = "scal3_finalize"]
// pub extern "C" fn finalize(instance: *mut Instance) {
//     assert!(!instance.is_null());
//     let _ = unsafe { Box::from_raw(instance) };
// }

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
pub enum VerifyStatus {
    InvalidPointer = -1,
    SerializationError = -2,
    Done = 0,
}

/// Verifies evidence that the identified [subscriber] passed the digest.
#[export_name = "scal3_verify"]
pub unsafe extern "C" fn verify(req_buf: *const u8, res_buf: *mut u8) -> VerifyStatus {
    if req_buf.is_null() || res_buf.is_null() {
        return VerifyStatus::InvalidPointer;
    }
    let request = std::slice::from_raw_parts(req_buf, buffer::size());
    let response = std::slice::from_raw_parts_mut(res_buf, buffer::size());
    let mut serializer = minicbor_serde::Serializer::new(response);
    let request = minicbor_serde::from_slice::<VerifyRequest>(request);
    let response = match request {
        Ok(r) => match r.handle() {
            None => VerifyResponse::error("missing value"),
            Some(Ok(_)) => VerifyResponse::result("verified"),
            Some(Err(_)) => VerifyResponse::result("falsified"),
        },
        Err(_) => VerifyResponse::error("schema mismatch"),
    };
    match response.serialize(&mut serializer) {
        Ok(_) => VerifyStatus::Done,
        Err(_) => VerifyStatus::SerializationError,
    }
}

#[cfg(test)]
mod test {
    use crate::api::*;
    use crate::provider::{Interaction, ProveRequest, ProveResponse};
    use hmac::digest::{crypto_common, KeyInit};
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::{PublicKey, SecretKey};
    use p256::{NistP256, NonZeroScalar};
    use sha2::{Digest as Sha2Digest, Sha256};
    use signature::hazmat::PrehashSigner;
    use signature::rand_core::{OsRng, RngCore};
    use std::ptr::null_mut;
    use std::slice;

    #[test]
    fn example() {
        fn sec1_compressed(pk: PublicKey<NistP256>) -> Key {
            pk.to_encoded_point(true).as_ref().try_into().unwrap()
        }

        fn prf(k: &crypto_common::Key<Hmac<Sha256>>, msg: &[u8]) -> [u8; 32] {
            <Hmac<Sha256> as Mac>::new(k)
                .chain_update(msg)
                .finalize()
                .into_bytes()
                .try_into()
                .unwrap()
        }

        fn ecdh(sk: &SecretKey<NistP256>, pk: &[u8; 33]) -> Secret {
            let sk = NonZeroScalar::from_repr(sk.to_bytes()).unwrap();
            let pk = p256::PublicKey::from_sec1_bytes(pk).unwrap();
            let secret = p256::ecdh::diffie_hellman::<NistP256>(sk, pk.as_affine());
            let bytes = secret.raw_secret_bytes().clone();
            bytes.into()
        }

        fn sign_prehash(sk: &p256::ecdsa::SigningKey, hash: &Digest, proof: &mut Proof) {
            let (signature, _) = sk.sign_prehash(hash).unwrap();
            proof.copy_from_slice(&signature.to_bytes());
        }

        let mut randomness = [0u8; size_of::<Randomness>()];
        let mut subscriber = [0u8; size_of::<Key>()];
        let mut verifier = [0u8; size_of::<Verifier>()];
        let mut challenge = [0u8; size_of::<Challenge>()];
        let mut mask = [0u8; size_of::<Mask>()];
        let mut client_data_hash = [0u8; size_of::<Digest>()];
        let mut to_sign = [0u8; size_of::<Digest>()];
        let mut proof = [0u8; size_of::<Proof>()];
        let mut sender = [0u8; size_of::<Key>()];
        let mut pass = [0u8; size_of::<Pass>()];

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
        mask.copy_from_slice(&prf(&k_subscriber, b"123456"));
        OsRng.fill_bytes(&mut randomness);
        subscriber::register(
            &mask,
            &randomness,
            &pk_provider,
            &mut subscriber,
            &mut verifier,
        );

        assert!(provider::accept(
            &pk_provider,
            &ecdh(&sk_provider, &subscriber),
            &verifier
        ));

        // Authentication

        let challenge_data = b"ts=1743930934&nonce=000001";
        randomness.copy_from_slice(&prf(&k_provider, challenge_data));
        provider::challenge(&randomness, &mut challenge);

        mask.copy_from_slice(&prf(&k_subscriber, b"123456"));
        OsRng.fill_bytes(&mut randomness);
        let client_data = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}";
        client_data_hash.copy_from_slice(Sha256::digest(client_data).as_slice());
        let authentication = subscriber::authenticate(
            &mask,
            &randomness,
            &pk_provider,
            &subscriber,
            &verifier,
            &challenge,
            &client_data_hash,
            &mut to_sign,
        );
        assert_ne!(null_mut(), authentication);
        sign_prehash(&sk_subscriber, &to_sign, &mut proof);
        assert!(subscriber::pass(
            authentication,
            &proof,
            &mut sender,
            &mut pass
        ));

        randomness.copy_from_slice(&prf(&k_provider, challenge_data));

        let req_buf = buffer::allocate();
        let res_buf = buffer::allocate();

        let req_buf_ref = unsafe { &mut *req_buf };

        let res_buf_ref = unsafe { &mut *res_buf };
        let res_buf_arr = res_buf_ref.0.as_mut_slice();

        let credential = Credential {
            verifier: Some(verifier),
            device: Some(pk_subscriber),
        };
        let interaction = Interaction {
            provider: Some(pk_provider),
            secret: Some(ecdh(&sk_provider, &subscriber)),
            credential: credential.clone(),
        };

        let prove_request = ProveRequest {
            randomness: Some(randomness),
            interaction,
            client_data_hash: Some(client_data_hash),
            pass_secret: Some(ecdh(&sk_provider, &sender)),
            pass: Some(pass),
        };
        {
            let binding = req_buf_ref.0.as_mut_slice();
            let mut serializer = minicbor_serde::Serializer::new(binding);
            prove_request.serialize(&mut serializer).unwrap();
        };
        let result = unsafe { provider::prove(req_buf, res_buf) };
        assert_eq!(result, VerifyStatus::Done);
        let mut deserializer = minicbor_serde::Deserializer::new(&res_buf_arr);
        let response = ProveResponse::deserialize(&mut deserializer).unwrap();
        assert!(response.result.is_some());
        assert!(response.error.is_none());
        let transcript = response.result.unwrap();

        // let req_buf = buffer::allocate();
        // let res_buf = buffer::allocate();
        //
        // let req_buf_ref = unsafe { &mut *req_buf };
        // let req_buf_arr = req_buf_ref.0.as_mut_slice();
        //
        // let res_buf_ref = unsafe { &mut *res_buf };
        // let res_buf_arr = res_buf_ref.0.as_mut_slice();
        //
        // let mut serializer = minicbor_serde::Serializer::new(req_buf_arr);
        // let mut deserializer = minicbor_serde::Deserializer::new(res_buf_arr);
        //
        // VerifyRequest {
        //     credential,
        //     hash: Some(client_data_hash),
        //     transcript,
        // }
        // .serialize(&mut serializer)
        // .unwrap();
        // let result = unsafe { verify(req_buf_arr.as_mut_ptr(), res_buf_arr.as_mut_ptr()) };
        // assert_eq!(result, VerifyStatus::Done);
        // let response = VerifyResponse::deserialize(&mut deserializer).unwrap();
        // assert_eq!(response.result, Some("verified".to_string()));

        unsafe {
            buffer::free(req_buf);
            buffer::free(res_buf);
        }
    }
}
