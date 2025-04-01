//! # Sole Control Assurance Level 3
//!
//! [Verify that systems operate under your sole control](https://github.com/cleverbase/scal3).
//! SCAL3 provides verifiable sole control assurance levels with tamper-evident
//! logs for multi-factor authentication transparency. This prototype contains
//! example functions and data. It implements the protocol from the technical
//! report “Authentication and sole control at a high level of assurance on
//! widespread smartphones with threshold signatures” in [Cryptology ePrint
//! Archive, Paper 2025/267](https://eprint.iacr.org/2025/267).
//!
//! <div class="warning">
//! <strong>Do not use this code for production.</strong>
//! The specification has not been finalized and the security of this prototype
//! code has not been evaluated.
//! The code is available for transparency and to enable public review.
//! </div>
//!
//! ## Legal
//!
//! Patent NL2037022 pending.
//!
//! Copyright Cleverbase ID B.V. 2024. The code and documentation are licensed under
//! [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/).
//!
//! To discuss other licensing options,
//! [contact Cleverbase](mailto:sander.dijkhuis@cleverbase.com).
//!
//! ## Example application context
//!
//! A provider manages a central hardware security module (HSM) that performs
//! instructions under sole control of its subscribers. Subscribers use a mobile
//! wallet app to authorize operations using a PIN code.
//!
//! To achieve SCAL3, the provider manages three assets:
//!
//! - a public key certificate to link the subscriber to enrolled keys, e.g.
//!   applying X.509 ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280));
//! - a tamper-evident log to record evidence of authentic instructions, e.g.
//!   applying [Trillian](https://transparency.dev/);
//! - a PIN attempt counter, e.g. using HSM-synchronized state.
//!
//! To enroll for a certificate, the subscriber typically uses a protocol such as
//! ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)). The
//! certificate binds to the subscriber’s subject identifier an (attested) P-256
//! ECDSA signing key from Secure Enclave, StrongBox Keymaster, or Android’s
//! hardware-backed Keystore. This is the possession factor for authentication.
//!
//! During enrollment, the provider also performs generation of a SCAL3 user
//! identifier and pre-authorization of this identifier for certificate issuance.
//! This part of enrollment applies [FROST](https://eprint.iacr.org/2020/852)
//! distributed key generation and requires the subscriber to set their PIN.
//!
//! During authentication, the certified identifier contains all information needed
//! for the original provider and subscriber to determine their secret signing
//! shares. The process applies FROST two-round threshold signing, combined with
//! ECDSA to prove possession of the enrolled device. Successful authentication
//! leads to recorded evidence that can be publicly verified.
//!
//! By design, the certificate and the evidence provide no information about the
//! PIN.  This means that even attackers with access to the device, the certificate
//! and  the log cannot bruteforce the PIN, since they would need to verify each
//! attempt using the rate-limited provider service.
//!
//! ## Cryptography overview
//!
//! This prototype uses the P-256 elliptic curve with order <i>p</i> and common base
//! point <i>G</i> for all keys.
//!
//! To the provider and subscriber, signing shares are assigned of the form
//! <i>s</i><sub><i>i</i></sub> =
//!   <i>a</i><sub>10</sub> +
//!   <i>a</i><sub>11</sub><i>i</i> +
//!   <i>a</i><sub>20</sub> +
//!   <i>a</i><sub>21</sub><i>i</i>
//!   (mod <i>p</i>)
//! where the provider has participant identifier <i>i</i> = 1
//! and the subscriber has <i>i</i> = 2.
//! During enrollment, the subscriber has randomly generated joint secret key
//! <i>s</i> = <i>s</i><sub>1</sub><i>s</i><sub>2</sub> and computed
//! <i>a</i><sub><i>ij</i></sub> as a trusted dealer.
//! The resulting joint verifying key equals
//! <i>V</i><sub>k</sub> = [<i>a</i><sub>10</sub> + <i>a</i><sub>20</sub>]<i>G</i>.
//!
//! The SCAL3 user identifier consists of <i>V</i><sub>k</sub> and:
//!
//! - <i>s</i><sub>1</sub> encrypted for the provider;
//! - <i>s</i><sub>2</sub> + <i>m</i><sub>2</sub> (mod <i>p</i>)
//!   where <i>m</i><sub>2</sub> is a key securely derived by the subscriber from
//!   the PIN, for example using PRF(<i>k</i>, <i>PIN</i>) with a local
//!   hardware-backed key <i>k</i>, followed by `hash_to_field` from
//!   [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380).
//!
//! During authentication, the subscriber generates an ephemeral ECDSA binding key
//! pair
//! (<i>s</i><sub>b</sub>, <i>V</i><sub>b</sub>)
//! and forms a message <i>M</i> that includes <i>V</i><sub>b</sub>,
//! the instruction to authorize, and log metadata.
//! Applying FROST threshold signing, both parties generate secret nonces
//! (<i>d</i><sub><i>i</i></sub>, <i>e</i><sub><i>i</i></sub>)
//! and together they form a joint signature
//! (<i>c</i>, <i>z</i>) over <i>M</i>. To do so, they compute with domain-separated
//! hash functions #<sub>1</sub> and #<sub>2</sub>:
//!
//! - commitment shares
//!   (<i>D</i><sub><i>i</i></sub>, <i>E</i><sub><i>i</i></sub>) =
//!   ([<i>d</i><sub><i>i</i></sub>]<i>G</i>, [<i>e</i><sub><i>i</i></sub>]<i>G</i>);
//! - binding factors
//!   <i>ρ</i><sub><i>i</i></sub> = #<sub>1</sub>(<i>i</i>, <i>M</i>, <i>B</i>)
//!   where <i>B</i> represents a list of all commitment shares;
//! - commitment
//!   <i>R</i> =
//!     <i>D</i><sub>1</sub> +
//!     [<i>ρ</i><sub><i>1</i></sub>]<i>E</i><sub><i>1</i></sub> +
//!     <i>D</i><sub>2</sub> +
//!     [<i>ρ</i><sub><i>2</i></sub>]<i>E</i><sub><i>2</i></sub>;
//! - challenge <i>c</i> = #<sub>2</sub>(<i>R</i>, <i>V</i><sub>k</sub>, <i>M</i>);
//! - signature share
//!   <i>z</i><sub><i>i</i></sub> =
//!     <i>d</i><sub><i>i</i></sub> +
//!     <i>e</i><sub><i>i</i></sub><i>ρ</i><sub><i>i</i></sub> +
//!     <i>c</i><i>λ</i><sub><i>i</i></sub><i>s</i><sub><i>i</i></sub>
//!     (mod <i>p</i>)
//!   with <i>λ</i><sub>1</sub> = 2 and <i>λ</i><sub>2</sub> = −1;
//! - proof
//!   <i>z</i> = <i>z</i><sub>1</sub> + <i>z</i><sub>2</sub>.
//!
//! All subscriber’s contributions are part of a single “pass the authentication
//! challenge” message that includes:
//!
//! - a device signature created using the possession factor over <i>c</i>;
//! - a binding signature created using <i>s</i><sub>b</sub> over the device
//!   signature.
//!
//! This construction makes sure that without simultaneous control over both
//! authentication factors, evidence cannot be forged.
//!
//! # Examples
//!
//! All functions are pure, enabling a mostly stateless server
//! implementation and easy integration on mobile client platforms.
//!
//! ## Setup
//!
//! Generate a P-256 ECDH key pair and a PRF secret key for the provider.
//! In production, protect these with a hardware security module.
//!
//! ```
//! # use hmac::digest::KeyInit;
//! # use hmac::Hmac;
//! # use p256::elliptic_curve::sec1::ToEncodedPoint;
//! # use sha2::Sha256;
//! # use signature::rand_core::OsRng;
//! # use scal3::*;
//! #
//! # fn sec1_compressed(pk: p256::PublicKey) -> Key {
//! #     pk.to_encoded_point(true).as_ref().try_into().unwrap()
//! # }
//! #
//! let sk_provider = p256::SecretKey::random(&mut OsRng);
//! let pk_provider = sec1_compressed(sk_provider.public_key());
//! let k_provider = Hmac::<Sha256>::generate_key(&mut OsRng);
//! ```
//!
//! ## Enrolment
//!
//! Generate a P-256 ECDSA key pair and a PRF secret key for the subscriber.
//! In production, protect these with a local secure area.
//!
//! Aborting upon failure, the [provider] and [subscriber] execute their
//! assigned functions in this order:
//!
//! 1. [subscriber]: derive a [Mask], obtain [Randomness],
//!    [subscriber::register] and send a [Key] with [Verifier].
//! 2. [provider]: derive the [Secret] and [provider::accept].
//!
//! In production, the [provider] would need to furthermore verify
//! possession of the device [Key] and bind these, for example in
//! a public key certificate.
//!
//! ```
//! # use hmac::digest::{crypto_common, KeyInit};
//! # use hmac::{Hmac, Mac};
//! # use p256::elliptic_curve::sec1::ToEncodedPoint;
//! # use signature::rand_core::{OsRng, RngCore};
//! # use sha2::Sha256;
//! # use scal3::*;
//! # fn sec1_compressed(pk: p256::PublicKey) -> Key {
//! #     pk.to_encoded_point(true).as_ref().try_into().unwrap()
//! # }
//! # fn prf(k: &crypto_common::Key<Hmac<Sha256>>, msg: &[u8]) -> [u8; 32] {
//! #     <Hmac<Sha256> as Mac>::new(k)
//! #         .chain_update(msg)
//! #         .finalize()
//! #         .into_bytes()
//! #         .try_into()
//! #         .unwrap()
//! # }
//! # fn ecdh(sk: &p256::SecretKey, pk: &[u8; 33]) -> Secret {
//! #     let sk = p256::NonZeroScalar::from_repr(sk.to_bytes()).unwrap();
//! #     let pk = p256::PublicKey::from_sec1_bytes(pk).unwrap();
//! #     let secret = p256::ecdh::diffie_hellman(sk, pk.as_affine());
//! #     let bytes = secret.raw_secret_bytes().clone();
//! #     bytes.into()
//! # }
//! # let sk_provider = p256::SecretKey::random(&mut OsRng);
//! # let pk_provider = sec1_compressed(sk_provider.public_key());
//! # let k_provider = Hmac::<Sha256>::generate_key(&mut OsRng);
//! # let mut randomness = [0u8; size_of::<Randomness>()];
//! # let mut subscriber = [0u8; size_of::<Key>()];
//! # let mut verifier = [0u8; size_of::<Verifier>()];
//! # let mut challenge = [0u8; size_of::<Challenge>()];
//! # let mut mask = [0u8; size_of::<Mask>()];
//! let sk_subscriber = p256::ecdsa::SigningKey::random(&mut OsRng);
//! let pk_subscriber = sec1_compressed(sk_subscriber.verifying_key().into());
//! let k_subscriber = Hmac::<Sha256>::generate_key(&mut OsRng);
//!
//! mask.copy_from_slice(&prf(&k_subscriber, b"123456"));
//! OsRng.fill_bytes(&mut randomness);
//! subscriber::register(
//!     &mask,
//!     &randomness,
//!     &pk_provider,
//!     &mut subscriber,
//!     &mut verifier,
//! );
//!
//! assert!(provider::accept(
//!     &pk_provider,
//!     &ecdh(&sk_provider, &subscriber),
//!     &verifier
//! ));
//! ```
//!
//! ## Authentication
//!
//! Aborting upon failure:
//!
//! 1. [provider]: derive [Randomness], [provider::challenge] and send
//!    a [Challenge].
//! 2. [subscriber]: derive a [Mask], obtain [Randomness],
//!    [subscriber::authenticate], create [Proof] of possession,
//!    [subscriber::pass] and send a [Pass].
//! 3. [provider]: [provider::prove] authentication and log
//!    [Authenticator], [Proof] and [Client] verification data.
//!
//! ```
//! # use std::ptr::null_mut;
//! # use hmac::digest::{crypto_common, KeyInit};
//! # use hmac::{Hmac, Mac};
//! # use p256::elliptic_curve::sec1::ToEncodedPoint;
//! # use signature::rand_core::{OsRng, RngCore};
//! # use sha2::{Digest as Sha2Digest, Sha256};
//! # use signature::hazmat::PrehashSigner;
//! # use scal3::*;
//! # fn sec1_compressed(pk: p256::PublicKey) -> Key {
//! #     pk.to_encoded_point(true).as_ref().try_into().unwrap()
//! # }
//! # fn prf(k: &crypto_common::Key<Hmac<Sha256>>, msg: &[u8]) -> [u8; 32] {
//! #     <Hmac<Sha256> as Mac>::new(k)
//! #         .chain_update(msg)
//! #         .finalize()
//! #         .into_bytes()
//! #         .try_into()
//! #         .unwrap()
//! # }
//! # fn ecdh(sk: &p256::SecretKey, pk: &[u8; 33]) -> Secret {
//! #     let sk = p256::NonZeroScalar::from_repr(sk.to_bytes()).unwrap();
//! #     let pk = p256::PublicKey::from_sec1_bytes(pk).unwrap();
//! #     let secret = p256::ecdh::diffie_hellman(sk, pk.as_affine());
//! #     let bytes = secret.raw_secret_bytes().clone();
//! #     bytes.into()
//! # }
//! # fn sign_prehash(sk: &p256::ecdsa::SigningKey, hash: &Digest, proof: &mut Proof) {
//! #     let (signature, _) = sk.sign_prehash(hash).unwrap();
//! #     proof.copy_from_slice(&signature.to_bytes());
//! # }
//! # let sk_provider = p256::SecretKey::random(&mut OsRng);
//! # let pk_provider = sec1_compressed(sk_provider.public_key());
//! # let k_provider = Hmac::<Sha256>::generate_key(&mut OsRng);
//! # let mut randomness = [0u8; size_of::<Randomness>()];
//! # let mut subscriber = [0u8; size_of::<Key>()];
//! # let mut verifier = [0u8; size_of::<Verifier>()];
//! # let mut challenge = [0u8; size_of::<Challenge>()];
//! # let mut mask = [0u8; size_of::<Mask>()];
//! # let mut client_data_hash = [0u8; size_of::<Digest>()];
//! # let mut to_sign = [0u8; size_of::<Digest>()];
//! # let mut proof = [0u8; size_of::<Proof>()];
//! # let mut sender = [0u8; size_of::<Key>()];
//! # let mut pass = [0u8; size_of::<Pass>()];
//! # let mut authenticator = [0u8; size_of::<Authenticator>()];
//! # let mut client = [0u8; size_of::<Client>()];
//! # let sk_subscriber = p256::ecdsa::SigningKey::random(&mut OsRng);
//! # let pk_subscriber = sec1_compressed(sk_subscriber.verifying_key().into());
//! # let k_subscriber = Hmac::<Sha256>::generate_key(&mut OsRng);
//! # mask.copy_from_slice(&prf(&k_subscriber, b"123456"));
//! # OsRng.fill_bytes(&mut randomness);
//! # subscriber::register(
//! #     &mask,
//! #     &randomness,
//! #     &pk_provider,
//! #     &mut subscriber,
//! #     &mut verifier,
//! # );
//! let challenge_data = b"ts=1743930934&nonce=000001";
//! randomness.copy_from_slice(&prf(&k_provider, challenge_data));
//! provider::challenge(&randomness, &mut challenge);
//!
//! mask.copy_from_slice(&prf(&k_subscriber, b"123456"));
//! OsRng.fill_bytes(&mut randomness);
//! let client_data = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}";
//! client_data_hash.copy_from_slice(Sha256::digest(client_data).as_slice());
//! let authentication = subscriber::authenticate(
//!     &mask,
//!     &randomness,
//!     &pk_provider,
//!     &subscriber,
//!     &verifier,
//!     &challenge,
//!     &client_data_hash,
//!     &mut to_sign,
//! );
//! assert_ne!(null_mut(), authentication);
//! sign_prehash(&sk_subscriber, &to_sign, &mut proof);
//! assert!(subscriber::pass(
//!     authentication,
//!     &proof,
//!     &mut sender,
//!     &mut pass
//! ));
//! randomness.copy_from_slice(&prf(&k_provider, challenge_data));
//!
//! assert!(provider::prove(
//!     &randomness,
//!     &pk_provider,
//!     &ecdh(&sk_provider, &subscriber),
//!     &verifier,
//!     &pk_subscriber,
//!     &client_data_hash,
//!     &ecdh(&sk_provider, &sender),
//!     &pass,
//!     &mut authenticator,
//!     &mut proof,
//!     &mut client
//! ));
//! # assert!(verify(
//! #     &verifier,
//! #     &pk_subscriber,
//! #     &client_data_hash,
//! #     &authenticator,
//! #     &proof,
//! #     &client
//! # ));
//! ```
//!
//! ## Auditing
//!
//! The [subscriber] or any other party with access can [verify] the evidence
//! consisting of [Authenticator], [Proof] and [Client] data.
//!
//! ```ignore
//! assert!(verify(
//!    &verifier,
//!    &pk_subscriber,
//!    &client_data_hash,
//!    &authenticator,
//!    &proof,
//!    &client
//! ))
//! ```
//!
//! # Risks
//!
//! - The implementation may still be vulnerability to side channel attacks,
//!   such as timing attacks and reading memory that was not zeroized in time.
//!   The security dependencies offer functions to implement this properly.
//! - Not all pass details are protected using the device signature, enabling
//!   a denial-of-service attack by changing details.

mod program;
mod domain;
mod kem;
mod rng;
pub(crate) mod api;

pub use api::*;
