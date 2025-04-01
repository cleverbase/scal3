pub mod provider;
pub mod subscriber;

use crate::program;

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

/// Verifies evidence that the identified [subscriber] passed the [Digest].
#[export_name = "scal3_verify"]
pub extern "C" fn verify(
    verifier: &Verifier,
    pk_device: &Key,
    client_data_hash: &Digest,
    authenticator: &Authenticator,
    proof: &Proof,
    client: &Client,
) -> bool {
    program::verify(
        verifier,
        pk_device,
        client_data_hash,
        authenticator,
        proof,
        client,
    )
    .is_ok()
}

#[cfg(test)]
mod test {
    use crate::api::*;
    use hmac::digest::{crypto_common, KeyInit};
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::{PublicKey, SecretKey};
    use p256::{NistP256, NonZeroScalar};
    use sha2::{Digest as Sha2Digest, Sha256};
    use signature::hazmat::PrehashSigner;
    use std::ptr::null_mut;
    use signature::rand_core::{OsRng, RngCore};

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
        let mut authenticator = [0u8; size_of::<Authenticator>()];
        let mut client = [0u8; size_of::<Client>()];

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
        assert!(provider::prove(
            &randomness,
            &pk_provider,
            &ecdh(&sk_provider, &subscriber),
            &verifier,
            &pk_subscriber,
            &client_data_hash,
            &ecdh(&sk_provider, &sender),
            &pass,
            &mut authenticator,
            &mut proof,
            &mut client
        ));

        assert!(verify(
            &verifier,
            &pk_subscriber,
            &client_data_hash,
            &authenticator,
            &proof,
            &client
        ));
    }
}
