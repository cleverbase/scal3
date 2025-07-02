use crate::kem::{HardwareBackedDhP256HkdfSha256, KemPrivateKey};
use crate::rng::ReproducibleRng;
use frost::keys::SecretShare;
use frost_core::keys::{default_identifiers, VerifyingShare};
use frost_core::{Field, Identifier};
use frost_p256 as frost;
use frost_p256::keys::{KeyPackage, SigningShare};
use frost_p256::round1::{SigningCommitments, SigningNonces};
use frost_p256::P256ScalarField;
use hpke::aead::{AeadTag, AesGcm128};
use hpke::generic_array::{typenum, GenericArray};
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use p256::ecdh::SharedSecret;
use p256::ecdsa::Signature;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use p256::elliptic_curve::ops::MulByGenerator;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::PrimeField;
use p256::{ecdsa, FieldBytes, ProjectivePoint, PublicKey};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier as SignatureVerifier};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub(crate) struct Verifier {
    blinded_subscriber_share: p256::Scalar,
    pk_joint: frost::VerifyingKey,
    pub(crate) pk_kem_subscriber: <DhP256HkdfSha256 as Kem>::EncappedKey,
    sealed_provider_share: Vec<u8>,
    tag: AeadTag<AesGcm128>,
}

pub(crate) struct Pass {
    subscriber_commitments: SigningCommitments,
    authenticator_proof: AuthenticatorProof,
    binding: Binding,
    pk_kem_sender: <DhP256HkdfSha256 as Kem>::EncappedKey,
    sealed_signature_share: Vec<u8>,
    tag: AeadTag<AesGcm128>,
}

impl Pass {
    pub(crate) fn to_bytes(&self) -> [u8; 308] {
        let mut encoded = [0u8; 308];
        let mut offset = 0;
        
        // 66 bytes
        let challenge_bytes = challenge_to_bytes(self.subscriber_commitments);
        encoded[offset..offset + 66].copy_from_slice(&challenge_bytes);
        offset += 66;
        
        // 64 bytes
        let sig_device_bytes = self.authenticator_proof.sig_device.to_bytes();
        encoded[offset..offset + 64].copy_from_slice(&sig_device_bytes);
        offset += 64;
        
        // 33 bytes
        let pk_bytes = self.binding.pk.to_encoded_point(true);
        encoded[offset..offset + 33].copy_from_slice(pk_bytes.as_bytes());
        offset += 33;
        
        // 64 bytes
        let signature_bytes = self.binding.signature.to_bytes();
        encoded[offset..offset + 64].copy_from_slice(&signature_bytes);
        offset += 64;
        
        // 33 bytes
        let pk_sender_bytes = pk_sender_to_bytes(&self.pk_kem_sender);
        encoded[offset..offset + 33].copy_from_slice(&pk_sender_bytes);
        offset += 33;
        
        // 32 bytes
        encoded[offset..offset + 32].copy_from_slice(&self.sealed_signature_share);
        offset += 32;
        
        // 16 bytes
        let tag_bytes = self.tag.to_bytes();
        encoded[offset..offset + 16].copy_from_slice(&tag_bytes);
        
        encoded
    }

    pub(crate) fn from_bytes(encoded: &[u8]) -> Option<Pass> {
        let subscriber_commitments = challenge_from_bytes(&encoded[..66])?;
        let sig_device = signature_from_bytes(&encoded[66..66 + 64])?;
        let pk = ecdsa::VerifyingKey::from_sec1_bytes(&encoded[66 + 64..66 + 64 + 33]).ok()?;
        let signature = signature_from_bytes(&encoded[66 + 64 + 33..66 + 64 + 33 + 64])?;
        let pk_kem_sender =
            pk_sender_from_bytes(&encoded[66 + 64 + 33 + 64..66 + 64 + 33 + 64 + 33])?;
        let sealed_signature_share =
            Vec::from(&encoded[66 + 64 + 33 + 64 + 33..66 + 64 + 33 + 64 + 33 + 32]);
        let tag = AeadTag::from_bytes(
            &encoded[66 + 64 + 33 + 64 + 33 + 32..66 + 64 + 33 + 64 + 33 + 32 + 16],
        )
        .ok()?;
        Some(Pass {
            subscriber_commitments,
            authenticator_proof: AuthenticatorProof { sig_device },
            binding: Binding { pk, signature },
            pk_kem_sender,
            sealed_signature_share,
            tag,
        })
    }
}

pub(crate) fn signature_from_bytes(encoded: &[u8]) -> Option<Signature> {
    let bytes = GenericArray::clone_from_slice(encoded);
    p256::ecdsa::Signature::from_bytes(&bytes).ok()
}

pub(crate) fn pk_from_bytes(encoded: &[u8]) -> Option<p256::ecdsa::VerifyingKey> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded).ok()
}

struct Binding {
    pk: ecdsa::VerifyingKey,
    signature: Signature,
}

pub(crate) struct AuthenticatorExtensionTranscript {
    sig_joint_first: p256::Scalar,
    sig_joint_tag: AeadTag<AesGcm128>,
}

impl AuthenticatorExtensionTranscript {
    pub(crate) fn from_bytes(encoded: &[u8]) -> Option<AuthenticatorExtensionTranscript> {
        let bytes = GenericArray::clone_from_slice(&encoded[..32]);
        let first = p256::Scalar::from_repr(bytes).into_option()?;
        let tag = AeadTag::from_bytes(&encoded[32..]).ok()?;
        Some(AuthenticatorExtensionTranscript {
            sig_joint_first: first,
            sig_joint_tag: tag,
        })
    }
}

pub(crate) struct AuthenticatorProof {
    pub(crate) sig_device: Signature,
}

impl AuthenticatorProof {
    pub(crate) fn from_bytes(encoded: &[u8]) -> Option<Self> {
        let bytes = GenericArray::clone_from_slice(encoded);
        let sig_device = p256::ecdsa::Signature::from_bytes(&bytes).ok()?;
        Some(AuthenticatorProof { sig_device })
    }
}

pub(crate) struct ClientExtensionTranscript {
    pub(crate) pk_binding: ecdsa::VerifyingKey,
    pub(crate) sig_binding: Signature,
    pub(crate) sig_joint_second: p256::Scalar,
}

impl ClientExtensionTranscript {
    pub(crate) fn from_bytes(encoded: &[u8]) -> Option<Self> {
        let pk_binding = pk_from_bytes(&encoded[..33])?;
        let sig_binding = signature_from_bytes(&encoded[33..33 + 64])?;
        let bytes = GenericArray::clone_from_slice(&encoded[33 + 64..]);
        let sig_joint_second = p256::Scalar::from_repr(bytes).into_option()?;
        Some(Self {
            pk_binding,
            sig_binding,
            sig_joint_second,
        })
    }
}

impl ClientExtensionTranscript {
    pub(crate) fn to_bytes(&self) -> [u8; 129] {
        let mut encoded = [0u8; 129];
        let mut offset = 0;
        
        // 33 bytes
        let pk_binding_bytes = self.pk_binding.to_encoded_point(true);
        encoded[offset..offset + 33].copy_from_slice(pk_binding_bytes.as_bytes());
        offset += 33;
        
        // 64 bytes
        let sig_binding_bytes = self.sig_binding.to_bytes();
        encoded[offset..offset + 64].copy_from_slice(&sig_binding_bytes);
        offset += 64;
        
        // 32 bytes
        let sig_joint_second_bytes = self.sig_joint_second.to_bytes();
        encoded[offset..offset + 32].copy_from_slice(&sig_joint_second_bytes);
        
        encoded
    }
}

pub(crate) struct Transcript {
    pub(crate) authenticator: AuthenticatorExtensionTranscript,
    pub(crate) proof: AuthenticatorProof,
    pub(crate) client: ClientExtensionTranscript,
}

pub(crate) struct Authentication {
    subscriber_commitments: SigningCommitments,
    pub(crate) to_device_sign: [u8; 32],
    sk_binding: p256::ecdsa::SigningKey,
    pk_binding: p256::ecdsa::VerifyingKey,
    pub(crate) pk_s: <DhP256HkdfSha256 as Kem>::EncappedKey,
    tag: AeadTag<AesGcm128>,
    sealed_signature_share: Vec<u8>,
}

enum Role {
    PROVIDER,
}

pub(crate) struct Provider {
    pub(crate) randomness: [u8; 32],
}

#[derive(Debug, PartialEq)]
pub(crate) struct VerificationError;

pub(crate) type Result = core::result::Result<(), VerificationError>;

fn aad(masked_subscriber_share: &p256::Scalar, pk_joint: &frost::VerifyingKey) -> Vec<u8> {
    [
        masked_subscriber_share.to_bytes().as_slice(),
        pk_joint.to_element().to_bytes().as_slice(),
    ]
    .concat()
}

struct BlindingFactor(p256::Scalar);

impl From<&[u8; 32]> for BlindingFactor {
    fn from(value: &[u8; 32]) -> Self {
        let mut scalars = [frost::P256ScalarField::zero()];
        let domain = "SCAL3-Thresholds-v1mask".as_bytes();
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[value], &[domain], &mut scalars)
            .expect("message expansion should never fail");
        BlindingFactor(scalars[0])
    }
}

impl BlindingFactor {
    fn blind(&self, share: &frost::keys::SigningShare) -> p256::Scalar {
        share.to_scalar().add(&self.0)
    }

    fn unblind(&self, scalar: &p256::Scalar) -> frost::keys::SigningShare {
        frost::keys::SigningShare::new(scalar.sub(&self.0))
    }
}

type Aead = AesGcm128;
type Kdf = HkdfSha256;
type SwKem = DhP256HkdfSha256;
type HwKem = HardwareBackedDhP256HkdfSha256;
pub(crate) type KemPublicKey = <SwKem as Kem>::PublicKey;

impl Serializable for AuthenticatorExtensionTranscript {
    type OutputSize = typenum::U48;

    fn write_exact(&self, buf: &mut [u8]) {
        buf[..32].copy_from_slice(self.sig_joint_first.to_bytes().as_slice());
        buf[32..].copy_from_slice(self.sig_joint_tag.to_bytes().as_slice());
    }
}

impl Verifier {
    pub(crate) fn to_bytes(&self) -> GenericArray<u8, typenum::U250> {
        let mut buf = [0u8; 250];
        buf[0..32].copy_from_slice(self.blinded_subscriber_share.to_bytes().as_slice());
        buf[32..32 + 33]
            .copy_from_slice(self.pk_joint.to_element().to_encoded_point(true).as_bytes());
        buf[32 + 33..32 + 33 + 33].copy_from_slice(
            PublicKey::from_sec1_bytes(&self.pk_kem_subscriber.to_bytes())
                .expect("Invalid public key")
                .to_encoded_point(true)
                .as_bytes(),
        );
        buf[32 + 33 + 33..32 + 33 + 33 + 136]
            .copy_from_slice(self.sealed_provider_share.as_slice());
        buf[32 + 33 + 33 + 136..32 + 33 + 33 + 136 + 16]
            .copy_from_slice(self.tag.to_bytes().as_slice());
        GenericArray::from_iter(buf)
    }

    pub(crate) fn from_bytes(buf: &[u8; 250]) -> Option<Self> {
        let blinded_subscriber_share = scalar_from_bytes(&buf[0..32])?;
        let pk_joint = pk_frost_from_bytes(&buf[32..32 + 33])?;
        let pk_kem_subscriber = pk_sender_from_bytes(&buf[32 + 33..32 + 33 + 33])?;
        let sealed_provider_share = buf[32 + 33 + 33..32 + 33 + 33 + 136].to_vec();
        let tag: AeadTag<AesGcm128> =
            AeadTag::from_bytes(&buf[32 + 33 + 33 + 136..32 + 33 + 33 + 136 + 16]).ok()?;
        Some(Self {
            blinded_subscriber_share,
            pk_joint,
            pk_kem_subscriber,
            sealed_provider_share,
            tag,
        })
    }
}

pub(crate) fn pk_sender_from_bytes(
    encoded: &[u8],
) -> Option<<DhP256HkdfSha256 as Kem>::EncappedKey> {
    let pk = PublicKey::from_sec1_bytes(encoded).ok()?;
    <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(pk.to_encoded_point(false).as_bytes()).ok()
}

fn pk_sender_to_bytes(pk: &<DhP256HkdfSha256 as Kem>::EncappedKey) -> [u8; 33] {
    let pk = PublicKey::from_sec1_bytes(&pk.to_bytes()).unwrap();
    let mut buf = [0u8; 33];
    buf.copy_from_slice(pk.to_encoded_point(true).as_bytes());
    buf
}

pub(crate) fn pk_recipient_from_bytes(
    encoded: &[u8],
) -> Option<<DhP256HkdfSha256 as Kem>::PublicKey> {
    let pk = PublicKey::from_sec1_bytes(encoded).ok()?;
    <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(pk.to_encoded_point(false).as_bytes()).ok()
}

fn scalar_from_bytes(encoded: &[u8]) -> Option<p256::Scalar> {
    let bytes = FieldBytes::clone_from_slice(encoded);
    p256::Scalar::from_repr(bytes).into_option()
}

pub(crate) fn pk_frost_from_bytes(encoded: &[u8]) -> Option<frost::VerifyingKey> {
    let pk = p256::PublicKey::from_sec1_bytes(encoded).ok()?;
    Some(frost::VerifyingKey::new(pk.into()))
}

pub(crate) fn shared_secret_from_bytes(encoded: &[u8]) -> Option<p256::ecdh::SharedSecret> {
    let bytes = FieldBytes::clone_from_slice(encoded);
    let secret = p256::ecdh::SharedSecret::from(bytes);
    Some(secret)
}

fn commitment_from_bytes(encoded: &[u8]) -> Option<frost::round1::NonceCommitment> {
    let com = p256::PublicKey::from_sec1_bytes(&encoded).ok()?;
    let mut buf = [0u8; 33];
    buf.copy_from_slice(&com.to_encoded_point(true).to_bytes());
    let com = frost::round1::NonceCommitment::deserialize(&buf).ok()?;
    Some(com)
}

pub(crate) fn challenge_from_bytes(encoded: &[u8]) -> Option<frost::round1::SigningCommitments> {
    let hiding = commitment_from_bytes(&encoded[..33])?;
    let binding = commitment_from_bytes(&encoded[33..])?;
    Some(frost::round1::SigningCommitments::new(hiding, binding))
}

fn commitment_to_bytes(commitment: frost::round1::NonceCommitment) -> [u8; 33] {
    let mut buf = [0u8; 33];
    let commitment =
        p256::PublicKey::from_sec1_bytes(&commitment.serialize().unwrap().as_slice()).unwrap();
    buf.copy_from_slice(&commitment.to_encoded_point(true).as_bytes());
    buf
}

fn challenge_to_bytes(challenge: frost::round1::SigningCommitments) -> [u8; 66] {
    let mut buf = [0u8; 66];
    buf[..33].copy_from_slice(&commitment_to_bytes(*challenge.hiding()));
    buf[33..].copy_from_slice(&commitment_to_bytes(*challenge.binding()));
    buf
}

impl Transcript {
    fn verify_binding(&self) -> Result {
        self.client
            .pk_binding
            .verify(&self.proof.sig_device.to_bytes(), &self.client.sig_binding)
            .map_err(|_| VerificationError)
    }

    fn verify_device_signature(&self, pk_device: &ecdsa::VerifyingKey) -> Result {
        pk_device
            .verify(&self.authenticator.to_bytes(), &self.proof.sig_device)
            .map_err(|_| VerificationError)
    }
}

impl Verifier {
    fn aad(&self) -> Vec<u8> {
        aad(&self.blinded_subscriber_share, &self.pk_joint)
    }

    pub(crate) fn new(
        pk_kem_provider: &KemPublicKey,
        mask: &[u8; 32],
        rng: &mut ChaCha20Rng,
    ) -> Verifier {
        let identifiers = frost::keys::IdentifierList::Default;
        let (mut shares, package) =
            frost::keys::generate_with_dealer(2, 2, identifiers, ReproducibleRng(rng))
                .expect("key generation failed");
        let (_id1, provider_share) = shares.pop_first().expect("expected at least one share");
        let (_id2, subscriber_share) = shares.pop_first().expect("expected at least two shares");

        let blinded_subscriber_share =
            BlindingFactor::from(mask).blind(subscriber_share.signing_share());
        let mut sealed_provider_share = provider_share.serialize().expect("serialization failed");
        let pk_joint = *package.verifying_key();
        let (pk_kem_subscriber, tag) =
            hpke::single_shot_seal_in_place_detached::<Aead, Kdf, SwKem, _>(
                &OpModeS::Base,
                &pk_kem_provider,
                &[],
                &mut *sealed_provider_share,
                &aad(&blinded_subscriber_share, &pk_joint),
                rng.into(),
            )
            .expect("sealing failed");

        Verifier {
            sealed_provider_share,
            blinded_subscriber_share,
            pk_joint,
            pk_kem_subscriber,
            tag,
        }
    }

    pub(crate) fn verify(&self, secret: SharedSecret, pk: &KemPublicKey) -> Option<SecretShare> {
        let mut provider_share = self.sealed_provider_share.clone();
        let sk_provider = KemPrivateKey {
            ecdh_shared_secret: secret,
            pk_sender: self.pk_kem_subscriber.clone(),
            pk_recipient: pk.clone(),
        };
        hpke::single_shot_open_in_place_detached::<Aead, Kdf, HwKem>(
            &OpModeR::Base,
            &sk_provider,
            &self.pk_kem_subscriber,
            &[],
            &mut provider_share,
            &self.aad(),
            &self.tag,
        )
        .ok()?;
        Some(SecretShare::deserialize(&provider_share).expect("failed to deserialize"))
    }

    fn joint_commitment(&self, transcript: &Transcript) -> ProjectivePoint {
        ProjectivePoint::mul_by_generator(&transcript.client.sig_joint_second)
            - self.pk_joint.to_element().to_affine() * &transcript.authenticator.sig_joint_first
    }

    fn joint_message(pk_binding: &ecdsa::VerifyingKey, hash: &[u8; 32]) -> Vec<u8> {
        [pk_binding.to_encoded_point(true).as_bytes(), hash].concat()
    }

    fn verify_joint_signature(&self, transcript: &Transcript, hash: &[u8; 32]) -> Result {
        let message = Self::joint_message(&transcript.client.pk_binding, hash);
        let commitment = self.joint_commitment(transcript);
        let signature = frost::Signature::new(commitment, transcript.client.sig_joint_second);
        self.pk_joint
            .verify(&message, &signature)
            .map_err(|_| VerificationError)
    }

    pub(crate) fn verify_transcript(
        &self,
        transcript: &Transcript,
        pk: &ecdsa::VerifyingKey,
        hash: &[u8; 32],
    ) -> Result {
        transcript.verify_binding()?;
        transcript.verify_device_signature(pk)?;
        self.verify_joint_signature(transcript, hash)
    }

    pub(crate) fn authenticate(
        &self,
        mask: &[u8; 32],
        provider_commitments: &SigningCommitments,
        pk_kem_provider: &KemPublicKey,
        rng: &mut ChaCha20Rng,
        client_data_hash: &[u8; 32],
    ) -> Authentication {
        let sk_binding = ecdsa::SigningKey::random(&mut ReproducibleRng(rng));
        let pk_binding = *sk_binding.verifying_key();
        let message = Self::joint_message(&pk_binding, client_data_hash);
        let share = BlindingFactor::from(mask).unblind(&self.blinded_subscriber_share);
        let (nonces, subscriber_commitments) =
            frost::round1::commit(&share, &mut ReproducibleRng(rng));
        let ids = &default_identifiers(2)[0..2];
        let commitments = commitment_map(*provider_commitments, subscriber_commitments);
        let signing_package = frost_p256::SigningPackage::new(commitments, &message);
        let key_package =
            KeyPackage::new(ids[1], share, VerifyingShare::from(share), self.pk_joint, 2);
        let signature_share =
            frost_p256::round2::sign(&signing_package, &nonces, &key_package).unwrap();
        let binding_factors =
            frost_core::compute_binding_factor_list(&signing_package, &self.pk_joint, &[])
                .expect("binding factors");
        let joint_commitment =
            frost_core::compute_group_commitment(&signing_package, &binding_factors)
                .expect("group commitment");
        let challenge = frost_core::challenge::<frost_p256::P256Sha256>(
            &joint_commitment.to_element(),
            &self.pk_joint,
            &message,
        )
        .expect("challenge")
        .to_scalar();

        let mut sealed_signature_share = signature_share.serialize();
        let (pk_s, tag) =
            hpke::single_shot_seal_in_place_detached::<AesGcm128, HkdfSha256, DhP256HkdfSha256, _>(
                &OpModeS::Base,
                &pk_kem_provider,
                &[],
                &mut *sealed_signature_share,
                &challenge.to_bytes(),
                rng,
            )
            .unwrap();
        let to_device_sign: [u8; 32] = Sha256::digest(
            AuthenticatorExtensionTranscript {
                sig_joint_first: challenge,
                sig_joint_tag: AeadTag::from_bytes(&tag.to_bytes()).expect("codec"),
            }
            .to_bytes(),
        )
        .into();

        Authentication {
            subscriber_commitments,
            to_device_sign,
            sk_binding,
            pk_binding,
            pk_s,
            tag,
            sealed_signature_share,
        }
    }

    fn key_package(&self, role: Role, share: &SigningShare) -> KeyPackage {
        let index = match role {
            Role::PROVIDER => 0,
        };
        KeyPackage::new(
            default_identifiers(2)[index],
            *share,
            VerifyingShare::from(*share),
            self.pk_joint,
            2,
        )
    }
}

impl Authentication {
    pub(crate) fn finalize(&self, sig_device: &Signature) -> Pass {
        let signature = self.sk_binding.sign(&sig_device.to_bytes());
        let pk = self.pk_binding;
        Pass {
            subscriber_commitments: self.subscriber_commitments,
            binding: Binding { pk, signature },
            pk_kem_sender: self.pk_s.clone(),
            sealed_signature_share: self.sealed_signature_share.clone(),
            tag: AeadTag::from_bytes(&self.tag.to_bytes()).expect("codec"),
            authenticator_proof: AuthenticatorProof {
                sig_device: sig_device.clone(),
            },
        }
    }
}

fn commitment_map(
    provider: SigningCommitments,
    subscriber: SigningCommitments,
) -> BTreeMap<Identifier<frost::P256Sha256>, SigningCommitments> {
    let ids = &default_identifiers(2)[0..2];
    BTreeMap::from([(ids[0], provider), (ids[1], subscriber)])
}

impl Provider {
    pub(crate) fn challenge(&self) -> (SigningNonces, SigningCommitments) {
        let mut scalars = [P256ScalarField::zero(), P256ScalarField::zero()];
        let domain = "FROST-P256-SHA256-v1nonce".as_bytes();
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(
            &[&self.randomness],
            &[domain],
            &mut scalars,
        )
        .expect("message expansion should never fail");
        let nonces = scalars.map(|s| frost_core::round1::Nonce::from_scalar(s));
        let nonces = frost::round1::SigningNonces::from_nonces(nonces[0], nonces[1]);
        let commitments = frost::round1::SigningCommitments::from(&nonces);
        (nonces, commitments)
    }

    pub(crate) fn prove(
        self,
        verifier: &Verifier,
        pk_device: &ecdsa::VerifyingKey,
        client_data_hash: &[u8; 32],
        pass: &Pass,
        shared_secret_verifier: SharedSecret,
        shared_secret_signature: SharedSecret,
        pk_kem_provider: &<HardwareBackedDhP256HkdfSha256 as Kem>::PublicKey,
    ) -> Option<Transcript> {
        let share = verifier.verify(shared_secret_verifier, &pk_kem_provider)?;
        let (nonces, commitments) = self.challenge();
        let message = Verifier::joint_message(&pass.binding.pk, client_data_hash);
        let commitments = commitment_map(commitments, pass.subscriber_commitments);
        let signing_package = frost_p256::SigningPackage::new(commitments, &message);
        let key_package = verifier.key_package(Role::PROVIDER, share.signing_share());
        let signature_share = frost_p256::round2::sign(&signing_package, &nonces, &key_package)
            .expect("signature share");
        let binding_factors =
            frost_core::compute_binding_factor_list(&signing_package, &verifier.pk_joint, &[])
                .expect("binding factors");
        let joint_commitment =
            frost_core::compute_group_commitment(&signing_package, &binding_factors)
                .expect("group commitment");
        let challenge_scalar = frost_core::challenge::<frost_p256::P256Sha256>(
            &joint_commitment.to_element(),
            &verifier.pk_joint,
            &message,
        )
        .expect("challenge")
        .to_scalar();
        let mut sealed_signature_share = pass.sealed_signature_share.clone();
        hpke::single_shot_open_in_place_detached::<Aead, Kdf, HwKem>(
            &OpModeR::Base,
            &KemPrivateKey {
                ecdh_shared_secret: shared_secret_signature,
                pk_sender: pass.pk_kem_sender.clone(),
                pk_recipient: pk_kem_provider.clone(),
            },
            &pass.pk_kem_sender,
            &[],
            &mut sealed_signature_share,
            &[challenge_scalar.to_bytes()].concat(), // TODO consider binding to message as well
            &pass.tag,
        )
        .ok()?;
        let subscriber_signature_share =
            frost_p256::round2::SignatureShare::deserialize(&sealed_signature_share).ok()?;

        let sig_joint_second = signature_share
            .share()
            .0
            .add(&subscriber_signature_share.share().0);
        let transcript = Transcript {
            authenticator: AuthenticatorExtensionTranscript {
                sig_joint_first: challenge_scalar,
                sig_joint_tag: AeadTag::from_bytes(&pass.tag.to_bytes()).expect("clone"),
            },
            proof: AuthenticatorProof {
                sig_device: pass.authenticator_proof.sig_device.clone(),
            },
            client: ClientExtensionTranscript {
                pk_binding: pass.binding.pk,
                sig_binding: pass.binding.signature.clone(),
                sig_joint_second,
            },
        };
        verifier
            .verify_transcript(&transcript, &pk_device, client_data_hash)
            .map(|_| transcript)
            .ok()
    }
}

#[cfg(test)]
mod test {
    use crate::domain::{Provider, Verifier};
    use crate::rng::ReproducibleRng;
    use hpke::kem::DhP256HkdfSha256;
    use hpke::{Kem, Serializable};
    use p256::elliptic_curve::ecdh::SharedSecret;
    use p256::{ecdsa, NistP256, NonZeroScalar};
    use rand_chacha::rand_core::SeedableRng as OtherSeedableRng;
    use sha2::{Digest, Sha256};
    use signature::hazmat::PrehashSigner;

    fn dh(
        sk_r: &<DhP256HkdfSha256 as Kem>::PrivateKey,
        pk_s: &<DhP256HkdfSha256 as Kem>::EncappedKey,
    ) -> SharedSecret<NistP256> {
        let pk = p256::PublicKey::from_sec1_bytes(&pk_s.to_bytes()).unwrap();
        let sk: NonZeroScalar = NonZeroScalar::from_repr(sk_r.to_bytes()).unwrap();
        p256::ecdh::diffie_hellman::<NistP256>(sk, pk.as_affine())
    }

    #[test]
    fn test_enrollment_and_authentication() {
        let mask = [0; 32];
        let randomness = [0; 32];
        let seed = [0; 32];
        let mut rng_hpke = rand_chacha::ChaCha20Rng::from_seed(seed);
        let (sk_r, pk_r) = DhP256HkdfSha256::gen_keypair(&mut rng_hpke);
        let verifier = Verifier::new(&pk_r, &mask, &mut rng_hpke);
        // Removed println! for no_std compatibility
        let shared_secret = dh(&sk_r, &verifier.pk_kem_subscriber);
        let s = verifier.verify(shared_secret, &pk_r);
        assert!(s.is_some());
        let provider = Provider { randomness };
        let (_nonces, commitments) = provider.challenge();
        let msg = Sha256::digest("hoi".as_bytes());
        let authentication =
            verifier.authenticate(&mask, &commitments, &pk_r, &mut rng_hpke, msg.as_ref());
        let sk_device = ecdsa::SigningKey::random(&mut ReproducibleRng(&mut rng_hpke));
        let pk_device = ecdsa::VerifyingKey::from(&sk_device);
        let (sig_device, _) = sk_device
            .sign_prehash(&authentication.to_device_sign)
            .unwrap();
        let pass = authentication.finalize(&sig_device);
        let shared_secret_verifier = dh(&sk_r, &verifier.pk_kem_subscriber);
        let shared_secret_signature = dh(&sk_r, &pass.pk_kem_sender);
        let evidence = provider.prove(
            &verifier,
            &pk_device,
            msg.as_ref(),
            &pass,
            shared_secret_verifier,
            shared_secret_signature,
            &pk_r,
        );
        assert!(evidence.is_some());
    }
}
