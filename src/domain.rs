use std::borrow::ToOwned;
use serde::{Deserialize, Serialize};
use frost_p256 as frost;
use frost_p256::keys::{dkg, KeyPackage, SecretShare, VerifyingShare};
use p256::{ecdsa, FieldBytes, ProjectivePoint};
use zeroize::ZeroizeOnDrop;
use frost_p256::{P256Group, P256ScalarField, P256Sha256};
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, hash_to_field};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use signature::rand_core::CryptoRngCore;
use frost_p256::keys::dkg::round2::Package;
use frost_core::frost::keys::SigningShare;
use p256::ecdsa::VerifyingKey;
use frost_core::frost::round1::NonceCommitment;
use frost_p256::round1::SigningCommitments;
use frost_core::{Field, Group};
use std::ops::Mul;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::ops::MulByGenerator;
use signature::{Signer, Verifier};
use crate::group::{Element, Proof, Scalar, Signature};
use crate::Payload;

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct Provider {
    pub(crate) randomness: [u8; 32],
}

impl Provider {
    pub(crate) fn vouch(self) -> (VoucherSecret, Voucher) {
        let mut scalars = [P256ScalarField::zero(), P256ScalarField::zero(), P256ScalarField::zero()];
        let domain = "SCAL3-FROST-v1share".as_bytes();
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[&self.randomness], &[domain], &mut scalars)
            .expect("message expansion should never fail");
        let coefficient_commitment: Vec<_> = scalars
            .iter()
            .map(|c| P256Group::generator() * *c)
            .collect();
        let proof_randomizer = scalars[2];
        let proof_commitment = P256Group::generator() * proof_randomizer;
        let mut proof_challenge = [P256ScalarField::zero()];
        let domain = "FROST-P256-SHA256-v1dkg".as_bytes();
        let mut preimage = vec![];
        preimage.extend_from_slice(Role::Provider.identifier().serialize().as_ref());
        preimage.extend_from_slice(P256Group::serialize(&coefficient_commitment[0]).as_ref());
        preimage.extend_from_slice(P256Group::serialize(&proof_commitment).as_ref());
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[&preimage], &[domain], &mut proof_challenge)
            .expect("message expansion should never fail");
        let proof_challenge = proof_challenge[0];
        let proof_of_knowledge = frost::Signature::new(proof_commitment, proof_randomizer + scalars[0] * proof_challenge);
        let payload = Voucher {
            commitment_share: (Element(coefficient_commitment[0]), Element(coefficient_commitment[1])),
            proof_of_knowledge: proof_of_knowledge.into(),
        };
        let secret = VoucherSecret { coefficients: (scalars[0], scalars[1]) };
        (secret, payload)
    }

    pub(crate) fn validate(self, redemption: Redemption) -> Option<Validating> {
        let (secret, payload) = self.vouch();
        let a10 = secret.coefficients.0;
        let a11 = secret.coefficients.1;
        let proof_commitment = redemption.proof.0.0;
        let mu2 = &redemption.proof.1.0;
        let phi20 = redemption.commitments.0.0;
        let mut c2 = [P256ScalarField::zero()];
        let domain = "FROST-P256-SHA256-v1dkg".as_bytes();
        let mut preimage = vec![];
        preimage.extend_from_slice(Role::Subscriber.identifier().serialize().as_ref());
        preimage.extend_from_slice(P256Group::serialize(&phi20).as_ref());
        preimage.extend_from_slice(P256Group::serialize(&proof_commitment).as_ref());
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[&preimage], &[domain], &mut c2)
            .expect("message expansion should never fail");
        let c2 = c2[0];
        if proof_commitment != P256Group::generator() * mu2 - phi20 * c2 { return None; }
        let f12 = a10 + Role::Subscriber.identifier().mul(a11);
        let f11 = a10 + Role::Provider.identifier().mul(a11);
        let f21 = &redemption.share;
        let f21 = frost::keys::SigningShare::deserialize(<[u8; 32]>::from(f21.0.to_bytes())).unwrap();
        let commitment0 = redemption.commitments.0.0.to_bytes().try_into().expect("known serialization");
        let commitment1 = redemption.commitments.1.0.to_bytes().try_into().expect("known serialization");
        let commitments = frost::keys::VerifiableSecretSharingCommitment::deserialize(vec!(
            commitment0, commitment1
        )).expect("known deserialization");

        let secret_share = SecretShare::new(Role::Provider.identifier(), f21, commitments.clone());
        let _ = secret_share.verify().expect("valid secret share");
        let own_signing_share = frost::keys::SigningShare::new(f21.to_scalar() + f11);
        let group_public = commitments.serialize();
        let group_public = P256Group::deserialize(group_public.first().unwrap()).unwrap() + payload.commitment_share.0.0;
        let group_public = frost::VerifyingKey::new(group_public);
        let package = dkg::round2::Package::new(frost::keys::SigningShare::new(f12));
        Some(Validating {
            round2_package: package,
            joint_vk: group_public,
            signing_share: own_signing_share,
        })
    }

    /// This implementation expects high quality randomness, so does not hedge against weak random
    /// number generators by mixing in the signing share value.
    pub(crate) fn challenge(self) -> (Randomizer, ChallengePayload) {
        let mut scalars = [P256ScalarField::zero(), P256ScalarField::zero()];
        let domain = "FROST-P256-SHA256-v1nonce".as_bytes();
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[&self.randomness], &[domain], &mut scalars)
            .expect("message expansion should never fail");
        let commitments = frost::round1::SigningCommitments::new(
            frost::round1::NonceCommitment::from(&nonce(scalars[0])),
            frost::round1::NonceCommitment::from(&nonce(scalars[1])),
        );
        let randomizer = Randomizer { hiding_nonce: scalars[0], binding_nonce: scalars[1] };
        let share = commitments.into();
        (randomizer, share)
    }

    pub(crate) fn prove(
        self, registration: &Subscriber, mask: Mask, payload: &Payload, pass: Pass,
    ) -> Result<Evidence, ProofError> {
        if !pass.is_well_bound() { return Err(ProofError::BadBinding); }
        let signing_share = frost::keys::SigningShare::new(registration.identifier.prov_sks_masked.0 - p256::Scalar::from(mask));
        let message = pass.message(&payload);
        let provider = Role::Provider.identifier();
        let (randomizer, share) = self.challenge();
        let package = frost::SigningPackage::new(BTreeMap::from([
            (Role::Subscriber.identifier(), pass.clone().into()),
            (provider, share.into()),
        ]), &message);
        let binding_factors = frost_core::frost::compute_binding_factor_list(
            &package, &frost::VerifyingKey::new(registration.identifier.joint_vk.0), &[]);
        let binding_factor = binding_factors.get(&provider)
            .expect("getting the provider binding factor should never fail");
        let commitment = frost_core::frost::compute_group_commitment(&package, &binding_factors)
            .expect("only possible error is identity commitment; too unlikely to catch");
        let lambda_i = frost_core::frost::derive_interpolating_value(&provider, &package)
            .expect("cannot fail");
        let challenge = frost_core::challenge::<P256Sha256>(
            &commitment.clone().to_element(), &registration.identifier.joint_vk.0, &message);
        let device_sig: ecdsa::Signature = pass.device_sig.clone().into();
        if !registration.device_vk.verify(
            &[
                DATA_TO_SIGN_DOMAIN,
                challenge.clone().to_scalar().to_bytes().as_slice()
            ].concat(),
            &device_sig,
        ).is_ok() { return Err(ProofError::BadDeviceSignature); }
        let z = pass.signature_share.0 + &randomizer.hiding_nonce
            + (randomizer.binding_nonce * Scalar::from(binding_factor).0)
            + (lambda_i * signing_share.to_scalar() * &challenge.clone().to_scalar());
        if !frost::VerifyingKey::new(registration.identifier.joint_vk.0).verify(
            &message, &frost::Signature::new(commitment.to_element(), z),
        ).is_ok() { return Err(ProofError::BadJointSignature); }
        let joint_sig = JointSignature { c: challenge.to_scalar().into(), z: z.into() };
        let evidence = Evidence {
            binding_vk: pass.binding_vk.into(),
            joint_sig,
            device_sig: pass.device_sig.into(),
            binding_sig: pass.binding_sig.into(),
        };
        Ok(evidence)
    }
}

impl From<[u8; 32]> for Provider {
    fn from(randomness: [u8; 32]) -> Self {
        Provider { randomness }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Voucher {
    commitment_share: (Element, Element),
    proof_of_knowledge: Proof,
}

impl Voucher {
    pub(crate) fn redeem(self, rng: &mut impl CryptoRngCore) -> Option<(Enrollment, Redemption)> {
        let provider = Role::Provider.identifier();
        let subs = Role::Subscriber.identifier();
        let (subs_dkg1_secret, subs_dkg1_share) = dkg::part1(subs, 2, 2, rng)
            .expect("the dkg first part should never fail");
        let subs_dkg1_in = HashMap::from([(provider, self.clone().into())]);
        let (subs_dkg2_secret, subs_dkg2_share) = dkg::part2(subs_dkg1_secret, &subs_dkg1_in).ok()?;
        let commitments = subs_dkg1_share.commitment().serialize();
        let commitments = (
            Element::deserialize(&commitments[0]).expect("known serialization"),
            Element::deserialize(&commitments[1]).expect("known serialization"),
        );
        let proof = (*subs_dkg1_share.proof_of_knowledge()).into();
        let share = Scalar(subs_dkg2_share[&provider].secret_share().to_scalar());
        Some((Enrollment {
            payload: self,
            package: subs_dkg2_secret,
        }, Redemption { commitments, proof, share }))
    }
}

impl From<Voucher> for dkg::round1::Package {
    fn from(value: Voucher) -> Self {
        let commitment_share: Vec<[u8; 33]> = [value.commitment_share.0, value.commitment_share.1]
            .iter()
            .map(|c| c.0.to_bytes())
            .map(|c| <[u8; 33]>::from(c))
            .collect();
        let commitment_share = frost_core::frost::keys::VerifiableSecretSharingCommitment::<P256Sha256>::deserialize(commitment_share)
            .expect("commitment share deserialization should never fail");
        dkg::round1::Package::new(commitment_share, value.proof_of_knowledge.into())
    }
}

#[derive(Debug)]
pub struct Enrollment {
    payload: Voucher,
    package: dkg::round2::SecretPackage,
}

impl Enrollment {
    pub(crate) fn complete(self, validation: Validation, subs_mask: Mask) -> Option<Identifier> {
        let prov_sks_masked = validation.prov_sks_masked.clone();
        let prov_dkg1_share = self.payload.into();
        let prov_dkg2_share = validation.into();
        let subs_dkg2_secret = self.package;
        let prov = Role::Provider.identifier();
        let subs_dkg1_in = HashMap::from([(prov, prov_dkg1_share)]);
        let subs_dkg2_in = HashMap::from([(prov, prov_dkg2_share)]);
        let (subs_sks, subs_pks) = dkg::part3(&subs_dkg2_secret, &subs_dkg1_in, &subs_dkg2_in).ok()?;
        let subs_sks_masked = subs_sks.secret_share().to_scalar() + p256::Scalar::from(subs_mask);
        Some(Identifier {
            joint_vk: subs_pks.group_public().to_element().into(),
            prov_sks_masked: prov_sks_masked.0.into(),
            subs_sks_masked: subs_sks_masked.into(),
        })
    }
}

pub(crate) struct VoucherSecret {
    coefficients: (p256::Scalar, p256::Scalar),
}

pub struct Validating {
    round2_package: dkg::round2::Package,
    joint_vk: frost::VerifyingKey,
    signing_share: frost::keys::SigningShare,
}

pub(crate) const KEY_DERIVATION_DOMAIN: &[u8; 20] = b"SCAL3-FROST-v1derive";

fn key_derivation_info(
    joint_vk: &frost::VerifyingKey,
) -> Vec<u8> {
    [
        &KEY_DERIVATION_DOMAIN[..],
        &joint_vk.serialize(),
    ].concat()
}

impl Validating {
    pub(crate) fn key_derivation_info(&self) -> Vec<u8> {
        key_derivation_info(&self.joint_vk)
    }

    pub(crate) fn finalize_with_mask(self, mask: Mask) -> Validation {
        let prov_sks_masked = self.signing_share.to_scalar() + p256::Scalar::from(mask);
        Validation {
            share: self.round2_package.secret_share().to_scalar().into(),
            joint_vk: self.joint_vk.to_element().into(),
            prov_sks_masked: prov_sks_masked.into(),
        }
    }

    fn finalize<F>(self, f: F) -> Validation where F: Fn(&[u8]) -> Mask {
        let info = self.key_derivation_info();
        self.finalize_with_mask(f(&info))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Validation {
    share: Scalar,
    joint_vk: Element,
    pub prov_sks_masked: Scalar,
}

impl Validation {
    pub(crate) fn authorize(self, identifier: &Identifier) -> bool {
        identifier.joint_vk.0 == self.joint_vk.0 && identifier.prov_sks_masked.0 == self.prov_sks_masked.0
    }
}

impl Into<dkg::round2::Package> for Validation {
    fn into(self) -> Package {
        dkg::round2::Package::new(SigningShare::new(self.share.0))
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct Mask(pub(crate) [u8; 32]);

impl From<Mask> for p256::Scalar {
    fn from(value: Mask) -> Self {
        let mut scalars = [P256ScalarField::zero()];
        let domain = "SCAL3-FROST-v1mask".as_bytes();
        hash_to_field::<ExpandMsgXmd<Sha256>, p256::Scalar>(&[&value.0], &[domain], &mut scalars)
            .expect("message expansion should never fail");
        scalars[0]
    }
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct Randomizer {
    hiding_nonce: p256::Scalar,
    binding_nonce: p256::Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengePayload {
    hiding_commitment: Element,
    binding_commitment: Element,
}

impl Into<frost::round1::SigningCommitments> for ChallengePayload {
    fn into(self) -> frost::round1::SigningCommitments {
        let hiding_bytes: [u8; 33] = self.hiding_commitment.0.to_bytes().as_slice().try_into()
            .expect("known serialization");
        let binding_bytes: [u8; 33] = self.binding_commitment.0.to_bytes().as_slice().try_into()
            .expect("known serialization");
        frost::round1::SigningCommitments::new(
            NonceCommitment::deserialize(hiding_bytes.into()).expect("known deserialization"),
            NonceCommitment::deserialize(binding_bytes.into()).expect("known deserialization"),
        )
    }
}

impl From<frost::round1::SigningCommitments> for ChallengePayload {
    fn from(value: SigningCommitments) -> Self {
        ChallengePayload {
            hiding_commitment: Element::deserialize(&value.hiding().serialize())
                .expect("known serialization"),
            binding_commitment: Element::deserialize(&value.binding().serialize())
                .expect("known serialization"),
        }
    }
}

fn nonce(scalar: p256::Scalar) -> frost_core::frost::round1::Nonce<P256Sha256> {
    let mut data = [0u8; 32];
    scalar.to_bytes().clone_into(<&mut FieldBytes>::from(&mut data));
    frost_core::frost::round1::Nonce::deserialize(data)
        .expect("scalar deserialization should never fail")
}

impl From<&Randomizer> for ChallengePayload {
    fn from(value: &Randomizer) -> Self {
        let mut nonce1data = [0u8; 32];
        let mut nonce2data = [0u8; 32];
        value.hiding_nonce.to_bytes().clone_into(<&mut FieldBytes>::from(&mut nonce1data));
        value.binding_nonce.to_bytes().clone_into(<&mut FieldBytes>::from(&mut nonce2data));
        let nonce1 = frost_core::frost::round1::Nonce::deserialize(nonce1data)
            .expect("known serialization");
        let nonce2 = frost_core::frost::round1::Nonce::deserialize(nonce2data)
            .expect("known serialization");
        let comm1 = frost::round1::NonceCommitment::from(&nonce1);
        let comm2 = frost::round1::NonceCommitment::from(&nonce2);
        let commitments = frost::round1::SigningCommitments::new(comm1, comm2);
        commitments.into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Identifier {
    pub joint_vk: Element,
    pub prov_sks_masked: Scalar,
    pub subs_sks_masked: Scalar,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JointSignature {
    pub c: Scalar,
    pub z: Scalar,
}

impl JointSignature {
    fn message(session_pk: &Element, payload: &[u8]) -> Vec<u8> {
        [
            &session_pk.0.to_encoded_point(true).as_bytes(),
            payload,
        ].concat()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub binding_vk: Element,
    pub joint_sig: JointSignature,
    pub device_sig: Signature,
    pub binding_sig: Signature,
}

#[derive(Debug)]
pub struct Subscriber {
    pub device_vk: ecdsa::VerifyingKey,
    pub identifier: Identifier,
}

pub(crate) const DATA_TO_SIGN_DOMAIN: &[u8; 20] = b"SCAL3-FROST-v1device";

impl Subscriber {
    pub(crate) fn pass(
        &self, mask: Mask, share: ChallengePayload, payload: &Payload, rng: &mut impl CryptoRngCore,
    ) -> PassDraft {
        let subscriber = Role::Subscriber.identifier();
        let signing_share = frost::keys::SigningShare::new(self.identifier.subs_sks_masked.0 - p256::Scalar::from(mask));
        let verifying_share = VerifyingShare::from(signing_share);
        let key_package = KeyPackage::new(
            subscriber, signing_share, verifying_share, frost::VerifyingKey::new(self.identifier.joint_vk.0), 2u16);
        let binding_sk = ecdsa::SigningKey::random(rng);
        let binding_vk = *binding_sk.verifying_key();
        let message = JointSignature::message(&binding_vk.into(), &payload.0);
        let (nonce, commitment_share) = frost_p256::round1::commit(&signing_share, rng);
        let signing = frost::SigningPackage::new(BTreeMap::from([
            (subscriber, commitment_share),
            (Role::Provider.identifier(), share.into()),
        ]), &message);
        let signature_share = frost::round2::sign(&signing, &nonce, &key_package)
            .expect("only possible error is identity commitment; too unlikely to catch");
        let binding_factors = frost_core::frost::compute_binding_factor_list(
            &signing, &key_package.group_public(), &[]);
        let joint_commitment = frost_core::frost::compute_group_commitment(
            &signing, &binding_factors)
            .expect("signing succeeded so recalculating the joint commitment should not fail");
        let challenge = frost_core::challenge::<P256Sha256>(
            &joint_commitment.clone().to_element(), &key_package.group_public().to_element(),
            &message);
        let data_under_device_proof = [
            DATA_TO_SIGN_DOMAIN,
            challenge.to_scalar().to_bytes().as_slice()
        ].concat();
        PassDraft {
            data_under_device_sig: data_under_device_proof,
            binding_vk,
            binding_sk,
            payload: payload.0.clone(),
            commitment_share,
            signature_share,
        }
    }

    pub(crate) fn verify(&self, payload: &Payload, evidence: &Evidence) -> bool {
        let message = [
            &evidence.binding_vk.0.to_encoded_point(true).as_bytes(),
            payload.0.as_slice(),
        ].concat();
        let binding_vk: &VerifyingKey = &evidence.binding_vk.clone().into();
        let binding_sig: &ecdsa::Signature = &evidence.binding_sig.clone().into();
        let device_sig: &ecdsa::Signature = &evidence.device_sig.clone().into();
        binding_vk.verify(&device_sig.to_bytes(), binding_sig).is_ok()
            && self.device_vk.verify(
            &[
                DATA_TO_SIGN_DOMAIN,
                evidence.joint_sig.c.clone().0.to_bytes().as_slice()
            ].concat(), device_sig).is_ok()
            && frost::VerifyingKey::new(self.identifier.joint_vk.0).verify(&message, &self.frost_signature(evidence)).is_ok()
    }

    fn joint_commitment(&self, evidence: &Evidence) -> ProjectivePoint {
        ProjectivePoint::mul_by_generator(&evidence.joint_sig.z.0) - self.identifier.joint_vk.0.mul(evidence.joint_sig.c.clone().0)
    }

    fn frost_signature(&self, evidence: &Evidence) -> frost::Signature {
        frost::Signature::new(self.joint_commitment(evidence), evidence.joint_sig.z.0)
    }

    pub fn key_derivation_info(&self) -> Vec<u8> {
        key_derivation_info(&frost::VerifyingKey::new(self.identifier.joint_vk.0))
    }
}

#[derive(Clone, Debug)]
pub struct PassDraft {
    pub data_under_device_sig: Vec<u8>,
    pub binding_sk: ecdsa::SigningKey,
    pub binding_vk: ecdsa::VerifyingKey,
    pub payload: Vec<u8>,
    pub commitment_share: frost::round1::SigningCommitments,
    pub signature_share: frost::round2::SignatureShare,
}

impl PassDraft {
    pub(crate) fn finalize_with_signature(self, device_sig: ecdsa::Signature) -> Pass {
        let (session_sig, _) = self.binding_sk.sign(&device_sig.to_bytes());
        Pass {
            binding_vk: self.binding_vk.into(),
            hiding_commitment: (*self.commitment_share.hiding()).into(),
            binding_commitment: (*self.commitment_share.binding()).into(),
            signature_share: (*self.signature_share.share()).into(),
            device_sig: device_sig.into(),
            binding_sig: session_sig.into(),
        }
    }

    pub fn finalize<F>(self, f: F) -> Pass where F: Fn(&[u8]) -> ecdsa::Signature {
        let signature = f(&self.data_under_device_sig);
        self.finalize_with_signature(signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pass {
    pub binding_vk: Element,
    pub hiding_commitment: Element,
    pub binding_commitment: Element,
    pub signature_share: Scalar,
    pub device_sig: Signature,
    pub binding_sig: Signature,
}

impl Pass {
    fn message(&self, payload: &Payload) -> Vec<u8> {
        JointSignature::message(&self.binding_vk, &payload.0)
    }

    fn is_well_bound(&self) -> bool {
        let binding_vk: &VerifyingKey = &self.binding_vk.clone().into();
        let binding_sig: &ecdsa::Signature = &self.binding_sig.clone().into();
        binding_vk.verify(&self.device_sig.clone().to_bytes(), binding_sig).is_ok()
    }
}

impl Into<frost::round1::SigningCommitments> for Pass {
    fn into(self) -> frost::round1::SigningCommitments {
        let hiding_bytes: [u8; 33] = self.hiding_commitment.0.to_bytes().as_slice().try_into()
            .expect("known serialization");
        let binding_bytes: [u8; 33] = self.binding_commitment.0.to_bytes().as_slice().try_into()
            .expect("known serialization");
        frost::round1::SigningCommitments::new(
            NonceCommitment::deserialize(hiding_bytes.into()).expect("known deserialization"),
            NonceCommitment::deserialize(binding_bytes.into()).expect("known deserialization"),
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Redemption {
    commitments: (Element, Element),
    proof: Proof,
    share: Scalar,
}

impl Into<dkg::round1::Package> for Redemption {
    fn into(self) -> dkg::round1::Package {
        let commitment0 = self.commitments.0.0.to_bytes().try_into().expect("known serialization");
        let commitment1 = self.commitments.1.0.to_bytes().try_into().expect("known serialization");
        let commitments = frost::keys::VerifiableSecretSharingCommitment::deserialize(vec!(
            commitment0, commitment1
        )).expect("known deserialization");
        dkg::round1::Package::new(commitments, self.proof.into())
    }
}

enum Role {
    Provider,
    Subscriber,
}

impl Role {
    fn identifier(&self) -> frost::Identifier {
        frost::Identifier::try_from(match self {
            Role::Provider => 1u16,
            Role::Subscriber => 2u16,
        }).expect("casting from these integers should never fail")
    }
}

#[derive(Debug)]
pub enum ProofError {
    BadBinding,
    BadDeviceSignature,
    BadJointSignature,
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use hmac::digest::Output;
    use p256::ecdsa;
    use rand::thread_rng;
    use sha2::Sha256;
    use signature::Signer;
    use crate::domain::{Mask, Provider, Subscriber};
    use crate::Payload;

    const PROV_KEY: &[u8] = b"provider secret key";
    const SUBS_KEY: &[u8] = b"provider secret key";

    type HmacSha256 = Hmac<Sha256>;

    fn derive(key: &[u8], info: &[u8]) -> [u8; 32] {
        let mut output = [0; 32];
        let mut mac = HmacSha256::new_from_slice(key).expect("should not fail");

        mac.update(info);
        mac.finalize().into_bytes().clone_into(<&mut Output<Hmac<Sha256>>>::from(&mut output));

        output
    }

    fn provider(info: &[u8]) -> Provider { derive(PROV_KEY, info).into() }

    fn enter(pin: &[u8]) -> Mask { Mask(derive(SUBS_KEY, pin)) }

    fn context(subscriber: &Subscriber) -> Mask { Mask(derive(PROV_KEY, &subscriber.key_derivation_info())) }

    #[test]
    fn test_enrollment_and_authentication() {
        let metadata = b"some unique voucher metadata, such as a nonce and timestamp";
        let pin = b"12345";

        let (_, payload) = provider(metadata).vouch();
        let (enrollment, redemption) = payload.redeem(&mut thread_rng()).unwrap();
        let validation = provider(metadata).validate(redemption.clone()).unwrap()
            .finalize(|info| Mask(derive(PROV_KEY, info)));
        let device = ecdsa::SigningKey::random(&mut thread_rng());
        let identifier = enrollment.complete(validation.clone(), enter(pin)).unwrap();
        if !validation.authorize(&identifier) { panic!() }
        let subscriber = Subscriber { device_vk: *device.verifying_key(), identifier };

        let metadata = b"some unique challenge metadata, such as a nonce and a timestamp";

        let (_, share) = provider(metadata).challenge();
        let payload = Payload("message to sign".as_bytes().to_vec());
        let pass = subscriber.pass(
            enter(pin),
            share,
            &payload,
            &mut thread_rng(),
        ).finalize(|data| {
            let (signature, _) = device.sign(data);
            signature
        });
        let evidence = provider(metadata).prove(&subscriber, context(&subscriber), &payload, pass).unwrap();
        if !subscriber.verify(&payload, &evidence) { panic!() }
    }
}
