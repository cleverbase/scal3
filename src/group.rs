use frost_core::{Field, Group};
use frost_core::frost::BindingFactor;
use frost_p256 as frost;
use frost_p256::{P256Group, P256ScalarField, P256Sha256};
use frost_p256::round1::NonceCommitment;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::PrimeField;
use p256::{ecdsa, FieldBytes};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Debug)]
pub(crate) struct Element(pub(crate) frost_core::Element<P256Sha256>);

impl Element {
    pub(crate) fn deserialize(bytes: &[u8; 33]) -> Option<Element> {
        P256Group::deserialize(bytes).ok().map(|result| Element(result))
    }
}

impl From<p256::ProjectivePoint> for Element {
    fn from(value: p256::ProjectivePoint) -> Self {
        Element(value)
    }
}

impl Into<ecdsa::VerifyingKey> for Element {
    fn into(self) -> VerifyingKey {
        VerifyingKey::from_affine(self.0.to_affine()).expect("known serialization")
    }
}

impl From<ecdsa::VerifyingKey> for Element {
    fn from(value: VerifyingKey) -> Self {
        Element(value.as_affine().into())
    }
}

impl From<frost::round1::NonceCommitment> for Element {
    fn from(value: NonceCommitment) -> Self {
        Self::deserialize(&value.serialize()).expect("known serialization")
    }
}

impl Serialize for Element {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), serializer)
            .map_err(|_| serde::ser::Error::custom("could not serialize element"))
    }
}

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let mut bytes = [0; 33];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        let result = P256Group::deserialize(&bytes)
            .map_err(|_| serde::de::Error::custom("invalid element"))?;
        Ok(Element(result))
    }
}

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub(crate) struct Scalar(pub(crate) p256::Scalar);

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), serializer)
            .map_err(|_| serde::ser::Error::custom("could not serialize scalar"))
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let mut bytes = [0; 32];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        let result = P256ScalarField::deserialize(&bytes)
            .map_err(|_| serde::de::Error::custom("invalid scalar"))?;
        Ok(Scalar(result))
    }
}

impl From<&BindingFactor<P256Sha256>> for Scalar {
    fn from(value: &BindingFactor<P256Sha256>) -> Self {
        let mut factor_data = [0u8; 32];
        value.serialize().clone_into(&mut factor_data);
        let value = p256::Scalar::from_repr(FieldBytes::from(factor_data))
            .expect("cannot fail given ciphersuite");
        Self(value)
    }
}

impl From<p256::Scalar> for Scalar {
    fn from(value: p256::Scalar) -> Self {
        Scalar(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof(pub(crate) Element, pub(crate) Scalar);

impl From<frost::Signature> for Proof {
    fn from(value: frost::Signature) -> Self {
        let serialization: [u8; 65] = value.serialize().try_into()
            .expect("known signature size serialization");
        let commitment_bytes = serialization[0..33].try_into()
            .expect("known element size serialization");
        let proof_bytes = serialization[33..65].try_into()
            .expect("known scalar size serialization");
        let commitment = Element::deserialize(commitment_bytes)
            .expect("known element format");
        let proof = P256ScalarField::deserialize(proof_bytes)
            .expect("known scalar format");
        Proof(commitment, Scalar(proof))
    }
}

impl From<Proof> for frost::Signature {
    fn from(value: Proof) -> Self {
        frost::Signature::new(value.0.0, value.1.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Signature {
    r: Scalar,
    s: Scalar,
}

impl Signature {
    pub(crate) fn to_bytes(self) -> [u8; 64] {
        let signature: ecdsa::Signature = self.into();
        signature.to_bytes().try_into().expect("known size")
    }
}

impl Into<ecdsa::Signature> for Signature {
    fn into(self) -> ecdsa::Signature {
        let binding = postcard::to_allocvec(&self)
            .expect("serialization should not fail");
        let bytes = binding.as_slice();
        ecdsa::Signature::from_bytes(bytes.into()).expect("deserialization should not fail")
    }
}

impl From<ecdsa::Signature> for Signature {
    fn from(value: ecdsa::Signature) -> Self {
        let binding = value.to_bytes();
        let (r, s) = binding.as_slice().split_at(32);
        let r: [u8; 32] = r.try_into().expect("known size");
        let s: [u8; 32] = s.try_into().expect("known size");
        let r = Scalar(P256ScalarField::deserialize(&r).expect("known serialization"));
        let s = Scalar(P256ScalarField::deserialize(&s).expect("known serialization"));
        Self { r, s }
    }
}

impl TryFrom<&[u8; 64]> for Signature {
    type Error = ();

    fn try_from(value: &[u8; 64]) -> Result<Self, Self::Error> {
        let r: [u8; 32] = value[0..32].try_into().expect("fixed size");
        let s: [u8; 32] = value[32..64].try_into().expect("fixed size");
        let r = P256ScalarField::deserialize(&r).or(Err(()))?;
        let s = P256ScalarField::deserialize(&s).or(Err(()))?;
        Ok(Self { r: r.into(), s: s.into() })
    }
}
