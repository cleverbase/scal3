use hpke::generic_array::typenum;
use hpke::kdf::{extract_and_expand, HkdfSha256};
use hpke::kem::{DhP256HkdfSha256, SharedSecret};
use hpke::{Deserializable, HpkeError, Kem, Serializable};

/// Instance of [DhP256HkdfSha256] where the ECDH operation
/// is done somewhere else.
pub(crate) struct HardwareBackedDhP256HkdfSha256;

pub(crate) struct KemPrivateKey {
    pub ecdh_shared_secret: p256::ecdh::SharedSecret,
    pub pk_sender: <DhP256HkdfSha256 as Kem>::EncappedKey,
    pub pk_recipient: <DhP256HkdfSha256 as Kem>::PublicKey,
}

impl Clone for KemPrivateKey {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl PartialEq for KemPrivateKey {
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}

impl Eq for KemPrivateKey {}

impl Serializable for KemPrivateKey {
    type OutputSize = typenum::U0;

    fn write_exact(&self, _buf: &mut [u8]) {
        todo!()
    }
}

impl Deserializable for KemPrivateKey {
    fn from_bytes(_encoded: &[u8]) -> Result<Self, HpkeError> {
        todo!()
    }
}

impl Kem for HardwareBackedDhP256HkdfSha256 {
    type PublicKey = <DhP256HkdfSha256 as Kem>::PublicKey;
    type PrivateKey = KemPrivateKey;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        sk.pk_recipient.clone()
    }

    type EncappedKey = <DhP256HkdfSha256 as Kem>::EncappedKey;
    type NSecret = <DhP256HkdfSha256 as Kem>::NSecret;
    const KEM_ID: u16 = <DhP256HkdfSha256 as Kem>::KEM_ID;

    fn derive_keypair(_ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        todo!()
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        _pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if encapped_key.to_bytes() != sk_recip.pk_sender.to_bytes() {
            return Err(HpkeError::ValidationError);
        }
        let mut secret = <SharedSecret<Self> as Default>::default();
        let kem_context = [encapped_key.to_bytes(), sk_recip.pk_recipient.to_bytes()].concat();
        let suite_id = ["KEM".as_bytes(), &[0, 16]].concat();
        extract_and_expand::<HkdfSha256>(
            &sk_recip.ecdh_shared_secret.raw_secret_bytes(),
            &suite_id,
            &kem_context,
            &mut secret.0,
        )
        .expect("extract_and_expand failed");
        Ok(secret)
    }

    fn encap<R: hpke::rand_core::CryptoRng + hpke::rand_core::RngCore>(
        _pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::kem::{HardwareBackedDhP256HkdfSha256, KemPrivateKey};
    use hpke::aead::AesGcm128;
    use hpke::kdf::HkdfSha256;
    use hpke::kem::DhP256HkdfSha256;
    use hpke::rand_core::SeedableRng;
    use hpke::{Kem, OpModeR, OpModeS, Serializable};
    use p256::elliptic_curve::ecdh::SharedSecret;
    use p256::{NistP256, NonZeroScalar};
    use rand_chacha::ChaCha20Rng;

    type Aead = AesGcm128;
    type Kdf = HkdfSha256;
    type DhKem = DhP256HkdfSha256;

    fn dh(
        sk_r: &<DhP256HkdfSha256 as Kem>::PrivateKey,
        pk_s: &<DhP256HkdfSha256 as Kem>::EncappedKey,
    ) -> SharedSecret<NistP256> {
        let pk = p256::PublicKey::from_sec1_bytes(&pk_s.to_bytes()).unwrap();
        let sk: NonZeroScalar = NonZeroScalar::from_repr(sk_r.to_bytes()).unwrap();
        p256::ecdh::diffie_hellman::<NistP256>(sk, pk.as_affine())
    }

    #[test]
    fn test_kem() {
        let mut rng_hpke = ChaCha20Rng::from_seed([0; 32]);
        let (sk_r, pk_r) = DhKem::gen_keypair(&mut rng_hpke);
        let text: &mut [u8] = &mut [0; 32];
        let (pk_s, tag) = hpke::single_shot_seal_in_place_detached::<Aead, Kdf, DhKem, _>(
            &OpModeS::Base,
            &pk_r,
            &[],
            text,
            &[],
            &mut rng_hpke,
        )
        .unwrap();
        let shared_secret = dh(&sk_r, &pk_s);
        let sk = KemPrivateKey {
            ecdh_shared_secret: shared_secret,
            pk_sender: pk_s.clone(),
            pk_recipient: pk_r,
        };
        hpke::single_shot_open_in_place_detached::<Aead, Kdf, HardwareBackedDhP256HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &pk_s,
            &[],
            text,
            &[],
            &tag,
        )
        .unwrap();
    }
}
