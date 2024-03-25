//! Central system provider operating under sole control of subscribers.

use crate::{api, Challenge, Device, Evidence, Mask, Pass, Payload, Randomness, Redemption, Validation, Voucher};
use crate::domain::{KEY_DERIVATION_DOMAIN, ProofError, Validating};
use crate::program::provider;

/// Key derivation information to obtain the provider [Mask].
///
/// Contains a domain separation tag and the joint verifying key.
pub type Info = [u8; KEY_DERIVATION_DOMAIN.len() + 33];

/// Process handle for validation.
pub struct Process(Validating);

/// Result of authenticating a [Pass].
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum Authentication {
    Ok,
    BadRequest,
    BadBinding,
    BadDeviceSignature,
    BadJointSignature,
}

/// Creates a [Voucher] based on [Randomness] derived from voucher metadata.
///
/// The provider shares this [Voucher] along with the metadata in an
/// integrity-protected message to the subscriber. For example, the message
/// may contain an HMAC-SHA256 authentication tag created using a
/// provider-secret key over the voucher metadata.
///
/// # Examples
///
/// Use a nonce and a timestamp to derive [Randomness], using some function
/// `hmac` that returns 32 bytes:
///
/// ```
/// # use std::time::{SystemTime, UNIX_EPOCH};
/// # use hex_literal::hex;
/// # use hmac::digest::Output;
/// # use hmac::{Hmac, Mac};
/// # use sha2::{Sha256, Sha256VarCore};
/// use scal3::provider;
///
/// # let key = hex!("90037986f5d6abbe2126814aa6b9b14b22111ff960172aa7967d6de90edeb38c");
/// # type HmacSha256 = Hmac<Sha256>;
/// # fn hmac(key: &[u8; 32], info: &[u8]) -> Output<Sha256VarCore> {
/// #     HmacSha256::new_from_slice(key).expect("known size")
/// #         .chain_update(info)
/// #         .finalize()
/// #         .into_bytes()
/// # }
/// # fn time_millis() -> u64 {
/// #     SystemTime::now()
/// #         .duration_since(UNIX_EPOCH).expect("long ago")
/// #         .as_millis() as u64
/// # }
/// let mut metadata = [0; 16];
/// metadata[..8].fill_with(rand::random);
/// metadata[8..].copy_from_slice(&time_millis().to_be_bytes());
///
/// let randomness = hmac(&key, &metadata).into();
///
/// let mut voucher = [0; 131];
/// provider::vouch(&randomness, &mut voucher);
/// ```
#[no_mangle]
#[export_name = "scal3_provider_vouch"]
pub extern "C" fn vouch(
    randomness: &Randomness,
    voucher: &mut Voucher,
) {
    provider::vouch(randomness).clone_into(voucher);
}

/// Starts validation of a [Voucher] in [Redemption].
///
/// Returns a null pointer if the [Redemption] is invalid.
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::provider;
///
/// let randomness = hex!("80265e3f0039ef23727989d30a1f4fb27047adcb0cdc1c8b0e46\
/// cc224b32af1b");
/// let voucher = hex!("02eb2d0419022ab697478a79a0df68822442f4dc3b212e2e0fcc46b\
/// 2e9abd515a0038f99465b183a4616b4881240ebc566ae42026ccbb3b22aa4b55113ecd6421e\
/// 9e03df49380b26c57e8e148fbd90529cb774e1420b911ccd915a9c856aa503af04bc466fa02\
/// cb6d19823770489f0816857e233b11547097eedfd5cdac23e5cfcce05");
/// let redemption = hex!("025b8310f21847408edd1faa2f60f10fd431b65ee3e828e9e21f\
/// 75f63f66386e9f02a23c999605480bfc2a0423824b9bf9e8b7b52c0ee09912556f048166997\
/// 4b1e5031d9be24c2a9099d7bd64ddf07a31c22395e988ebfbf06fe196add200b2de142ba9fa\
/// ce11998701d8ff2b67632c4aef325d1e9ca637c9798bd91122f9b9aeb77ce99e2004b8a3ffa\
/// ffeb6d1179d28beffc2559acca702de0ec8198c160b7fc1c2");
///
/// let mut info = [0; 53];
/// let process = provider::process(&randomness, &redemption, &mut info);
/// assert!(!process.is_null())
/// ```
///
/// # Risks
///
/// - The output `info` leaks implementation details. It could be better to
///   output a fixed-size digest for use with a pre-hashed signing function.
#[no_mangle]
#[export_name = "scal3_provider_process"]
pub extern "C" fn process(
    randomness: &Randomness,
    redemption: &Redemption,
    info: &mut Info,
) -> *mut Process {
    provider::process(randomness, redemption).map_or(std::ptr::null_mut(), |draft| {
        draft.key_derivation_info().clone_into(&mut info.into());
        Box::into_raw(Box::new(Process(draft)))
    })
}

/// Completes a [Process] using a [Mask] derived from [Info].
///
/// # Examples
///
/// ```
/// # use hex_literal::hex;
/// # use hmac::digest::Output;
/// # use hmac::{Hmac, Mac};
/// # use sha2::{Sha256, Sha256VarCore};
/// use scal3::provider;
/// # type HmacSha256 = Hmac<Sha256>;
/// # fn hmac(key: &[u8; 32], info: &[u8]) -> Output<Sha256VarCore> {
/// #     HmacSha256::new_from_slice(key).expect("known size")
/// #         .chain_update(info)
/// #         .finalize()
/// #         .into_bytes()
/// # }
/// # let key = hex!("90037986f5d6abbe2126814aa6b9b14b22111ff960172aa7967d6de90edeb38c");
///
/// let randomness = hex!("80265e3f0039ef23727989d30a1f4fb27047adcb0cdc1c8b0e46\
/// cc224b32af1b");
/// let voucher = hex!("02eb2d0419022ab697478a79a0df68822442f4dc3b212e2e0fcc46b\
/// 2e9abd515a0038f99465b183a4616b4881240ebc566ae42026ccbb3b22aa4b55113ecd6421e\
/// 9e03df49380b26c57e8e148fbd90529cb774e1420b911ccd915a9c856aa503af04bc466fa02\
/// cb6d19823770489f0816857e233b11547097eedfd5cdac23e5cfcce05");
/// let redemption = hex!("025b8310f21847408edd1faa2f60f10fd431b65ee3e828e9e21f\
/// 75f63f66386e9f02a23c999605480bfc2a0423824b9bf9e8b7b52c0ee09912556f048166997\
/// 4b1e5031d9be24c2a9099d7bd64ddf07a31c22395e988ebfbf06fe196add200b2de142ba9fa\
/// ce11998701d8ff2b67632c4aef325d1e9ca637c9798bd91122f9b9aeb77ce99e2004b8a3ffa\
/// ffeb6d1179d28beffc2559acca702de0ec8198c160b7fc1c2");
///
/// let mut info = [0; 53];
/// let process = provider::process(&randomness, &redemption, &mut info);
///
/// let mask = hmac(&key, &info).into();
///
/// let mut validation = [0; 97];
/// assert!(provider::validate(process, &mask, &mut validation));
/// ```
#[no_mangle]
#[export_name = "scal3_provider_validate"]
pub extern "C" fn validate(
    draft: *mut Process,
    mask: &Mask,
    validation: &mut api::Validation,
) -> bool {
    if draft.is_null() { return false }
    let draft = unsafe { Box::from_raw(draft) };
    provider::validate(draft.0, mask).clone_into(validation);
    true
}

/// After [Validation], checks authorization for an [api::Identifier].
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::provider;
///
/// let validation = hex!("74f6d3ee0c981361ddb81d4db39a2946d9515ef3ca9cf3be64dd\
/// e18b4417c6ec02bb2890eea9a8d1123c07d67ae358bd59659710d750565b9131f32e6af6517\
/// 7166219b62bee024abdd74c6f94a7bb909fccef89863c8f6d2c239a0151493f064f");
/// let identifier = hex!("02bb2890eea9a8d1123c07d67ae358bd59659710d750565b9131\
/// f32e6af65177166219b62bee024abdd74c6f94a7bb909fccef89863c8f6d2c239a0151493f0\
/// 64fd949263127ed3828c9457e5c3118b2131da53ec1ec2c8222a0399e096b316763");
///
/// assert!(provider::authorize(&validation, &identifier));
/// ```
#[no_mangle]
#[export_name = "scal3_provider_authorize"]
pub extern "C" fn authorize(
    validation: &Validation,
    identifier: &api::Identifier,
) -> bool {
    provider::authorize(validation, identifier).is_ok()
}

/// Creates a [Challenge] based on [Randomness] derived from challenge metadata.
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::provider;
///
/// let randomness = hex!("80265e3f0039ef23727989d30a1f4fb27047adcb0cdc1c8b0e46\
/// cc224b32af1b");
///
/// let mut challenge = [0; 66];
/// provider::challenge(&randomness, &mut challenge);
/// ```
#[no_mangle]
#[export_name = "scal3_provider_challenge"]
pub extern "C" fn challenge(
    randomness: &Randomness,
    challenge: &mut Challenge,
) {
    provider::challenge(randomness).clone_into(challenge)
}

/// Finishes [Authentication] by creating [Evidence] that [Pass] is correct.
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::{Payload, provider};
///
/// # fn main() -> Result<(), ()> {
/// let randomness = hex!("d277220c22a71ab93cc413370ce4fe7d37d7f472f0ad8b065beb\
/// aa713c1df012");
/// let identifier = hex!("03e745506f157c1b2613545c82e77852602a11ba3552feceaabf\
/// 1a4a2a88e7dd0e2ffcb3690c8200f598fa0173e56fb63bf8cfac4723d5dc6cf17c340260d39\
/// f4f6587d0237573e7d3b289265a416c5402abad39d857f0dbf18f2ba75f85a51c9d");
/// let device = hex!("021749278d707befe54ffa476ad42d6a53ad5bec62b80e665fe52835\
/// f6be33ef49");
/// let mask = hex!("b6a4459e97c77a487ed8b4267be060f71d3b2a18632ac3cfe384e7b495\
/// 48d632");
/// let pass = hex!("031de5d7c377beb388d059555b875c7b2d16480db0e8495817f2b88a65\
/// 823369a303cbf09a3b62c356cbc32679b3cdc32ca7a513e3534e6c0fdfcb47a5a8ba17b1310\
/// 3ec4db8f9c8204291c3cfb577449f031cc5bbcc64c4426274edddfb69383631ca955b0bd755\
/// 99f9d8c390633b02a22b7bf9ac13f1f69404b55752a67d6442f7c3f1ad4bf355fdc42ab6fb0\
/// e90c59a76b76de2376b7508bff4c1395694d5e8364a2606023b20b91d66f6d9540d7d38f42d\
/// 9b61ee743d05e9a49ee3a236bac47b770a302265cb93441d0a14a6825cf1500718dc7e74f93\
/// 02bf6a6b1e89d928ad64d329a5060854a51b06d0a0ccaa66006cae146366afe779aba3a5f48\
/// 4c858f84f5");
///
/// let payload = hex!("7b226f7065726174696f6e223a226c6f672d696e222c22736573736\
/// 96f6e223a2236386339656565646466613566623530227d");
/// let payload = Payload::try_from(payload.to_vec())?;
///
/// let mut evidence = [0; 225];
/// let authentication = provider::prove(
///     &randomness,
///     &identifier,
///     &device,
///     &mask,
///     &payload,
///     &pass,
///     &mut evidence,
/// );
/// assert_eq!(authentication, provider::Authentication::Ok);
/// # Ok(())
/// # }
/// ```
///
/// # Risks
///
/// - A person in the middle could change the subscriber’s signature share
///   before forwarding to the provider, potentially exhausting an attempt
///   rate limiting counter, and thereby causing a denial of service. This
///   could be mitigated by additionally verifying a checksum of input data
///   under the device signature.
#[export_name = "scal3_provider_prove"]
pub extern "C" fn prove(
    randomness: &Randomness,
    identifier: &api::Identifier,
    device: &Device,
    mask: &Mask,
    payload: &Payload,
    pass: &Pass,
    evidence: &mut Evidence,
) -> Authentication {
    match provider::prove(
        randomness,
        identifier,
        device,
        mask,
        payload,
        pass
    ) {
        Ok(e) => {
            evidence.copy_from_slice(&e);
            Authentication::Ok
        }
        Err(provider::ProofError::SyntaxError) => Authentication::BadRequest,
        Err(provider::ProofError::ContentError(ProofError::BadBinding)) =>
            Authentication::BadBinding,
        Err(provider::ProofError::ContentError(ProofError::BadDeviceSignature)) =>
            Authentication::BadDeviceSignature,
        Err(provider::ProofError::ContentError(ProofError::BadJointSignature)) =>
            Authentication::BadJointSignature,
    }
}
