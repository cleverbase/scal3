//! User with a device under full control, subscribing to provider services.

use std::ptr::null_mut;
use crate::domain::{self, DATA_TO_SIGN_DOMAIN, PassDraft};
use crate::{Challenge, Device, Identifier, Mask, Pass, Payload, Redemption, Validation, Voucher};
use crate::program::subscriber;

/// Process handle for enrollment using a [Voucher].
pub struct Enrollment(pub(crate) domain::Enrollment);

/// Process handle for passing a [Challenge].
pub struct Passing(PassDraft);

/// Creates [Redemption] data for a [Voucher], starting an [Enrollment] process.
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::subscriber;
///
/// let voucher = hex!("03ecc135f1028bb5ecf3dbfc221ef18eb019e351ea5d86a3ee01891\
/// 55292a20f1502ce64b35cbdaca0ffa56808aa27eb715c776e7094b9b64847ef2a13cf5f3c91\
/// cc035e2c9dc9fa8d7ffa758d3ac1930d3bed34c4c1bc137262e3b65329064a88902bd28f670\
/// be048b3a9ad98973f551ba199371c8fbfade34943093766c26151254a");
///
/// let mut redemption = [0; 163];
/// let enrollment = subscriber::redeem(&voucher, &mut redemption);
/// ```
#[no_mangle]
#[export_name = "scal3_subscriber_redeem"]
pub extern "C" fn redeem(
    voucher: &Voucher,
    redemption: &mut Redemption,
) -> *mut Enrollment {
    subscriber::redeem(voucher).map_or(std::ptr::null_mut(), |(r, e)| {
        r.clone_into(redemption);
        Box::into_raw(Box::new(Enrollment(e)))
    })
}

/// Completes [Enrollment] by providing [Validation] and a [Mask], creating an
/// [Identifier].
///
/// Returns false if `enrollment` is null or `validation` is invalid.
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// # use hmac::digest::Output;
/// # use hmac::{Hmac, Mac};
/// # use sha2::{Sha256, Sha256VarCore};
/// use scal3::{subscriber};
/// # type HmacSha256 = Hmac<Sha256>;
/// # fn hmac(key: &[u8; 32], info: &[u8]) -> Output<Sha256VarCore> {
/// #     HmacSha256::new_from_slice(key).expect("known size")
/// #         .chain_update(info)
/// #         .finalize()
/// #         .into_bytes()
/// # }
/// # let key = hex!("997f5ef18a998189ced2abebcc74da9a534e4b4705eeef907722cb9ce\
/// # 13ef9cb");
///
/// let randomness = hex!("80265e3f0039ef23727989d30a1f4fb27047adcb0cdc1c8b0e46\
/// cc224b32af1b");
/// let voucher = hex!("02eb2d0419022ab697478a79a0df68822442f4dc3b212e2e0fcc46b\
/// 2e9abd515a0038f99465b183a4616b4881240ebc566ae42026ccbb3b22aa4b55113ecd6421e\
/// 9e03df49380b26c57e8e148fbd90529cb774e1420b911ccd915a9c856aa503af04bc466fa02\
/// cb6d19823770489f0816857e233b11547097eedfd5cdac23e5cfcce05");
///
/// let mut redemption = [0; 163];
/// let enrollment = subscriber::redeem(&voucher, &mut redemption);
///
/// let validation = hex!("74f6d3ee0c981361ddb81d4db39a2946d9515ef3ca9cf3be64dd\
/// e18b4417c6ec02ddfc55f76cc2aee73b8bfb95fc3485e4640df462467e2df74706158d45c61\
/// eb51fd97575a2e8dc484130044606ace983306eae6b0a0cdde13886d6f116bc1abf");
///
/// let pin = b"12345";
/// let mask = hmac(&key, pin).into();
///
/// let mut identifier = [0; 97];
/// assert!(subscriber::enroll(enrollment, &validation, &mask, &mut identifier));
/// ```
#[no_mangle]
#[export_name = "scal3_subscriber_enroll"]
pub extern "C" fn enroll(
    enrollment: *mut Enrollment,
    validation: &Validation,
    mask: &Mask,
    identifier: &mut Identifier,
) -> bool {
    if enrollment.is_null() { return false; }
    let enrollment = unsafe { Box::from_raw(enrollment) }.0;
    subscriber::enroll(enrollment, validation, mask).map_or(false, |i| {
        i.clone_into(identifier);
        true
    })
}

/// Data to be signed using the [Device] signing key.
///
/// Contains a domain separation tag and the first part of the joint signature.
pub type Data = [u8; DATA_TO_SIGN_DOMAIN.len() + 32];

/// Starts passing a [Challenge].
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// # use hmac::digest::Output;
/// # use hmac::{Hmac, Mac};
/// # use sha2::{Sha256, Sha256VarCore};
/// use scal3::{Payload, subscriber};
/// # type HmacSha256 = Hmac<Sha256>;
/// # fn hmac(key: &[u8; 32], info: &[u8]) -> Output<Sha256VarCore> {
/// #     HmacSha256::new_from_slice(key).expect("known size")
/// #         .chain_update(info)
/// #         .finalize()
/// #         .into_bytes()
/// # }
/// # fn main() -> Result<(), ()> {
/// # let key = hex!("997f5ef18a998189ced2abebcc74da9a534e4b4705eeef907722cb9ce\
/// # 13ef9cb");
///
/// let identifier = hex!("03226bc3f0babd46deb93945df27e82ab317136803154954a921\
/// 8c662c5761186aaf0bd07f3c00934341e836815bf12d0378ca36717648009064bb515d08d7b\
/// fe88fc1a30d2a6353ab02caa79520a4c9786f1c81f9eec7ec6e5f59b3c109b8544e");
/// let device = hex!("02c1fbeda869351e40e1d0c7b9cea64a015e288e407073d831286fc2\
/// ab0fcf3ef0");
/// let challenge = hex!("02ff11d31a1f0f874706113be3caf80ef4fb1a2eb5ba79015b44d\
/// 946e959116cbe0307289ec04e8e4d169ab19ec1fc2de384f55dde9fb306fc07219ed4e0f341\
/// fdaf");
///
/// let payload = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}"
///     .to_vec()
///     .try_into()?;
///
/// let pin = b"12345";
/// let mask = hmac(&key, pin).into();
///
/// let mut data = [0; 52];
/// let pass = subscriber::authenticate(
///     &identifier,
///     &device,
///     &challenge,
///     &mask,
///     &payload,
///     &mut data
/// );
/// assert!(!pass.is_null());
/// # Ok(())
/// # }
/// ```
///
/// # Risks
///
/// - The output `data` leaks implementation details. It could be better to
///   output a fixed-size digest for use with a pre-hashed signing function.
#[no_mangle]
#[export_name = "scal3_subscriber_authenticate"]
pub extern "C" fn authenticate(
    identifier: &Identifier,
    device: &Device,
    challenge: &Challenge,
    mask: &Mask,
    payload: &Payload,
    data: &mut Data,
) -> *mut Passing {
    subscriber::authenticate(identifier, device, challenge, mask, payload).map_or(null_mut(), |p| {
        let data_under_device_sig: Data = p.data_under_device_sig
            .clone()
            .try_into()
            .expect("known serialization");
        data_under_device_sig.clone_into(data);
        Box::into_raw(Box::new(Passing(p)))
    })
}

/// Signature over [Data] with [Device].
pub type Signature = [u8; 64];

/// Finishes [Passing] using a [Signature].
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// # use hmac::digest::Output;
/// # use hmac::{Hmac, Mac};
/// # use sha2::{Sha256, Sha256VarCore};
/// use scal3::{Payload, subscriber};
/// # type HmacSha256 = Hmac<Sha256>;
/// # fn hmac(key: &[u8; 32], info: &[u8]) -> Output<Sha256VarCore> {
/// #     HmacSha256::new_from_slice(key).expect("known size")
/// #         .chain_update(info)
/// #         .finalize()
/// #         .into_bytes()
/// # }
/// # fn main() -> Result<(), ()> {
/// # use p256::ecdsa;
/// # use rand::thread_rng;
/// use signature::Signer;
/// let key = hex!("997f5ef18a998189ced2abebcc74da9a534e4b4705eeef907722cb9ce\
/// # 13ef9cb");
/// # let device_sk = ecdsa::SigningKey::random(&mut thread_rng());
///
/// let identifier = hex!("03226bc3f0babd46deb93945df27e82ab317136803154954a921\
/// 8c662c5761186aaf0bd07f3c00934341e836815bf12d0378ca36717648009064bb515d08d7b\
/// fe88fc1a30d2a6353ab02caa79520a4c9786f1c81f9eec7ec6e5f59b3c109b8544e");
/// let challenge = hex!("02ff11d31a1f0f874706113be3caf80ef4fb1a2eb5ba79015b44d\
/// 946e959116cbe0307289ec04e8e4d169ab19ec1fc2de384f55dde9fb306fc07219ed4e0f341\
/// fdaf");
/// # let device = device_sk.verifying_key().to_encoded_point(true)
/// #     .to_bytes().to_vec().try_into().expect("known serialization");
///
/// let payload = b"{\"operation\":\"log-in\",\"session\":\"68c9eeeddfa5fb50\"}"
///     .to_vec()
///     .try_into()?;
///
/// let pin = b"12345";
/// let mask = hmac(&key, pin).into();
///
/// let mut data = [0; 52];
/// let passing = subscriber::authenticate(
///     &identifier,
///     &device,
///     &challenge,
///     &mask,
///     &payload,
///     &mut data
/// );
///
/// let (device_sig, _) = device_sk.sign(&data);
/// let device_sig: [u8; 64] = device_sig.to_bytes().into();
///
/// let mut pass = [0; 259];
/// assert!(subscriber::pass(passing, &device_sig, &mut pass));
/// # Ok(())
/// # }
/// ```
#[no_mangle]
#[export_name = "scal3_subscriber_pass"]
pub extern "C" fn pass(
    passing: *mut Passing,
    device_sig: &Signature,
    pass: &mut Pass,
) -> bool {
    if passing.is_null() { return false }
    let draft = unsafe { Box::from_raw(passing) }.0;
    subscriber::pass(draft, device_sig).map_or(false, |p| {
        p.clone_into(pass);
        true
    })
}
