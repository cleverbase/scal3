pub mod provider;
pub mod subscriber;

use std::ptr::null_mut;
use std::slice;
use libc::size_t;
use serde::{Serialize, Serializer};
use crate::program;

/// Enrolled authenticator data for the subscriber.
///
/// Contains a joint verifying key, and two signing shares. Each signing share
/// is masked by adding a scalar derived from the corresponding mask.
pub type Identifier = [u8; 97];

/// Authenticator device verifying key.
///
/// Contains a compressed P-256 point.
pub type Device = [u8; 33];

/// Evidence that some subscriber passed some payload.
///
/// Contains a P-256 binding verifying key, a joint signature, an ECDSA P-256
/// device signature, and an ECDSA P-256 binding signature.
pub type Evidence = [u8; 225];

/// Secret entropy derived from execution context data using a hardware-backed key.
pub type Randomness = [u8; 32];

/// Secret entropy derived from application-provided data using a hardware-backed key.
///
/// Gets added to the corresponding signing share in the [Identifier].
pub type Mask = [u8; 32];

/// Entitlement to enroll.
///
/// Contains provider commitments ([<i>a</i><sub>10</sub>]<i>G</i>,
/// [<i>a</i><sub>11</sub>]<i>G</i>) and a Schnorr zero-knowledge proof of
/// knowledge of <i>a</i><sub>10</sub>.
pub type Voucher = [u8; 131];

/// Attempt to redeem a [Voucher] to enroll.
///
/// Contains subscriber commitments () `([a20]G, [a21]G)`, a proof of knowledge
/// of `a20`, and a secret share `a20 + a21 * 1` for the provider.
pub type Redemption = [u8; 163];

/// Validation of a [Voucher] with [Redemption].
///
/// Contains a secret share `a10 + a11 * 2` for the [subscriber], a joint
/// verifying key, and a masked provider signing share.
pub type Validation = [u8; 97];

/// Authentication challenge data.
///
/// Contains [provider] commitments ([<i>d</i><sub>1</sub>]<i>G</i>, [<i>e</i><sub>1</sub>]<i>G</i>).
pub type Challenge = [u8; 66];

/// Response to a [Challenge].
///
/// Contains a binding verifying key, [subscriber] commitments ([<i>d</i><sub>2</sub>]<i>G</i>, [<i>e</i><sub>2</sub>]<i>G</i>),
/// [subscriber] signature share <i>z</i><sub>2</sub>], a device signature, and a binding
/// signature.
pub type Pass = [u8; 259];

/// Log metadata and instructions.
#[derive(Clone, Debug)]
pub struct Payload(pub(crate) Vec<u8>);

impl TryFrom<Vec<u8>> for Payload {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, ()> {
        if value.len() < MAXIMUM_PAYLOAD_SIZE { Ok(Payload(value)) } else { Err(()) }
    }
}

impl Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serdect::array::serialize_hex_lower_or_bin(&self.0, serializer)
            .map_err(|_| serde::ser::Error::custom("could not serialize element"))
    }
}

/// The maximum size of a payload.
pub const MAXIMUM_PAYLOAD_SIZE: usize = 1024;

/// Verifies [Evidence] that the identified [subscriber] passed the [Payload].
///
/// # Examples
///
/// ```
/// use hex_literal::hex;
/// use scal3::{pay, release, verify};
///
/// let identifier = hex!("03790293a35b3e293619f84628dd2d1b9d508a57a28f3aaea7fb\
/// 39ede6dc45e61dd329cc44569bc3b7cbe05947d79e92c1e14f2d61391994db6cc895d255ce4\
/// 4470881ce68a102d13905e67e086a2c88b7d20da3fe595211e4800d19af5e5e5802");
/// let device = hex!("02650501ae4d0eb95c8128b47f6348fb7a071e42cc4f8d5afdcda01f\
/// 83149f29ba");
/// let payload = hex!("7b226f7065726174696f6e223a226c6f672d696e222c22736573736\
/// 96f6e223a2236386339656565646466613566623530227d");
/// let evidence = hex!("03fe24affb03808ece87bf8b3d59f30a55b56c616c11546243b4c6\
/// 37e9a0b4e5f725c52ca44f91eabee9d42a2679e456bcf9203e651ca120ccdce692d03d742ed\
/// bf5e7d24cf6074f08c6466196fe39752068d8021b6e5f617cbb070eaaefe93f269c9c4d335e\
/// b1fd9026cf9ac937803a32d0062bf5499ca81e70450498fd2c8171cd9cf28714590093d6178\
/// e4d1762b83173605f27dd54c9002f9d8e880ace3f63e4867a639f8aa7f8cdf4b7ff20ad092b\
/// f01d01e3a53866e1913cd5ae8f12c1f112b21aebd97761f6548d6f9c9d48408fe27e1a931b3\
/// d97e902b6320b9c6dcb59");
///
/// let payload_handle = unsafe { pay(payload.as_ptr(), payload.len()) };
/// assert!(verify(
///     &identifier,
///     &device,
///     payload_handle,
///     &evidence,
/// ));
/// unsafe { release(payload_handle) };
/// ```
#[no_mangle]
#[export_name = "scal3_verify"]
pub extern "C" fn verify(
    identifier: &Identifier,
    device: &Device,
    payload: *mut Payload,
    evidence: &Evidence,
) -> bool {
    if payload.is_null() { return false }
    let payload_box = unsafe { Box::from_raw(payload) };
    let result = program::verify(identifier, device, &payload_box, evidence);
    unsafe { Box::into_raw(payload_box) };
    result.is_some()
}

/// Constructs a [Payload] from a pointer and a size in bytes.
#[no_mangle]
#[export_name = "scal3_pay"]
pub unsafe extern "C" fn pay(
    value: *const u8,
    size: size_t
) -> *mut Payload {
    if value.is_null() { panic!("null input") }
    let value = slice::from_raw_parts(value, size);
    match Payload::try_from(value.to_vec()) {
        Ok(payload) => Box::into_raw(Box::new(payload)),
        Err(_) => null_mut(),
    }
}

/// Releases a [Payload] from memory.
///
/// # Risk
///
/// - It is easy for users to forget releasing allocated memory. Possibly this
///   does not require a separate function anyway, since the functions consuming
///   a payload would release it anyway.
#[no_mangle]
#[export_name = "scal3_release"]
pub unsafe extern "C" fn release(
    payload: *mut Payload,
) {
    if payload.is_null() { return }
    let _ = Box::from_raw(payload);
}
