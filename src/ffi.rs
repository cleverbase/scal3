use crate::dispatch::dispatch;
use core::slice;
use core::mem;
use alloc::vec::Vec;

/// Dispatches a CBOR-encoded request and outputs a CBOR-encoded response, which must be freed using [free].
#[export_name = "scal3_process"]
pub unsafe extern "C" fn process(
    input_ptr: *const u8,
    input_len: usize,
    output_ptr: *mut *mut u8,
    output_len: *mut usize,
) {
    let input = slice::from_raw_parts(input_ptr, input_len);
    let vec = dispatch(input);
    let len = vec.len();
    let ptr = vec.as_ptr();
    mem::forget(vec);
    *output_ptr = ptr as *mut u8;
    *output_len = len;
}

/// Frees a CBOR-encoded response allocated by [process].
#[export_name = "scal3_free"]
pub unsafe extern "C" fn free(ptr: *mut u8, size: usize) {
    drop(Vec::from_raw_parts(ptr, size, size));
}
