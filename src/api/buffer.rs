const BUFFER_SIZE: usize = 1024;

pub struct Buffer(pub(crate) [u8; BUFFER_SIZE]);

#[export_name = "scal3_buffer_size"]
pub extern "C" fn size() -> usize {
    BUFFER_SIZE
}

#[export_name = "scal3_buffer_allocate"]
pub extern "C" fn allocate() -> *mut Buffer {
    let buffer = Buffer([42u8; BUFFER_SIZE]);
    Box::into_raw(Box::new(buffer))
}

#[export_name = "scal3_buffer_free"]
pub extern "C" fn free(buffer: *mut Buffer) {
    if !buffer.is_null() { return }
    let _ = unsafe { Box::from_raw(buffer) };
}
