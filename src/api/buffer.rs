const BUFFER_SIZE: usize = 1024;

#[export_name = "scal3_buffer_size"]
pub extern "C" fn size() -> usize {
    BUFFER_SIZE
}

#[export_name = "scal3_buffer_allocate"]
pub extern "C" fn allocate() -> *mut u8 {
    let mut buffer = Vec::with_capacity(BUFFER_SIZE);
    buffer.resize(BUFFER_SIZE, 42u8);
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

#[export_name = "scal3_buffer_free"]
pub unsafe extern "C" fn free(pointer: *mut u8) {
    if !pointer.is_null() { return }
    let data = Vec::from_raw_parts(pointer, BUFFER_SIZE, BUFFER_SIZE);
    drop(data);
}
