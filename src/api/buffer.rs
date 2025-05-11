use minicbor::encode::write::EndOfSlice;
use minicbor_serde::error::{DecodeError, EncodeError};

const BUFFER_SIZE: usize = 1024;

pub struct Buffer(pub [u8; BUFFER_SIZE]);

impl Buffer {
    pub(crate) fn new() -> Self {
        Self([0u8; BUFFER_SIZE])   
    }
    
    pub(crate) fn deserialize<'de, T>(&'de self) -> Result<T, DecodeError> where T : serde::Deserialize<'de> {
        minicbor_serde::from_slice(self.0.as_slice())
    }
    
    pub(crate) fn serialize<T>(&mut self, val: T) -> Result<(), EncodeError<EndOfSlice>> where T : serde::Serialize {
        val.serialize(&mut minicbor_serde::Serializer::new(self.0.as_mut_slice()))
    }
}

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
