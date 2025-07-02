use alloc::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn libc_free(ptr: *mut c_void);
}

struct SystemAllocator;

unsafe impl GlobalAlloc for SystemAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size()) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        libc_free(ptr as *mut c_void);
    }
}

#[global_allocator]
static ALLOCATOR: SystemAllocator = SystemAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        for i in 0..n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return if a < b { -1 } else { 1 };
            }
        }
        0
    }
}

#[no_mangle]
pub extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let total_size = nmemb.saturating_mul(size);
    if total_size == 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        let ptr = malloc(total_size);
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr as *mut u8, 0, total_size);
        }
        ptr
    }
}

#[no_mangle]
pub extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, dest as *mut u8, n);
    }
    dest
}

#[no_mangle]
pub extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe {
        core::ptr::copy(src as *const u8, dest as *mut u8, n);
    }
    dest
}

#[no_mangle]
pub extern "C" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe {
        core::ptr::write_bytes(s as *mut u8, c as u8, n);
    }
    s
}
