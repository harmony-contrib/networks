use std::{mem::MaybeUninit, ptr::NonNull};

pub struct UninitBuffer {
    ptr: NonNull<MaybeUninit<u8>>,
    capacity: usize,
}

impl UninitBuffer {
    pub fn new(size: usize) -> Self {
        let mut vec = Vec::with_capacity(size);
        let ptr = NonNull::new(vec.as_mut_ptr() as *mut MaybeUninit<u8>).unwrap();
        let capacity = vec.capacity();
        std::mem::forget(vec);

        Self { ptr, capacity }
    }

    pub fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity) }
    }
}

impl Drop for UninitBuffer {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(self.ptr.as_ptr() as *mut u8, 0, self.capacity);
        }
    }
}
