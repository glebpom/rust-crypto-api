use std::fmt;
use std::mem;
use std::slice;

pub struct AlignedBuf<'a> {
    buf: Vec<u8>,
    alignment_mask: u16,
    len: usize,
    aligned_slice: &'a mut [u8],
}

const MAX_ALIGNMENT_DIFF: usize = 63;

impl<'a> AlignedBuf<'a> {
    pub fn new(len: usize, alignment_mask: u16) -> AlignedBuf<'a> {
        assert!(alignment_mask as usize <= MAX_ALIGNMENT_DIFF);
        let mut buf = vec![0u8; len + MAX_ALIGNMENT_DIFF];
        //        let mut buf = Vec::with_capacity(len + MAX_ALIGNMENT_DIFF);
        AlignedBuf {
            aligned_slice: unsafe { slice::from_raw_parts_mut(AlignedBuf::aligned_ptr(&mut buf, alignment_mask), len) },
            buf,
            alignment_mask,
            len,
        }
    }

    fn aligned_ptr(buf: &mut Vec<u8>, alignment_mask: u16) -> *mut u8 {
        let ptr = (*buf).as_mut_ptr();
        if alignment_mask == 0 {
            ptr
        } else {
            let ptr: usize = unsafe { mem::transmute(ptr) };
            let alignment_mask: usize = alignment_mask.into();
            let aligned_ptr = (ptr + alignment_mask) & !alignment_mask;
            unsafe { mem::transmute(aligned_ptr) }
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.aligned_slice.as_mut_ptr()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.aligned_slice.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a> AsRef<[u8]> for AlignedBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        self.aligned_slice
    }
}

impl<'a> AsMut<[u8]> for AlignedBuf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.aligned_slice
    }
}

impl<'a> fmt::Debug for AlignedBuf<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        self.aligned_slice.fmt(f)
    }
}

mod tests {
    use super::*;

    #[test]
    pub fn test_simple() {
        let buf = AlignedBuf::new(16, 0);
        assert_eq!(buf.len(), 16);
    }

    #[test]
    pub fn test_alignment() {
        for mask in &[0, 1, 3, 7, 15, 31, 63] {
            let buf = AlignedBuf::new(16, *mask);
            let ptr = unsafe { mem::transmute::<_, usize>(buf.as_ptr()) };
            assert_eq!(ptr % (*mask as usize + 1), 0);
        }
    }

    #[test]
    pub fn test_data() {
        let mut buf = AlignedBuf::new(16, 0);
        buf.as_mut()[0] = 1;
        buf.as_mut()[1] = 2;
        buf.as_mut()[5] = 3;
        assert_eq!(buf.as_ref(), [1, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
