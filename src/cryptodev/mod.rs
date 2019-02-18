use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Cursor;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::*;
use std::ptr;

use mio;
use mio::unix::EventedFd;
use tokio::io::AsyncRead;
use tokio::prelude::*;
use tokio::reactor::PollEvented2;

use crate::algorithms::Cipher;
use crate::AlignedBuf;
use crate::CryptoApiError;
use crate::NewSession;

mod sys;

fn cipher_to_op(cipher: &Cipher) -> (sys::cryptodev_crypto_op_t, u16) {
    match *cipher {
        Cipher::AesCtr(key_size) => (sys::cryptodev_crypto_op_t::CRYPTO_AES_CTR, key_size as u16),
    }
}

fn start_session(op: sys::cryptodev_crypto_op_t, key: &[u8]) -> Result<(File, u32, sys::session_info_op), CryptoApiError> {
    let crypto = OpenOptions::new().write(true).read(true).open("/dev/crypto").map_err(CryptoApiError::CryptoDevOpen)?;
    let mut siop: sys::session_info_op = unsafe { mem::zeroed() };

    let mut sop = sys::session_op {
        cipher: op as u32,
        mac: 0,
        keylen: key.len() as u32,
        key: key.as_ptr(),
        mackeylen: 0,
        mackey: ptr::null_mut(),
        ses: 0,
    };
    unsafe { sys::CIOCGSESSION(crypto.as_raw_fd(), &mut sop) }.map_err(CryptoApiError::CryptoDevCreateSession)?;
    siop.ses = sop.ses;
    unsafe { sys::CIOCGSESSINFO(crypto.as_raw_fd(), &mut siop) }.map_err(CryptoApiError::CryptoDevFetchSession)?;
    Ok((crypto, sop.ses, siop))
}

pub struct SyncCryptoDev {}

//pub struct AsyncCryptoDev {}

impl SyncCryptoDev {
    pub fn new() -> Result<SyncCryptoDev, CryptoApiError> {
        Ok(SyncCryptoDev {})
    }
}

//impl AsyncCryptoDev {
//    pub fn new() -> Result<AsyncCryptoDev, CryptoApiError> {
//        Ok(AsyncCryptoDev {})
//    }
//}

pub struct CryptoDevSyncCipherSession {
    file: File,
    session: u32,
    cipher: Cipher,
    driver_name: String,
    is_accelerated: bool,
    alignment_mask: u16,
}

impl fmt::Debug for CryptoDevSyncCipherSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("CryptoDevSyncCipherSession")
            .field("session", &self.session)
            .field("cipher", &self.cipher)
            .field("driver", &self.driver_name)
            .field("is_accelerated", &self.is_accelerated)
            .field("alignment_mask", &self.alignment_mask)
            .finish()
    }
}

struct EventedFile {
    inner: File,
}

impl Write for EventedFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.inner.flush()
    }
}

impl Read for EventedFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.inner.read(buf)
    }
}

impl AsRawFd for EventedFile {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl mio::Evented for EventedFile {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}
//
//pub struct CryptoDevAsyncCipherSession {
//    evented: PollEvented2<EventedFile>,
//    session: u32,
//    cipher: Cipher,
//    driver_name: String,
//    is_accelerated: bool,
//    alignment_mask: u16,
//}
//
//impl fmt::Debug for CryptoDevAsyncCipherSession {
//    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//        fmt.debug_struct("CryptoDevAsyncCipherSession")
//            .field("session", &self.session)
//            .field("cipher", &self.cipher)
//            .field("driver", &self.driver_name)
//            .field("is_accelerated", &self.is_accelerated)
//            .field("alignment_mask", &self.alignment_mask)
//            .finish()
//    }
//}

impl SyncCryptoDev {}

impl NewSession for SyncCryptoDev {
    type Session = CryptoDevSyncCipherSession;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<CryptoDevSyncCipherSession, CryptoApiError> {
        let (op, key_len) = cipher_to_op(cipher);
        assert_eq!(key.len(), key_len as usize);

        let (file, session, siop) = start_session(op, key)?;

        let driver_name = unsafe { CStr::from_ptr(siop.cipher_info.cra_driver_name.as_ptr() as *const _) }.to_string_lossy().into_owned();
        Ok(CryptoDevSyncCipherSession {
            session,
            file,
            driver_name,
            cipher: *cipher,
            is_accelerated: !siop.flags.contains(sys::SiopFlags::KERNEL_DRIVER_ONLY),
            alignment_mask: siop.alignmask,
        })
    }
}

//impl AsyncCryptoDev {}
//
//impl NewSession for AsyncCryptoDev {
//    type Session = CryptoDevAsyncCipherSession;
//
//    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<CryptoDevAsyncCipherSession, CryptoApiError> {
//        let (op, key_len) = cipher_to_op(cipher);
//        assert_eq!(key.len(), key_len as usize);
//
//        let (file, session, siop) = start_session(op, key)?;
//
//        let driver_name = unsafe { CStr::from_ptr(siop.cipher_info.cra_driver_name.as_ptr() as *const _) }.to_string_lossy().into_owned();
//        Ok(CryptoDevAsyncCipherSession {
//            session,
//            evented: PollEvented2::new(EventedFile { inner: file }),
//            driver_name,
//            cipher: *cipher,
//            is_accelerated: !siop.flags.contains(sys::SiopFlags::KERNEL_DRIVER_ONLY),
//            alignment_mask: siop.alignmask,
//        })
//    }
//}

enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    fn op(&self) -> u16 {
        match *self {
            Operation::Encrypt => sys::COP_ENCRYPT,
            Operation::Decrypt => sys::COP_DECRYPT,
        }
    }
}

impl CryptoDevSyncCipherSession {
    fn perform<'a>(&self, op: Operation, iv: &[u8], payload: &[u8]) -> Result<AlignedBuf<'a>, CryptoApiError> {
        assert_eq!(iv.len(), self.cipher.iv_len());
        assert_eq!(payload.len() % self.cipher.block_len(), 0);

        let mut data = AlignedBuf::new(payload.len(), self.alignment_mask);
        data.as_mut().copy_from_slice(&payload);
        let mut buf = AlignedBuf::new(payload.len(), self.alignment_mask);

        let mut op = sys::crypt_op {
            ses: self.session,
            op: op.op(),
            flags: 0,
            len: payload.len() as u32,
            src: data.as_ptr(),
            dst: buf.as_mut_ptr(),
            mac: ptr::null_mut(),
            iv: iv.as_ptr(),
        };
        unsafe { sys::CIOCCRYPT(self.file.as_raw_fd(), &mut op) }.map_err(CryptoApiError::CryptoDevOperation)?;

        Ok(buf)
    }

    pub fn encrypt_future<'a>(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, AlignedBuf<'a>), Error = CryptoApiError> {
        self.perform(Operation::Encrypt, iv, payload).into_future().map(|res| (self, res))
    }

    pub fn decrypt_future<'a>(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, AlignedBuf<'a>), Error = CryptoApiError> {
        self.perform(Operation::Decrypt, iv, payload).into_future().map(|res| (self, res))
    }

    pub fn encrypt<'a>(&self, iv: &[u8], payload: &[u8]) -> Result<AlignedBuf<'a>, CryptoApiError> {
        self.perform(Operation::Encrypt, iv, payload)
    }

    pub fn decrypt<'a>(&self, iv: &[u8], payload: &[u8]) -> Result<AlignedBuf<'a>, CryptoApiError> {
        self.perform(Operation::Decrypt, iv, payload)
    }
}

//struct Perform<'a> {
//    inner: Option<CryptoDevAsyncCipherSession>,
//    buf: Option<AlignedBuf<'a>>,
//}
//
//impl<'a> Future for Perform<'a> {
//    type Item = (CryptoDevAsyncCipherSession, AlignedBuf<'a>);
//    type Error = CryptoApiError;
//
//    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
//        if let (Some(ref mut buf), Some(ref mut session)) = (self.buf.as_mut(), self.inner.as_mut()) {
//            let mut c = Cursor::new(buf);
//            let res = session.evented.read_buf(&mut c);
//            println!("res = {:?}", res);
//            match res {
//                Ok(Async::Ready(n)) => {
//                    //                if n != self.buf.as_ref().len() {
//                    //                    panic!("Size missmatch!")
//                    //                }
//                }
//                Ok(Async::NotReady) => return Ok(Async::NotReady),
//                Err(e) => unimplemented!(),
//            }
//        } else {
//            unreachable!()
//        }
//        Ok(Async::Ready((self.inner.take().unwrap(), self.buf.take().unwrap())))
//    }
//}

//impl CryptoDevAsyncCipherSession {
//    fn perform<'a>(mut self, op: Operation, iv: &[u8], payload: &[u8]) -> impl Future<Item = (CryptoDevAsyncCipherSession, AlignedBuf<'a>), Error = CryptoApiError> {
//        assert_eq!(iv.len(), self.cipher.iv_len());
//        assert_eq!(payload.len() % self.cipher.block_len(), 0);
//
//        let mut data = AlignedBuf::new(payload.len(), self.alignment_mask);
//        data.as_mut().copy_from_slice(&payload);
//        let mut buf = AlignedBuf::new(payload.len(), self.alignment_mask);
//
//        let mut op = sys::crypt_op {
//            ses: self.session,
//            op: op.op(),
//            flags: 0,
//            len: payload.len() as u32,
//            src: data.as_ptr(),
//            dst: buf.as_mut_ptr(),
//            mac: ptr::null_mut(),
//            iv: iv.as_ptr(),
//        };
//        unsafe { sys::CIOCASYNCCRYPT(self.evented.get_ref().as_raw_fd(), &mut op) };
//        //        .map_err(CryptoApiError::CryptoDevAsyncCryptOperation)? };
//        unsafe { sys::CIOCASYNCFETCH(self.evented.get_ref().as_raw_fd(), &mut op) };
//        //        .map_err(CryptoApiError::CryptoDevAsyncFetchOperation)? };
//
//        Perform { inner: Some(self), buf: Some(buf) }.fuse()
//    }
//
//    pub fn encrypt_future<'a>(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, AlignedBuf<'a>), Error = CryptoApiError> {
//        self.perform(Operation::Encrypt, iv, payload)
//    }
//
//    pub fn decrypt_future<'a>(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, AlignedBuf<'a>), Error = CryptoApiError> {
//        self.perform(Operation::Decrypt, iv, payload)
//    }
//}
