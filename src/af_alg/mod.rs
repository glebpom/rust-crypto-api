use std::cell::RefCell;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::iter;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::prelude::*;
use std::ptr;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use bytes::BytesMut;
use futures::future::IntoFuture;
use futures::lazy;
use futures::stream;
use futures::{Future, Stream};
use nix::fcntl;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::{sendmsg, ControlMessage};
use nix::sys::uio::IoVec;
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::prelude::FutureExt;
use tokio::prelude::*;
use tokio::runtime::current_thread::Runtime;

use crate::algorithms::Cipher;
use crate::CryptoApiError;
use crate::NewSession;

unsafe fn setsockopt(socket: &Socket, opt: libc::c_int, val: libc::c_int, payload: &[u8]) -> io::Result<()> {
    let len = payload.len();
    let payload = payload.as_ptr() as *const _ as *const libc::c_void;
    if libc::setsockopt(socket.as_raw_fd(), opt, val, payload, len as libc::socklen_t) != 0 {
        return Err(io::Error::last_os_error());
    };
    Ok(())
}
//
//pub struct Session {
//    socket: Socket,
//    session_socket: Socket,
//    context: tokio_linux_aio::AioContext,
//}
//
//impl Session {
//    pub fn new(private_key: &[u8], context: &tokio_linux_aio::AioContext) -> io::Result<Session> {
//        let salg_type = "blkcipher";
//        let salg_name = "cbc(aes)";
//
//    }
//
//    pub fn encrypt<I, D>(self, iv: I, data: D) -> impl Future<Item=(Vec<u8>, Session), Error=CryptoApiError>
//        where I: AsRef<[u8]>,
//              D: AsRef<[u8]> {
//        lazy(move || {
//            let msgs = [
//                ControlMessage::AlgSetOp(&libc::ALG_OP_ENCRYPT),
//                ControlMessage::AlgSetIv(iv.as_ref()),
//            ];
//            let iov = IoVec::from_slice(data.as_ref());
//            sendmsg(self.session_socket.as_raw_fd(), &[iov], &msgs, MsgFlags::empty(), None)
//                .map_err(CryptoApiError::SendMsg)
//                .into_future()
//                .and_then(move |_| {
//                    let mut buf = vec![0u8; data.as_ref().len()];
//
//                    self.context.read(self.session_socket.as_raw_fd(), 0, buf)
//                        .map_err(|_| CryptoApiError::AsyncRead)
//                        .map(|res| (res, self))
//                })
//        })
//    }
//}

pub struct SyncAfAlg {}

impl SyncAfAlg {
    pub fn new() -> Result<Self, CryptoApiError> {
        Ok(SyncAfAlg {})
    }
}

pub struct AsyncAfAlg {
    aio: tokio_linux_aio::AioContext,
}

impl AsyncAfAlg {
    pub fn new(aio: &tokio_linux_aio::AioContext) -> Result<Self, CryptoApiError> {
        Ok(AsyncAfAlg { aio: aio.clone() })
    }
}

pub struct AfAlgSyncCipherSession {
    socket: Socket,
    session_socket: Socket,
    cipher: Cipher,
    //    driver_name: String,
    //    is_accelerated: bool,
}

//
impl fmt::Debug for AfAlgSyncCipherSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AfAlgSyncCipherSession").field("cipher", &self.cipher).finish()
    }
}

pub struct AfAlgAsyncCipherSession {
    socket: Socket,
    session_socket: Socket,
    cipher: Cipher,
    aio: tokio_linux_aio::AioContext,
    //    driver_name: String,
    //    is_accelerated: bool,
}

//
impl fmt::Debug for AfAlgAsyncCipherSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AfAlgAsyncCipherSession").field("cipher", &self.cipher).finish()
    }
}

impl NewSession for SyncAfAlg {
    type Session = AfAlgSyncCipherSession;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<AfAlgSyncCipherSession, CryptoApiError> {
        let (salg_name, salg_type) = match *cipher {
            Cipher::AesCtr(key_size) => ("ctr(aes)", "skcipher"),
        };

        let socket = Socket::new(Domain::from(libc::AF_ALG), Type::seqpacket(), None).map_err(CryptoApiError::AfAlgSocket)?;
        let mut saddr: libc::sockaddr_alg = unsafe { mem::zeroed() };
        saddr.salg_family = libc::AF_ALG as u16;
        saddr.salg_type[..salg_type.len()].copy_from_slice(salg_type.to_string().as_bytes());
        saddr.salg_name[..salg_name.len()].copy_from_slice(salg_name.to_string().as_bytes());
        let sock_addr = unsafe { SockAddr::from_raw_parts(&saddr as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t) };
        socket.bind(&sock_addr).map_err(CryptoApiError::AfAlgBind)?;
        unsafe { setsockopt(&socket, libc::SOL_ALG, libc::ALG_SET_KEY, key) }.map_err(CryptoApiError::AfAlgSetKey)?;
        let session_socket = unsafe { Socket::from_raw_fd(libc::accept(socket.as_raw_fd(), ptr::null_mut(), &mut 0 as *mut _ as *mut libc::socklen_t)) };
        Ok(AfAlgSyncCipherSession {
            socket,
            session_socket,
            cipher: *cipher,
        })
    }
}

impl NewSession for AsyncAfAlg {
    type Session = AfAlgAsyncCipherSession;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<AfAlgAsyncCipherSession, CryptoApiError> {
        let (salg_name, salg_type) = match *cipher {
            Cipher::AesCtr(key_size) => ("ctr(aes)", "skcipher"),
        };

        let socket = Socket::new(Domain::from(libc::AF_ALG), Type::seqpacket(), None).map_err(CryptoApiError::AfAlgSocket)?;
        let mut saddr: libc::sockaddr_alg = unsafe { mem::zeroed() };
        saddr.salg_family = libc::AF_ALG as u16;
        saddr.salg_type[..salg_type.len()].copy_from_slice(salg_type.to_string().as_bytes());
        saddr.salg_name[..salg_name.len()].copy_from_slice(salg_name.to_string().as_bytes());
        let sock_addr = unsafe { SockAddr::from_raw_parts(&saddr as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t) };
        socket.bind(&sock_addr).map_err(CryptoApiError::AfAlgBind)?;
        unsafe { setsockopt(&socket, libc::SOL_ALG, libc::ALG_SET_KEY, key) }.map_err(CryptoApiError::AfAlgSetKey)?;
        let session_socket = unsafe { Socket::from_raw_fd(libc::accept(socket.as_raw_fd(), ptr::null_mut(), &mut 0 as *mut _ as *mut libc::socklen_t)) };
        Ok(AfAlgAsyncCipherSession {
            socket,
            session_socket,
            cipher: *cipher,
            aio: self.aio.clone(),
        })
    }
}

enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    fn set_op_code(&self) -> libc::c_int {
        match *self {
            Operation::Encrypt => libc::ALG_OP_ENCRYPT,
            Operation::Decrypt => libc::ALG_OP_DECRYPT,
        }
    }
}

impl AfAlgSyncCipherSession {
    fn perform<'a>(&self, op: Operation, iv: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoApiError> {
        assert_eq!(iv.len(), self.cipher.iv_len());
        assert_eq!(payload.len() % self.cipher.block_len(), 0);

        let set_op_code = op.set_op_code();

        let mut iv_storage = vec![0u8; iv.len() + mem::size_of::<libc::af_alg_iv>()];
        let iv_storage = unsafe { mem::transmute::<_, *mut libc::af_alg_iv>(iv_storage.as_mut_ptr()) };
        unsafe {
            (*iv_storage).ivlen = iv.len() as u32;
            ptr::copy_nonoverlapping(iv.as_ptr(), (*iv_storage).iv.as_mut_ptr(), iv.len());
        };
        let set_iv = &unsafe { *iv_storage };

        let msgs = [ControlMessage::AlgSetOp(&set_op_code), ControlMessage::AlgSetIv(set_iv)];
        let iov = IoVec::from_slice(payload);
        sendmsg(self.session_socket.as_raw_fd(), &[iov], &msgs, MsgFlags::empty(), None).map_err(CryptoApiError::AfAlgSendMsg)?;

        let mut buf = vec![0u8; payload.len()];
        let read_bytes = unsafe { libc::read(self.session_socket.as_raw_fd(), buf.as_mut_ptr() as *mut _, payload.len()) };
        if read_bytes as usize != buf.len() {
            return Err(CryptoApiError::AfAlgRead(io::Error::last_os_error()));
        }
        Ok(buf)
    }

    pub fn encrypt_future(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
        self.perform(Operation::Encrypt, iv, payload).into_future().map(|res| (self, res))
    }

    pub fn decrypt_future(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
        self.perform(Operation::Decrypt, iv, payload).into_future().map(|res| (self, res))
    }

    pub fn encrypt(&self, iv: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoApiError> {
        self.perform(Operation::Encrypt, iv, payload)
    }

    pub fn decrypt(&self, iv: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoApiError> {
        self.perform(Operation::Decrypt, iv, payload)
    }
}

impl AfAlgAsyncCipherSession {
    fn perform(self, op: Operation, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
        assert_eq!(iv.len(), self.cipher.iv_len());
        assert_eq!(payload.len() % self.cipher.block_len(), 0);

        let mut iv_storage = vec![0u8; iv.len() + mem::size_of::<libc::af_alg_iv>()];
        let iv_storage = unsafe { mem::transmute::<_, *mut libc::af_alg_iv>(iv_storage.as_mut_ptr()) };
        unsafe {
            (*iv_storage).ivlen = iv.len() as u32;
            ptr::copy_nonoverlapping(iv.as_ptr(), (*iv_storage).iv.as_mut_ptr(), iv.len());
        };
        let set_iv = &unsafe { *iv_storage };

        let set_op_code = op.set_op_code();

        let msgs = [ControlMessage::AlgSetOp(&set_op_code), ControlMessage::AlgSetIv(set_iv)];
        let iov = IoVec::from_slice(payload);

        let payload = payload.to_vec();

        sendmsg(self.session_socket.as_raw_fd(), &[iov], &msgs, MsgFlags::empty(), None)
            .map_err(CryptoApiError::AfAlgSendMsg)
            .into_future()
            .and_then(move |_| {
                let mut buf = vec![0u8; payload.len()];

                self.aio
                    .read(self.session_socket.as_raw_fd(), 0, buf)
                    .map_err(|_| CryptoApiError::AfAlgAsyncRead)
                    .map(|res| (self, res))
            })
    }

    pub fn encrypt_future(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
        self.perform(Operation::Encrypt, iv, payload)
    }

    pub fn decrypt_future(self, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
        self.perform(Operation::Decrypt, iv, payload)
    }
}
