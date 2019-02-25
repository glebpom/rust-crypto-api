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
use nix::sys::socket::{sendmsg, ControlMessage, setsockopt};
use nix::sys::socket::sockopt::{AlgSetKey, AlgSetAeadAuthSize};
use nix::sys::uio::IoVec;
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::prelude::FutureExt;
use tokio::prelude::*;
use tokio::runtime::current_thread::Runtime;

use crate::algorithms::{Cipher, Aead, Hash, KeySize};
use crate::CryptoApiError;
use crate::NewCipherSession;
use crate::NewAeadSession;

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
}

impl fmt::Debug for AfAlgAsyncCipherSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AfAlgAsyncCipherSession").field("cipher", &self.cipher).finish()
    }
}

pub struct AfAlgSyncAeadSession {
    socket: Socket,
    session_socket: Socket,
    aead: Aead,
    aead_auth_len: u8,
}

impl fmt::Debug for AfAlgSyncAeadSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AfAlgSyncAeadSession").field("aead", &self.aead).finish()
    }
}

pub struct AfAlgAsyncAeadSession {
    socket: Socket,
    session_socket: Socket,
    aead: Aead,
    aead_auth_len: u8,
    aio: tokio_linux_aio::AioContext,
}

impl fmt::Debug for AfAlgAsyncAeadSession {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AfAlgAsyncAeadSession").field("aead", &self.aead).finish()
    }
}


fn aead_to_spec(aead: &Aead) -> (&'static str, &'static str) {
    match *aead {
        Aead {
            cipher: Cipher::AesCbc(_),
            hmac: Hash::Sha256,
        } => ("authenc(hmac(sha256),cbc(aes))", "aead"),
        Aead {
            cipher: Cipher::AesCbc(_),
            hmac: Hash::Sha1,
        } => ("authenc(hmac(sha1),cbc(aes))", "aead"),
        _ => unimplemented!(),
    }
}

fn cipher_to_spec(cipher: &Cipher) -> (&'static str, &'static str) {
    match *cipher {
        Cipher::AesCtr(key_size) => ("ctr(aes)", "skcipher"),
        _ => unimplemented!(),
    }
}

fn new_session(salg_name: &str, salg_type: &str, key: Option<&[u8]>, aead_auth_len: Option<u8>) -> Result<(Socket, Socket), CryptoApiError> {
    let socket = Socket::new(Domain::from(libc::AF_ALG), Type::seqpacket(), None).map_err(CryptoApiError::AfAlgSocket)?;
    let mut saddr: libc::sockaddr_alg = unsafe { mem::zeroed() };
    saddr.salg_family = libc::AF_ALG as u16;
    saddr.salg_type[..salg_type.len()].copy_from_slice(salg_type.to_string().as_bytes());
    saddr.salg_name[..salg_name.len()].copy_from_slice(salg_name.to_string().as_bytes());
    let sock_addr = unsafe { SockAddr::from_raw_parts(&saddr as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t) };
    socket.bind(&sock_addr).map_err(CryptoApiError::AfAlgBind)?;
    if let Some(aead_auth_len) = aead_auth_len {
        // case ALG_SET_AEAD_AUTHSIZE:
        //   if (sock->state == SS_CONNECTED)
        //       goto unlock;
        //   if (!type->setauthsize)
        //       goto unlock;
        //   err = type->setauthsize(ask->private, optlen);

//        setsockopt(socket.as_raw_fd(), AlgSetAeadAuthSize, &aead_auth_len).map_err(CryptoApiError::AfAlgSetKey)?;
    }
    if let Some(key) = key {
        let key = key.to_vec();
        setsockopt(socket.as_raw_fd(), AlgSetKey::default(), &key).map_err(CryptoApiError::AfAlgSetKey)?;
    }
    let session_socket = unsafe { Socket::from_raw_fd(libc::accept(socket.as_raw_fd(), ptr::null_mut(), &mut 0 as *mut _ as *mut libc::socklen_t)) };
    Ok((socket, session_socket))
}

impl NewCipherSession for SyncAfAlg {
    type Cipher = AfAlgSyncCipherSession;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<AfAlgSyncCipherSession, CryptoApiError> {
        let (salg_name, salg_type) = cipher_to_spec(cipher);
        let (socket, session_socket) = new_session(salg_name, salg_type, Some(key), None)?;
        Ok(AfAlgSyncCipherSession {
            socket,
            session_socket,
            cipher: *cipher,
        })
    }
}

impl NewCipherSession for AsyncAfAlg {
    type Cipher = AfAlgAsyncCipherSession;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<AfAlgAsyncCipherSession, CryptoApiError> {
        let (salg_name, salg_type) = cipher_to_spec(cipher);
        let (socket, session_socket) = new_session(salg_name, salg_type, Some(key), None)?;
        Ok(AfAlgAsyncCipherSession {
            socket,
            session_socket,
            cipher: *cipher,
            aio: self.aio.clone(),
        })
    }
}

impl NewAeadSession for AsyncAfAlg {
    type Aead = AfAlgAsyncAeadSession;

    fn new_aead(&self, key: &[u8], aead: &Aead, aead_auth_len: u8) -> Result<Self::Aead, CryptoApiError> {
        let (salg_name, salg_type) = aead_to_spec(aead);
        let (socket, session_socket) = new_session(salg_name, salg_type, Some(key), Some(aead_auth_len))?;
        Ok(AfAlgAsyncAeadSession {
            socket,
            session_socket,
            aead: *aead,
            aead_auth_len,
            aio: self.aio.clone(),
        })
    }
}

impl NewAeadSession for SyncAfAlg {
    type Aead = AfAlgSyncAeadSession;

    fn new_aead(&self, key: &[u8], aead: &Aead, aead_auth_len: u8) -> Result<Self::Aead, CryptoApiError> {
        let (salg_name, salg_type) = aead_to_spec(aead);
        let (socket, session_socket) = new_session(salg_name, salg_type, Some(key), Some(aead_auth_len))?;
        Ok(AfAlgSyncAeadSession {
            socket,
            session_socket,
            aead: *aead,
            aead_auth_len: 0
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

        let msgs = [ControlMessage::AlgSetOp(&set_op_code), ControlMessage::AlgSetIv(iv)];
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

        let set_op_code = op.set_op_code();

        let msgs = [ControlMessage::AlgSetOp(&set_op_code), ControlMessage::AlgSetIv(iv)];
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

impl AfAlgAsyncAeadSession {
    fn perform(self, op: Operation, iv: &[u8], payload: &[u8]) -> impl Future<Item = (Self, Vec<u8>), Error = CryptoApiError> {
//        assert_eq!(iv.len(), self.aead.cipher.iv_len());
//        assert_eq!(payload.len() % self.aead.cipher.block_len(), 0);

        let aead_auth_len = self.aead_auth_len;

        let set_op_code = op.set_op_code();

        let msgs = [ControlMessage::AlgSetOp(&set_op_code), ControlMessage::AlgSetIv(iv)];
        let iov = IoVec::from_slice(payload);

        let payload = payload.to_vec();

        sendmsg(self.session_socket.as_raw_fd(), &[iov], &msgs, MsgFlags::empty(), None)
            .map_err(CryptoApiError::AfAlgSendMsg)
            .into_future()
            .and_then(move |_| {
                let mut buf = vec![0u8; payload.len() + aead_auth_len as usize];

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
