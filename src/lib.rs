extern crate bytes;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate libc;
#[macro_use]
extern crate nix;
extern crate socket2;
extern crate tokio;
extern crate tokio_linux_aio;
#[macro_use]
extern crate bitflags;
extern crate mio;

pub mod af_alg;
mod algorithms;
mod aligned_buf;
pub mod cryptodev;

pub use aligned_buf::AlignedBuf;

use core::mem;
use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::iter;
use std::os::unix::io::{AsRawFd, FromRawFd};
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
use tokio::runtime::current_thread::Runtime;

pub use crate::algorithms::{Cipher, KeySize};

pub trait NewSession
where
    Self: std::marker::Sized,
{
    type Session;

    fn new_cipher(&self, key: &[u8], cipher: &Cipher) -> Result<Self::Session, CryptoApiError>;
}

#[derive(Debug, Fail)]
pub enum CryptoApiError {
    #[fail(display = "/dev/crypto open error: _0")]
    CryptoDevOpen(#[fail(cause)] io::Error),
    #[fail(display = "cryptodev create session error: _0")]
    CryptoDevCreateSession(#[fail(cause)] nix::Error),
    #[fail(display = "cryptodev fetch session error: _0")]
    CryptoDevFetchSession(#[fail(cause)] nix::Error),
    #[fail(display = "cryptodev read error: _0")]
    CryptoDevRead(#[fail(cause)] io::Error),
    #[fail(display = "cryptodev operation error: _0")]
    CryptoDevOperation(#[fail(cause)] nix::Error),
    #[fail(display = "cryptodev async crypt operation error: _0")]
    CryptoDevAsyncCryptOperation(#[fail(cause)] nix::Error),
    #[fail(display = "cryptodev async fetch operation error: _0")]
    CryptoDevAsyncFetchOperation(#[fail(cause)] nix::Error),
    #[fail(display = "AF_ALG socket error: _0")]
    AfAlgSocket(#[fail(cause)] io::Error),
    #[fail(display = "AF_ALG bind error: _0")]
    AfAlgBind(#[fail(cause)] io::Error),
    #[fail(display = "AF_ALG set key error: _0")]
    AfAlgSetKey(#[fail(cause)] io::Error),
    #[fail(display = "AF_ALG read error: _0")]
    AfAlgRead(#[fail(cause)] io::Error),
    #[fail(display = "AF_ALG AIO read error")]
    AfAlgAsyncRead,
    #[fail(display = "AF_ALG failed to send message to socket: _0")]
    AfAlgSendMsg(#[fail(cause)] nix::Error),
}