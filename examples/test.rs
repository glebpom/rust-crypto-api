extern crate crypto_api;

use std::cell::RefCell;
use std::iter;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures::lazy;
use futures::prelude::*;
use tokio::clock;
use tokio::prelude::*;
use tokio::prelude::FutureExt;
use tokio::runtime::current_thread::Runtime;

use crypto_api::{Cipher, KeySize};
use crypto_api::NewCipherSession;

fn main() {
    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    for &data_size in &[4096, 8192] {
        for &parallel in &[4] {
            let mut rt = Runtime::new().unwrap();

            let counter = Arc::new(AtomicUsize::new(0));
            let started_at = clock::now();

            rt.block_on(
                lazy({
                    let counter = counter.clone();

                    move || {
                        let aio = tokio_linux_aio::AioContext::new(&tokio::executor::DefaultExecutor::current(), parallel).expect("AIO");
                        let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

                        stream::iter_ok(iter::repeat_with(move || {
                            let key = key.clone();
                            let af_alg = crypto_api::af_alg::AsyncAfAlg::new(&aio).expect("AsyncAfAlg");
                            af_alg.new_cipher(&key, &Cipher::AesCtr(KeySize::Bits256)).expect("NewCipher")
                        }).take(parallel))
                            .and_then({
                                let counter = counter.clone();
                                move |session| {
                                    let counter = counter.clone();
                                    Ok(stream::iter_ok(iter::repeat(()).take(100000))
                                           .fold(session, {
                                               let counter = counter.clone();

                                               move |session, ()| {
                                                   let num = counter.fetch_add(1, Ordering::Relaxed);
                                                   if num % 10000 == 0 {
                                                       println!("num = {:?}. passed: {:?}", num, clock::now() - started_at);
                                                   }

                                                   let iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
                                                   let data = vec![1u8; data_size];

                                                   session.encrypt_future(&iv, &data)
                                                       .map_err(|e| {
                                                           println!("Error {:?}", e);
                                                       })
                                                       .and_then(move |(session, r)| {
                                                           Ok(session)
                                                       })
                                               }
                                           })
                                            .map(|_| ())
                                            .map_err(|()| ()))
                                }
                            })
                            .buffer_unordered(parallel)
                            .for_each(|_| Ok::<(), ()>(()))
                    }
                }).then({
                    let counter = counter.clone();

                    move |r| {
                        let passed = clock::now() - started_at;
                        let secs = passed.as_secs() as usize;
                        println!("AF_ALG {} block with {} parallelism async: {} Mbits/sec", data_size, parallel, (counter.load(Ordering::SeqCst) * data_size * 8 / 1024 / 1024) / secs);
                        Ok::<(), ()>(())
                    }
                }));
        }
    }
}