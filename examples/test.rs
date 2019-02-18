extern crate crypto_api;

use std::cell::RefCell;
use std::iter;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures::lazy;
use futures::prelude::*;
use tokio::clock;
use tokio::prelude::FutureExt;
use tokio::prelude::*;
use tokio::runtime::current_thread::Runtime;
//use tokio::runtime::Runtime;

use crypto_api::NewSession;
use crypto_api::{Cipher, KeySize};

const DATA_SIZE: usize = 4096 * 2;

fn main() {
    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    //    let encrypted = session.encrypt(&iv, &payload).unwrap();
    //    println!("Encrypted = {:?}", encrypted);
    //    let decrypted = session.decrypt(&iv, encrypted.as_ref()).unwrap();
    //    println!("Decrypted = {:?}", decrypted);

    //
    let mut rt = Runtime::new().unwrap();

    //    let counter = Rc::new(RefCell::new(0usize));
    //    let started_at = clock::now();
    //    rt.block_on(
    //        lazy(move || {
    //            let crypto_dev = crypto_api::cryptodev::SyncCryptoDev::new().unwrap();
    //            let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    //            let session = crypto_dev.new_cipher(&key, &Cipher::AesCtr(KeySize::Bits256)).unwrap();
    //            Ok::<_, ()>(session)
    //        }).and_then({
    //            let counter = counter.clone();
    //            move |session| {
    //                stream::iter_ok(iter::repeat(()).take(10000))
    //                    .fold(session, move |session, ()| {
    //                        *counter.borrow_mut() += 1;
    //                        let iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    //                        let data = vec![1u8; DATA_SIZE];
    //
    //                        session.encrypt_future(&iv, &data)
    //                            .map_err(|e| {
    //                                println!("Error {:?}", e);
    //                            })
    //                            .and_then(move |(session, r)| {
    ////                                println!("Result {:?}", r);
    //                                Ok(session)
    //                            })
    //                    })
    //                    .map(|_| ())
    //            }
    //        })
    //            .then({
    //                let counter = counter.clone();
    //
    //                move |r| {
    //                    let passed = clock::now() - started_at;
    //                    let secs = passed.as_secs() as usize;
    //                    println!("CryptoDev sync: {} Mbits/sec", (*counter.borrow() * DATA_SIZE * 8 / 1024 / 1024) / secs);
    //                    Ok::<(), ()>(())
    //                }
    //            })
    //    );
    //
    ////    let counter = Rc::new(RefCell::new(0usize));
    ////    let started_at = clock::now();
    ////    rt.block_on(
    ////        lazy(move || {
    ////            let crypto_dev = crypto_api::cryptodev::AsyncCryptoDev::new().unwrap();
    ////            let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    ////            let session = crypto_dev.new_cipher(&key, &Cipher::AesCtr(KeySize::Bits256)).unwrap();
    ////            Ok::<_, ()>(session)
    ////        }).and_then({
    ////            let counter = counter.clone();
    ////            move |session| {
    ////                stream::iter_ok(iter::repeat(()).take(1000000))
    ////                    .fold(session, move |session, ()| {
    ////                        *counter.borrow_mut() += 1;
    ////                        let iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    ////                        let data = vec![1u8; DATA_SIZE];
    ////
    ////                        session.encrypt_future(&iv, &data)
    ////                            .map_err(|e| {
    ////                                println!("Error {:?}", e);
    ////                            })
    ////                            .and_then(move |(session, r)| {
    //////                                println!("Result {:?}", r);
    ////                                Ok(session)
    ////                            })
    ////                    })
    ////                    .map(|_| ())
    ////            }
    ////        })
    ////            .then({
    ////                let counter = counter.clone();
    ////
    ////                move |r| {
    ////                    let passed = clock::now() - started_at;
    ////                    let secs = passed.as_secs() as usize;
    ////                    println!("CryptoDev sync: {} Mbits/sec", (*counter.borrow() * DATA_SIZE * 8 / 1024 / 1024) / secs);
    ////                    Ok::<(), ()>(())
    ////                }
    ////            })
    ////    );
    //
    //
    //    let counter = Rc::new(RefCell::new(0usize));
    //    let started_at = clock::now();
    //    rt.block_on(
    //        lazy(move || {
    //            let af_alg = crypto_api::af_alg::SyncAfAlg::new().unwrap();
    //            let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    //            let session = af_alg.new_cipher(&key, &Cipher::AesCtr(KeySize::Bits256)).unwrap();
    //            Ok::<_, ()>(session)
    //        }).and_then({
    //            let counter = counter.clone();
    //            move |session| {
    //                stream::iter_ok(iter::repeat(()).take(10000))
    //                    .fold(session, move |session, ()| {
    //                        *counter.borrow_mut() += 1;
    //                        let iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    //                        let data = vec![1u8; DATA_SIZE];
    //
    //                        session.encrypt_future(&iv, &data)
    //                            .map_err(|e| {
    //                                println!("Error {:?}", e);
    //                            })
    //                            .and_then(move |(session, r)| {
    ////                                println!("Result {:?}", r);
    //                                Ok(session)
    //                            })
    //                    })
    //                    .map(|_| ())
    //            }
    //        })
    //            .then({
    //                let counter = counter.clone();
    //
    //                move |r| {
    //                    let passed = clock::now() - started_at;
    //                    let secs = passed.as_secs() as usize;
    //                    println!("AF_ALG: {} Mbits/sec", (*counter.borrow() * DATA_SIZE * 8 / 1024 / 1024) / secs);
    //                    Ok::<(), ()>(())
    //                }
    //            })
    //    );

    for &data_size in &[64, 512, 1024, 2048, 4096, 8192, 16536] {
        for &parallel in &[1, 2, 3, 4, 5, 6] {
            let mut rt = Runtime::new().unwrap();

            let counter = Arc::new(AtomicUsize::new(0));
            let started_at = clock::now();

            rt.block_on(
                lazy({
                    let counter = counter.clone();

                    move || {
                        let aio = tokio_linux_aio::AioContext::new(&tokio::executor::DefaultExecutor::current(), parallel).expect("AIO");
                        let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

                        stream::iter_ok(
                            iter::repeat_with(move || {
                                let key = key.clone();
                                let af_alg = crypto_api::af_alg::AsyncAfAlg::new(&aio).expect("AsyncAfAlg");
                                (af_alg.new_cipher(&key, &Cipher::AesCtr(KeySize::Bits256)).expect("NewCipher"), key, af_alg)
                            })
                            .take(parallel),
                        )
                        .and_then({
                            let counter = counter.clone();
                            move |(session, key, af_alg)| {
                                let counter = counter.clone();
                                Ok(stream::iter_ok(iter::repeat(()))
                                    .fold(session, {
                                        let counter = counter.clone();

                                        move |session, ()| {
                                            //                                        let counter = counter.clone();
                                            let num = counter.fetch_add(1, Ordering::Relaxed);
                                            if num % 10000 == 0 {
                                                println!("num = {:?}. passed: {:?}", num, clock::now() - started_at);
                                            }

                                            let iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
                                            let data = vec![1u8; data_size];

                                            session
                                                .encrypt_future(&iv, &data)
                                                .map_err(|e| {
                                                    println!("Error {:?}", e);
                                                })
                                                .and_then(move |(session, r)| Ok(session))
                                        }
                                    })
                                    .map(|_| ())
                                    .map_err(|()| ())
                                    .timeout(Duration::from_secs(2))
                                    .map_err(|_: tokio::timer::timeout::Error<()>| ()))
                            }
                        })
                        .buffered(parallel)
                        .for_each(|_| Ok::<(), ()>(()))
                    }
                })
                .then({
                    let counter = counter.clone();

                    move |r| {
                        let passed = clock::now() - started_at;
                        let secs = passed.as_secs() as usize;
                        println!(
                            "AF_ALG {} block with {} parallelism async: {} Mbits/sec",
                            data_size,
                            parallel,
                            (counter.load(Ordering::SeqCst) * data_size * 8 / 1024 / 1024) / secs
                        );
                        Ok::<(), ()>(())
                    }
                }),
            );
        }
    }
}
