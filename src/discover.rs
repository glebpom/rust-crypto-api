use std::io::{self, Read};
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug)]
pub struct CipherParams {
    blocksize: u16,
    min_keysize: u16,
    max_keysize: u16,
    ivsize: u16,
    chunksize: u16,
}

//
//#[derive(Debug)]
//pub struct HashParams {
//    blocksize: u16,
//    digestsize: u16,
//}
//
//#[derive(Debug)]
//pub struct AeadParams {
//    blocksize: u16,
//    ivsize: u16,
//    max_auth_size: u16,
//}


//skcipher - symmetric key cipher
//akcipher - asymmetric key cipher
//shash - hash

#[derive(Debug)]
pub enum AlgorithmType {
    Skcipher(CipherParams),
    Akcipher(CipherParams),
}

#[derive(Debug, Fail)]
pub enum AlgorithmTypeError {
    #[fail(display = "unknown algorithm type: _0")]
    Unknown(String),
}

impl FromStr for AlgorithmType {
    type Err = AlgorithmTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
//            "aead" => AlgorithmType::Aead,
//            "akcipher" => AlgorithmType::Akcipher,
//            "blkcipher" => AlgorithmType::Blkcipher,
//            "cipher" => AlgorithmType::Cipher,
//            "compression" => AlgorithmType::Compression,
//            "kpp" => AlgorithmType::Kpp,
//            "rng" => AlgorithmType::Rng,
//            "scomp" => AlgorithmType::Scomp,
//            "shash" => AlgorithmType::Shash,
            "skcipher" => AlgorithmType::Skcipher,
            s => return Err(AlgorithmTypeError::Unknown(s.to_string())),
        })
    }
}

#[derive(Debug)]
pub struct Algorithm {
    name: String,
    driver: String,
    module: String,
    algo_type: AlgorithmType,
    priority: u32,
    refcnt: u32,
//    block_size: u32,
//    min_keysize: u32,
//    max_keysize: u32,
//    is_internal: bool,
}


#[derive(Debug, Fail)]
pub enum AlgorithmError {
    #[fail(display = "algorithm type error")]
    AlgorithmType(#[fail(cause)] AlgorithmTypeError),
}

impl Algorithm {
    fn from_hash(hash: &mut HashMap<String, String>) -> Option<Algorithm> {
        Some(Algorithm {
            name: hash.remove("name")?,
            driver: hash.remove("driver")?,
            module: hash.remove("module")?,
            algo_type: hash.remove("type")?.parse().unwrap(),
            priority: hash.remove("priority")?.parse().unwrap(),
            refcnt: hash.remove("refcnt")?.parse().unwrap(),
//            block_size: hash.remove("block_size")?.parse().unwrap(),
//            min_keysize: hash.remove("min_keysize")?.parse().unwrap(),
//            max_keysize: hash.remove("max_keysize")?.parse().unwrap(),
//            is_internal: true,// hash.remove("internal").unwrap_or("no".to_string),
        })
    }
}

pub fn algorithms() -> io::Result<Vec<Algorithm>> {
    let f = File::open("/proc/crypto")?;
    let f = BufReader::new(f);

    let mut hash = HashMap::new();

    for line in f.lines() {
        let line = line?;
        if line.is_empty() {
            let algorithm = Algorithm::from_hash(&mut hash);
            hash.clear();
            println!("Got algorithm: {:?}", algorithm);
            continue;
        }
        let kv = line.split(":").map(|s| s.to_string()).collect::<Vec<String>>();
        if kv.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad line"));
        }
        let key = kv[0].trim_end().to_string();
        let value = kv[1].trim_start().to_string();

        hash.insert(key, value);
    }

    let algorithm = Algorithm::from_hash(&mut hash);
    println!("Last hash: {:?}", algorithm);

    Ok(vec![])
}