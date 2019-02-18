#[derive(Debug, Clone, Copy)]
pub enum KeySize {
    Bits128 = 16,
    Bits192 = 24,
    Bits256 = 32,
}

#[derive(Debug, Clone, Copy)]
pub enum CipherType {
    Symmetric,
    Asymmetric,
}

#[derive(Debug, Clone, Copy)]
pub struct CipherInfo {
    cipher_type: CipherType,
    key_size: KeySize,
    block_size: usize,
    ivsize: usize,
    //    chunksize: Option<u16>,
    //    walksize: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct HashInfo {
    block_size: usize,
    digest_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum Aead {
    AesGcm(KeySize),
}

#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    AesCtr(KeySize),
    //    AesCbc(KeySize),
}

impl Cipher {
    pub fn key_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(k) => *k as usize,
        }
    }

    pub fn iv_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(_) => 16usize,
        }
    }

    pub fn block_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(_) => 1usize,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Hash {
    Sha1,
}

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    //    Aead(Aead),
    Cipher(Cipher),
    //    Hash(Hash),
}

impl Algorithm {
    //    pub fn algorithm_type(&self) -> AlgorithmType {
    //        match *self {
    //            Algorithm::Aead(Aead::AesGcm(key_size)) => AlgorithmType::Aead {
    //                cipher: CipherInfo {
    //                    cipher_type: CipherType::Symmetric,
    //                    key_size,
    //                    block_size: 1,
    //                    ivsize: 12,
    //                },
    //                hash: None,
    //            },
    //            Algorithm::Cipher(Cipher::AesCtr(key_size)) => AlgorithmType::Cipher(CipherInfo {
    //                cipher_type: CipherType::Symmetric,
    //                key_size,
    //                block_size: 1,
    //                ivsize: 16,
    //            }),
    //            Algorithm::Cipher(Cipher::AesCbc(key_size)) => AlgorithmType::Cipher(CipherInfo {
    //                cipher_type: CipherType::Symmetric,
    //                key_size,
    //                block_size: 16,
    //                ivsize: 16,
    //            }),
    //            Algorithm::Hash(Hash::Sha1) => AlgorithmType::Hash(HashInfo {
    //                block_size: 64,
    //                digest_size: 20,
    //            })
    //        }
    //    }
}

pub struct Session<I> {
    session: I,
}
