#[derive(Debug, Clone, Copy)]
pub enum KeySize {
    Bits128 = 16,
    Bits192 = 24,
    Bits256 = 32,
}

#[derive(Debug, Clone, Copy)]
pub enum Hash {
    Sha256,
    Sha224,
    Sha1,
    Md5,
}

impl Hash {
    pub fn block_len(&self) -> usize {
        match &self {
            Hash::Sha256 => 64,
            Hash::Sha224 => 64,
            Hash::Sha1 => 64,
            Hash::Md5 => 64,
        }
    }

    pub fn digest_len(&self) -> usize {
        match &self {
            Hash::Sha256 => 32,
            Hash::Sha224 => 28,
            Hash::Sha1 => 20,
            Hash::Md5 => 15,        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Aead {
    pub cipher: Cipher,
    pub hmac: Hash,
}

#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    AesCtr(KeySize),
    AesCbc(KeySize),
}

impl Cipher {
    pub fn key_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(k) => *k as usize,
            Cipher::AesCbc(k) => *k as usize,
        }
    }

    pub fn iv_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(_) => 16usize,
            Cipher::AesCbc(_) => 16usize,
        }
    }

    pub fn block_len(&self) -> usize {
        match &self {
            Cipher::AesCtr(_) => 1usize,
            Cipher::AesCbc(_) => 16usize,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    Aead(Aead),
    Cipher(Cipher),
}
