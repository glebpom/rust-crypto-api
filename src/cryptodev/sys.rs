#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use libc::c_char;

pub const CRYPTO_HMAC_MAX_KEY_LEN: u32 = 512;
pub const CRYPTO_CIPHER_MAX_KEY_LEN: u32 = 64;

/// All the supported algorithms
pub enum cryptodev_crypto_op_t {
    CRYPTO_DES_CBC = 1,
    CRYPTO_3DES_CBC = 2,
    CRYPTO_BLF_CBC = 3,
    CRYPTO_CAST_CBC = 4,
    CRYPTO_SKIPJACK_CBC = 5,
    CRYPTO_MD5_HMAC = 6,
    CRYPTO_SHA1_HMAC = 7,
    CRYPTO_RIPEMD160_HMAC = 8,
    CRYPTO_MD5_KPDK = 9,
    CRYPTO_SHA1_KPDK = 10,
    CRYPTO_AES_CBC = 11,
    /// alias to CRYPTO_RIJNDAEL128_CBC
    CRYPTO_ARC4 = 12,
    CRYPTO_MD5 = 13,
    CRYPTO_SHA1 = 14,
    CRYPTO_DEFLATE_COMP = 15,
    CRYPTO_NULL = 16,
    CRYPTO_LZS_COMP = 17,
    CRYPTO_SHA2_256_HMAC = 18,
    CRYPTO_SHA2_384_HMAC = 19,
    CRYPTO_SHA2_512_HMAC = 20,
    CRYPTO_AES_CTR = 21,
    CRYPTO_AES_XTS = 22,
    CRYPTO_AES_ECB = 23,
    CRYPTO_AES_GCM = 50,

    CRYPTO_CAMELLIA_CBC = 101,
    CRYPTO_RIPEMD160,
    CRYPTO_SHA2_224,
    CRYPTO_SHA2_256,
    CRYPTO_SHA2_384,
    CRYPTO_SHA2_512,
    CRYPTO_SHA2_224_HMAC,
    CRYPTO_ALGORITHM_ALL, // Keep updated - see below
}

pub const CRYPTO_ALGORITHM_MAX: isize = (cryptodev_crypto_op_t::CRYPTO_ALGORITHM_ALL as isize - 1);

/* Values for ciphers */
pub const DES_BLOCK_LEN: usize = 8;
pub const DES3_BLOCK_LEN: usize = 8;
pub const AES_BLOCK_LEN: usize = 16;
pub const CAMELLIA_BLOCK_LEN: usize = 16;
pub const BLOWFISH_BLOCK_LEN: usize = 8;
pub const SKIPJACK_BLOCK_LEN: usize = 8;
pub const CAST128_BLOCK_LEN: usize = 8;

/// the maximum of the above
pub const EALG_MAX_BLOCK_LEN: usize = 16;

/// Values for hashes/MAC
pub const AALG_MAX_RESULT_LEN: usize = 64;

/// maximum length of verbose alg names (depends on CRYPTO_MAX_ALG_NAME)
pub const CRYPTODEV_MAX_ALG_NAME: usize = 64;

pub const HASH_MAX_LEN: usize = 64;

#[derive(Copy, Clone)]
#[repr(C)]
/// input of `CIOCGSESSION`
/// Specify either cipher or mac
pub struct session_op {
    /// `cryptodev_crypto_op_t`
    pub cipher: u32,
    /// `cryptodev_crypto_op_t`
    pub mac: u32,
    pub keylen: u32,
    /// pointer to key data
    pub key: *const u8,
    pub mackeylen: u32,
    /// pointer to mac key data
    pub mackey: *const u8,
    /// session identifier
    pub ses: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct alg_info {
    pub cra_name: [c_char; CRYPTODEV_MAX_ALG_NAME],
    pub cra_driver_name: [c_char; CRYPTODEV_MAX_ALG_NAME],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct session_info_op {
    /// session identifier */
    pub ses: u32,

    /// verbose names for the requested ciphers
    pub cipher_info: alg_info,
    pub hash_info: alg_info,

    /// alignment pub constraints
    pub alignmask: u16,

    /// SIOP_FLAGS_*
    pub flags: SiopFlags,
}

///If this flag is set then this algorithm uses
///a driver only available in kernel (software drivers,
///or drivers based on inpub struction sets do not set this flag).
///
///If multiple algorithms are involved (as in AEAD case), then
bitflags! {
    pub struct SiopFlags: u32 {
        const KERNEL_DRIVER_ONLY = 1;
    }
}

pub const COP_ENCRYPT: u16 = 0;
pub const COP_DECRYPT: u16 = 1;

#[derive(Copy, Clone)]
#[repr(C)]
/// input of `CIOCCRYPT`
pub struct crypt_op {
    /// session identifier
    pub ses: u32,
    /// `COP_ENCRYPT` or `COP_DECRYPT`
    pub op: u16,
    /// see `COP_FLAG_*`
    pub flags: u16,
    /// length of source data
    pub len: u32,
    /// source data
    pub src: *const u8,
    /// pointer to output data
    pub dst: *mut u8,
    /// pointer to output data for hash/MAC operations
    pub mac: *mut u8,
    /// initialization vector for encryption operations
    pub iv: *const u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
/// input of CIOCAUTHCRYPT
pub struct crypt_auth_op {
    /// session identifier
    ses: u32,
    /// COP_ENCRYPT or COP_DECRYPT
    op: u16,
    /// see COP_FLAG_AEAD_*
    flags: u16,
    /// length of source data
    len: u32,
    /// length of auth data
    auth_len: u32,
    /// authenticated-only data
    auth_src: *mut u8,

    /// The current implementation is more efficient if data are
    /// encrypted in-place (src==dst).
    /// data to be encrypted and authenticated
    src: *mut u8,
    /// pointer to output data. Must have space for tag. For TLS this should be at least
    /// len + tag_size + block_size for padding
    dst: *mut u8,

    /// where the tag will be copied to. TLS mode
    /// doesn't use that as tag is copied to dst.
    /// SRTP mode copies tag there.
    tag: *mut u8,
    /// the length of the tag. Use zero for digest size or max tag.
    tag_len: u32,

    /// initialization vector for encryption operations
    iv: *mut u8,
    iv_len: u32,
}

/* In plain AEAD mode the following are required:
*  flags   : 0
*  iv      : the initialization vector (12 bytes)
*  auth_len: the length of the data to be authenticated
*  auth_src: the data to be authenticated
*  len     : length of data to be encrypted
*  src     : the data to be encrypted
*  dst     : space to hold encrypted data. It must have
*            at least a size of len + tag_size.
*  tag_size: the size of the desired authentication tag or zero to use
*            the maximum tag output.
*
* Note tag isn't being used because the Linux AEAD interface
* copies the tag just after data.
*/

/* In TLS mode (used for CBC ciphers that required padding)
* the following are required:
*  flags   : COP_FLAG_AEAD_TLS_TYPE
*  iv      : the initialization vector
*  auth_len: the length of the data to be authenticated only
*  len     : length of data to be encrypted
*  auth_src: the data to be authenticated
*  src     : the data to be encrypted
*  dst     : space to hold encrypted data (preferably in-place). It must have
*            at least a size of len + tag_size + blocksize.
*  tag_size: the size of the desired authentication tag or zero to use
*            the default mac output.
*
* Note that the padding used is the minimum padding.
*/

/* In SRTP mode the following are required:
*  flags   : COP_FLAG_AEAD_SRTP_TYPE
*  iv      : the initialization vector
*  auth_len: the length of the data to be authenticated. This must
*            include the SRTP header + SRTP payload (data to be encrypted) + rest
*
*  len     : length of data to be encrypted
*  auth_src: pointer the data to be authenticated. Should point at the same buffer as src.
*  src     : pointer to the data to be encrypted.
*  dst     : This is mandatory to be the same as src (in-place only).
*  tag_size: the size of the desired authentication tag or zero to use
*            the default mac output.
*  tag     : Pointer to an address where the authentication tag will be copied.
*/

/// pub struct crypt_op flags
bitflags! {
    pub struct CryptoFlags: u8 {
        /// multi-update hash mode
        const UPDATE = (1 << 0);
        /// multi-update final hash mode
        const FINAL = (1 << 1);
        /// update the IV during operation
        const WRITE_IV =(1 << 2);
        /// do not zero-copy
        const NO_ZC =(1 << 3);
        /// authenticate and encrypt using the TLS protocol rules
        const AEAD_TLS_TYPE = (1 << 4);
        /// authenticate and encrypt using the SRTP protocol rules
        const AEAD_SRTP_TYPE = (1 << 5);
        /// multi-update reset the state. should be used in combination with COP_FLAG_UPDATE
        const RESET = (1 << 6);
    }
}

/// Stuff for bignum arithmetic and public key
/// cryptography - not supported yet by linux
/// cryptodev.
bitflags! {
    pub struct CryptoAlgFlags: u8 {
        const SUPPORTED = 1;
        const RNG_ENABLE= 2;
        const DSA_SHA= 4;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct crparam {
    crp_p: *mut u8,
    crp_nbits: u32,
}

pub const CRK_MAXPARAM: usize = 8;

/// input of CIOCKEY
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypt_kop {
    /// cryptodev_crk_op_t
    crk_op: u32,
    crk_status: u32,
    crk_iparams: u16,
    crk_oparams: u16,
    crk_pad1: u32,
    crk_param: [crparam; CRK_MAXPARAM],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub enum cryptodev_crk_op_t {
    CRK_MOD_EXP = 0,
    CRK_MOD_EXP_CRT = 1,
    CRK_DSA_SIGN = 2,
    CRK_DSA_VERIFY = 3,
    CRK_DH_COMPUTE_KEY = 4,
    CRK_ALGORITHM_ALL,
}

pub const CRK_ALGORITHM_MAX: isize = cryptodev_crk_op_t::CRK_ALGORITHM_ALL as isize - 1;

/// input of `CIOCCPHASH`
///  * `dst_ses` : destination session identifier
///  * `src_ses` : source session identifier
///  * `dst_ses` must have been created with `CIOGSESSION` first
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cphash_op {
    dst_ses: u32,
    src_ses: u32,
}

// features to be queried with `CIOCASYMFEAT` ioctl

pub const CRF_MOD_EXP: u32 = (1 << cryptodev_crk_op_t::CRK_MOD_EXP as u32);
pub const CRF_MOD_EXP_CRT: u32 = (1 << cryptodev_crk_op_t::CRK_MOD_EXP_CRT as u32);
pub const CRF_DSA_SIGN: u32 = (1 << cryptodev_crk_op_t::CRK_DSA_SIGN as u32);
pub const CRF_DSA_VERIFY: u32 = (1 << cryptodev_crk_op_t::CRK_DSA_VERIFY as u32);
pub const CRF_DH_COMPUTE_KEY: u32 = (1 << cryptodev_crk_op_t::CRK_DH_COMPUTE_KEY as u32);

/// #define CRIOGET         _IOWR('c', 101, __u32)
ioctl_readwrite!(CRIOGET, b'c', 101, u32);
/// #define CIOCGSESSION    _IOWR('c', 102, pub struct session_op)
ioctl_readwrite!(CIOCGSESSION, b'c', 102, session_op);
/// #define CIOCFSESSION    _IOW('c', 103, __u32)
ioctl_write_ptr!(CIOCFSESSION, b'c', 103, u32);

/// #define CIOCCRYPT       _IOWR('c', 104, pub struct crypt_op)
ioctl_readwrite!(CIOCCRYPT, b'c', 104, crypt_op);

/// #define CIOCKEY         _IOWR('c', 105, pub struct crypt_kop)
ioctl_readwrite!(CIOCKEY, b'c', 105, crypt_kop);

/// #define CIOCASYMFEAT    _IOR('c', 106, __u32)
ioctl_read!(CIOCASYMFEAT, b'c', 106, u32);

/// #define CIOCGSESSINFO	_IOWR('c', 107, pub struct session_info_op)
ioctl_readwrite!(CIOCGSESSINFO, b'c', 107, session_info_op);

/// to indicate that CRIOGET is not required in linux
pub const CRIOGET_NOT_NEEDED: u8 = 1;

/// additional ioctls for AEAD */
/// #define CIOCAUTHCRYPT   _IOWR('c', 109, pub struct crypt_auth_op)
ioctl_readwrite!(CIOCAUTHCRYPT, b'c', 109, crypt_auth_op);

///#define CIOCASYNCCRYPT    _IOW('c', 110, pub struct crypt_op)
ioctl_write_ptr!(CIOCASYNCCRYPT, b'c', 110, crypt_op);

/// #define CIOCASYNCFETCH    _IOR('c', 111, pub struct crypt_op)
ioctl_read!(CIOCASYNCFETCH, b'c', 111, crypt_op);

/// additional ioctl for copying of hash/mac session state data
/// between sessions.
/// The cphash_op parameter should contain the session id of
/// the source and destination sessions. Both sessions
/// must have been created with CIOGSESSION.
/// #define CIOCCPHASH _IOW('c', 112, pub struct cphash_op)
ioctl_write_ptr!(CIOCCPHASH, b'c', 112, cphash_op);
