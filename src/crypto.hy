// crypto: hashing (SHA-256, SHA-512, BLAKE3, incremental `Hasher`), HMAC,
// OS randomness, AEAD (ChaCha20-Poly1305, AES-256-GCM), Ed25519 signatures,
// X25519 key agreement, Argon2id password hashing and constant-time compare.
//
// Userland crypto — FFI to native/libcrypto.{so,dylib,dll} (dload("crypto")).
// Surface names match CRYPTO_WIRING. Hasher state lives in the .so.
//
// Bytes cross the FFI directly: every native that reads or writes a buffer
// is bound with `declare`, inputs as `ConstBytes` and output buffers as
// `Bytes`, so the VM lends each `Vec<byte>` (or copies it once) instead of
// coil code copying it one byte at a time. `extern` blocks cannot take those
// tags, which is why these go through `declare` / `invoke`; the natives with
// no buffer stay in the `extern` block.
//
// err_out is never a Coil array: pass a null pointer (`err_ptr()` in the
// extern block, `0` through `invoke`) and read coil_crypto_last_error()
// after a failing call.

use ffi::{dload, declare, invoke, Error};
use ffi::types::{Bytes, ConstBytes, Int, Void};
use string::{from_bytes, slice_bytes, to_bytes};

extern "crypto" {
    fn coil_crypto_null() -> ptr;
    fn coil_crypto_last_error() -> int;
    fn coil_crypto_last_i64() -> int;
    fn coil_crypto_is_null(ptr p) -> int;
    fn coil_crypto_hasher_init(int alg, ptr err_out) -> ptr;
    fn coil_crypto_random_u64(ptr value_out, ptr err_out) -> int;
}

/// Why a crypto call failed.
///
/// Every fallible function in this package returns `Result<_, CryptoError>`.
/// Verification functions (`hmac_verify_sha256`, `ed25519_verify`,
/// `argon2id_verify`) report a mismatch as `AuthenticationFailed`, never as
/// `Ok(false)`.
///
/// # Examples
///
/// ```
/// use crypto::{chacha20_poly1305_decrypt, CryptoError};
/// # use tests::assert;
/// let short_key: Vec<byte> = [1 as byte, 2 as byte];
/// let nonce: Vec<byte> = [0 as byte, 0 as byte, 0 as byte, 0 as byte, 0 as byte, 0 as byte,
///     0 as byte, 0 as byte, 0 as byte, 0 as byte, 0 as byte, 0 as byte];
/// let empty: Vec<byte> = [];
/// let wrong_size = match chacha20_poly1305_decrypt(short_key, nonce, empty, empty) {
///     Result::Ok(_) => false,
///     Result::Err(e) => match e {
///         CryptoError::InvalidLength => true,
///         default => false,
///     },
/// };
/// assert!(wrong_size);
/// ```
enum CryptoError {
    /// An argument the native rejected: a value out of range (such as
    /// `random_bytes` above 1 MiB), a malformed key or a malformed PHC hash.
    InvalidInput,
    /// A key, nonce, tag, signature or salt of the wrong size.
    InvalidLength,
    /// A tag, signature or password did not verify, or ciphertext was tampered with.
    AuthenticationFailed,
    /// `init` was given an algorithm tag other than `0`, `1` or `2`.
    UnsupportedAlgorithm,
    /// `update` or `finalize` on a `Hasher` that was already finalized.
    AlreadyFinalized,
    /// Any other failure, such as the OS random source failing.
    Other,
}

/// An incremental hash of SHA-256, SHA-512 or BLAKE3.
///
/// Make one with `init`, feed it with `update` as many times as needed and
/// read the digest once with `finalize`. The digest equals the one-shot
/// `sha256` / `sha512` / `blake3` of all the data concatenated. The state
/// lives in the native library and is freed when the `Hasher` is dropped.
///
/// # Examples
///
/// ```
/// use crypto::{init, sha256, Hasher};
/// use string::{to_bytes};
/// # use tests::assert;
/// let h = match init(0) {
///     Result::Ok(h) => h,
///     Result::Err(_) => panic "init failed",
/// };
/// assert!(h.update(to_bytes("ab")).is_ok());
/// assert!(h.update(to_bytes("c")).is_ok());
/// let incremental = h.finalize().unwrap_or(Vec::new());
/// assert!(incremental == sha256(to_bytes("abc")).unwrap_or(Vec::new()));
/// assert!(h.finalize().is_err());
/// ```
class Hasher {
    handle: ptr,
    live: bool,
}

// One dload per process. `invoke` takes its function id from a local, so
// each wrapper calls `native()` first and then copies its id out of these.
static let native_lib = 0;
static let fn_sha256 = 0;
static let fn_sha512 = 0;
static let fn_blake3 = 0;
static let fn_hasher_update = 0;
static let fn_hasher_finalize = 0;
static let fn_hasher_free = 0;
static let fn_hmac_sha256 = 0;
static let fn_hmac_sha512 = 0;
static let fn_hmac_verify_sha256 = 0;
static let fn_random_bytes = 0;
static let fn_chacha20_poly1305_encrypt = 0;
static let fn_chacha20_poly1305_decrypt = 0;
static let fn_aes_256_gcm_encrypt = 0;
static let fn_aes_256_gcm_decrypt = 0;
static let fn_ed25519_generate = 0;
static let fn_ed25519_sign = 0;
static let fn_ed25519_verify = 0;
static let fn_x25519_generate = 0;
static let fn_x25519_shared_secret = 0;
static let fn_argon2id_hash = 0;
static let fn_argon2id_verify = 0;
static let fn_ct_eq = 0;

// A missing library or symbol is a build mismatch, as it is for the
// `extern` block, so it panics.
fn bound(Result<int, Error> r) -> int {
    return match r {
        Result::Ok(id) => id,
        Result::Err(e) => panic e.message,
    };
}

// The library handle, declaring every buffer native on first use.
fn native() -> int {
    if native_lib != 0 {
        return native_lib;
    }
    let lib = bound(dload("crypto"));
    fn_sha256 = bound(declare(lib, "coil_crypto_sha256", (ConstBytes, Int, Bytes, Int, Int), Int));
    fn_sha512 = bound(declare(lib, "coil_crypto_sha512", (ConstBytes, Int, Bytes, Int, Int), Int));
    fn_blake3 = bound(declare(lib, "coil_crypto_blake3", (ConstBytes, Int, Bytes, Int, Int), Int));
    fn_hasher_update = bound(declare(lib, "coil_crypto_hasher_update", (Int, ConstBytes, Int, Int), Int));
    fn_hasher_finalize = bound(declare(lib, "coil_crypto_hasher_finalize", (Int, Bytes, Int, Int), Int));
    fn_hasher_free = bound(declare(lib, "coil_crypto_hasher_free", (Int,), Void));
    fn_hmac_sha256 = bound(declare(lib, "coil_crypto_hmac_sha256", (ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_hmac_sha512 = bound(declare(lib, "coil_crypto_hmac_sha512", (ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_hmac_verify_sha256 = bound(declare(lib, "coil_crypto_hmac_verify_sha256", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Int), Int));
    fn_random_bytes = bound(declare(lib, "coil_crypto_random_bytes", (Int, Bytes, Int, Int), Int));
    fn_chacha20_poly1305_encrypt = bound(declare(lib, "coil_crypto_chacha20_poly1305_encrypt", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_chacha20_poly1305_decrypt = bound(declare(lib, "coil_crypto_chacha20_poly1305_decrypt", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_aes_256_gcm_encrypt = bound(declare(lib, "coil_crypto_aes_256_gcm_encrypt", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_aes_256_gcm_decrypt = bound(declare(lib, "coil_crypto_aes_256_gcm_decrypt", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_ed25519_generate = bound(declare(lib, "coil_crypto_ed25519_generate", (Bytes, Bytes, Int), Int));
    fn_ed25519_sign = bound(declare(lib, "coil_crypto_ed25519_sign", (ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_ed25519_verify = bound(declare(lib, "coil_crypto_ed25519_verify", (ConstBytes, Int, ConstBytes, Int, ConstBytes, Int, Int), Int));
    fn_x25519_generate = bound(declare(lib, "coil_crypto_x25519_generate", (Bytes, Bytes, Int), Int));
    fn_x25519_shared_secret = bound(declare(lib, "coil_crypto_x25519_shared_secret", (ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_argon2id_hash = bound(declare(lib, "coil_crypto_argon2id_hash", (ConstBytes, Int, ConstBytes, Int, Bytes, Int, Int), Int));
    fn_argon2id_verify = bound(declare(lib, "coil_crypto_argon2id_verify", (ConstBytes, Int, ConstBytes, Int, Int), Int));
    fn_ct_eq = bound(declare(lib, "coil_crypto_ct_eq", (ConstBytes, Int, ConstBytes, Int), Int));
    native_lib = lib;
    return lib;
}

fn err_ptr() -> ptr {
    return coil_crypto_null();
}

fn err_from(int tag) -> CryptoError {
    if tag == 0 {
        return CryptoError::InvalidInput;
    }
    if tag == 1 {
        return CryptoError::InvalidLength;
    }
    if tag == 2 {
        return CryptoError::AuthenticationFailed;
    }
    if tag == 3 {
        return CryptoError::UnsupportedAlgorithm;
    }
    if tag == 4 {
        return CryptoError::AlreadyFinalized;
    }
    return CryptoError::Other;
}

// A native's return code: the byte count (or 0), or the native's error.
// An FFI failure of the call itself (never expected) is `Other`.
fn checked(Result<int, Error> r) -> Result<int, CryptoError> {
    let rc = match r {
        Result::Ok(v) => v,
        Result::Err(_) => raise CryptoError::Other,
    };
    if rc < 0 {
        raise err_from(coil_crypto_last_error());
    }
    return rc;
}

// `n` zero bytes for a native to write into: a NUL string doubled up to
// `n`, then one copy into a packed `Vec<byte>`, with no per-byte coil loop.
fn buffer(int n) -> Vec<byte> {
    if n <= 0 {
        let empty: Vec<byte> = Vec::new();
        return empty;
    }
    let s = "\0";
    while s.len() < n {
        s = s + s;
    }
    if s.len() > n {
        s = match slice_bytes(s, 0, n) {
            Result::Ok(t) => t,
            Result::Err(_) => panic "slice_bytes of NUL bytes",
        };
    }
    return to_bytes(s);
}

// `out` cut down to the `n` bytes the native wrote.
fn fit(Vec<byte> out, int n) -> Vec<byte> {
    while out.len() > n {
        out.pop();
    }
    return out;
}

fn digest_with(int which, Vec<byte> data, int size) -> Result<Vec<byte>, CryptoError> {
    let lib = native();
    let f = which;
    let out = buffer(size);
    let w = checked(invoke(lib, f, (data, data.len(), out, size, 0)))?;
    return fit(out, w);
}

/// Returns the 32-byte SHA-256 digest of `data`.
///
/// # Examples
///
/// ```
/// use crypto::{sha256};
/// use bytes::{to_hex};
/// use string::{to_bytes};
/// # use tests::assert;
/// let digest = sha256(to_bytes("abc")).unwrap_or(Vec::new());
/// assert!(to_hex(digest) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
/// ```
fn sha256(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_sha256, data, 32)?;
}

/// Returns the 64-byte SHA-512 digest of `data`.
///
/// # Examples
///
/// ```
/// use crypto::{sha512};
/// use string::{to_bytes};
/// # use tests::assert;
/// let digest = sha512(to_bytes("abc")).unwrap_or(Vec::new());
/// assert!(digest.len() == 64);
/// ```
fn sha512(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_sha512, data, 64)?;
}

/// Returns the 32-byte BLAKE3 digest of `data`.
///
/// # Examples
///
/// ```
/// use crypto::{blake3};
/// use bytes::{to_hex};
/// # use tests::assert;
/// let empty: Vec<byte> = [];
/// let digest = blake3(empty).unwrap_or(Vec::new());
/// assert!(to_hex(digest) == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
/// ```
fn blake3(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_blake3, data, 32)?;
}

/// Starts an incremental `Hasher` for algorithm `alg`.
///
/// `alg` is `0` for SHA-256, `1` for SHA-512 and `2` for BLAKE3.
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` for any other `alg`.
///
/// # Examples
///
/// ```
/// use crypto::{init, update, finalize, blake3};
/// use string::{to_bytes};
/// # use tests::assert;
/// let h = match init(2) {
///     Result::Ok(h) => h,
///     Result::Err(_) => panic "init failed",
/// };
/// assert!(update(h, to_bytes("hello")).is_ok());
/// assert!(finalize(h).unwrap_or(Vec::new()) == blake3(to_bytes("hello")).unwrap_or(Vec::new()));
/// assert!(init(9).is_err());
/// ```
fn init(int alg) -> Result<Hasher, CryptoError> {
    let h = coil_crypto_hasher_init(alg, err_ptr());
    if coil_crypto_is_null(h) != 0 {
        raise err_from(coil_crypto_last_error());
    }
    return new Hasher(h, true);
}

impl Hasher {
    fn drop() {
        if self.live {
            let lib = native();
            let f = fn_hasher_free;
            match invoke(lib, f, (self.handle,)) {
                Result::Ok(_) => {},
                Result::Err(_) => {},
            };
            self.live = false;
        }
    }

    /// Feeds `data` into the hash.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AlreadyFinalized` after `finalize`.
    pub fn update(Vec<byte> data) -> Result<(), CryptoError> {
        let lib = native();
        let f = fn_hasher_update;
        checked(invoke(lib, f, (self.handle, data, data.len(), 0)))?;
        return ();
    }

    /// Returns the digest of everything fed so far: 32 bytes for SHA-256 and
    /// BLAKE3, 64 for SHA-512.
    ///
    /// A hasher finalizes once.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AlreadyFinalized` when called a second time.
    pub fn finalize() -> Result<Vec<byte>, CryptoError> {
        let lib = native();
        let f = fn_hasher_finalize;
        let out = buffer(64);
        let w = checked(invoke(lib, f, (self.handle, out, 64, 0)))?;
        return fit(out, w);
    }
}

/// Feeds `data` into `h`; the function form of `Hasher.update`.
///
/// # Errors
///
/// Returns `CryptoError::AlreadyFinalized` after `finalize`.
fn update(Hasher h, Vec<byte> data) -> Result<(), CryptoError> {
    return h.update(data)?;
}

/// Returns the digest of `h`; the function form of `Hasher.finalize`.
///
/// # Errors
///
/// Returns `CryptoError::AlreadyFinalized` when `h` was already finalized.
fn finalize(Hasher h) -> Result<Vec<byte>, CryptoError> {
    return h.finalize()?;
}

fn pair_with(int which, Vec<byte> a, Vec<byte> b, int size) -> Result<Vec<byte>, CryptoError> {
    let lib = native();
    let f = which;
    let out = buffer(size);
    let w = checked(invoke(lib, f, (a, a.len(), b, b.len(), out, size, 0)))?;
    return fit(out, w);
}

/// Returns the 32-byte HMAC-SHA256 tag of `data` under `key`.
///
/// `key` may be any length, including empty.
///
/// # Examples
///
/// ```
/// use crypto::{hmac_sha256, hmac_verify_sha256};
/// use string::{to_bytes};
/// # use tests::assert;
/// let key = to_bytes("secret");
/// let tag = hmac_sha256(key, to_bytes("message")).unwrap_or(Vec::new());
/// assert!(tag.len() == 32);
/// assert!(hmac_verify_sha256(key, to_bytes("message"), tag).is_ok());
/// assert!(hmac_verify_sha256(key, to_bytes("tampered"), tag).is_err());
/// ```
fn hmac_sha256(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_hmac_sha256, key, data, 32)?;
}

/// Returns the 64-byte HMAC-SHA512 tag of `data` under `key`.
///
/// `key` may be any length, including empty.
///
/// # Examples
///
/// ```
/// use crypto::{hmac_sha512};
/// use string::{to_bytes};
/// # use tests::assert;
/// let tag = hmac_sha512(to_bytes("secret"), to_bytes("message")).unwrap_or(Vec::new());
/// assert!(tag.len() == 64);
/// ```
fn hmac_sha512(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_hmac_sha512, key, data, 64)?;
}

/// Checks in constant time that `tag` is the HMAC-SHA256 of `data` under `key`.
///
/// Returns `Ok(true)` on a match; it never returns `Ok(false)`.
///
/// # Errors
///
/// Returns `CryptoError::AuthenticationFailed` when the tag does not match
/// (including a tag of the wrong length).
fn hmac_verify_sha256(Vec<byte> key, Vec<byte> data, Vec<byte> tag) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_hmac_verify_sha256;
    checked(invoke(lib, f, (key, key.len(), data, data.len(), tag, tag.len(), 0)))?;
    return true;
}

/// Returns `n` bytes from the operating system's cryptographically secure
/// random source.
///
/// `n` may be `0` (an empty vector).
///
/// # Errors
///
/// Returns `CryptoError::InvalidInput` when `n` is negative or above 1 MiB
/// (1048576), and `CryptoError::Other` when the OS random source fails.
///
/// # Examples
///
/// ```
/// use crypto::{random_bytes};
/// # use tests::assert;
/// let key = random_bytes(32).unwrap_or(Vec::new());
/// assert!(key.len() == 32);
/// assert!(random_bytes(2000000).is_err());
/// ```
fn random_bytes(int n) -> Result<Vec<byte>, CryptoError> {
    let lib = native();
    let f = fn_random_bytes;
    // Past the native's 1 MiB cap (or below 0, which it reads as a huge
    // u64) it fails with InvalidInput before touching `out`, so do not
    // allocate `n` bytes for it.
    let cap = n;
    if n < 0 || n > 1048576 {
        cap = 0;
    }
    let out = buffer(cap);
    let w = checked(invoke(lib, f, (n, out, cap, 0)))?;
    return fit(out, w);
}

/// Returns 64 random bits from the operating system's cryptographically
/// secure random source.
///
/// Coil `int` is a signed 64-bit integer, so about half of the results are
/// negative.
///
/// # Errors
///
/// Returns `CryptoError::Other` when the OS random source fails.
///
/// # Examples
///
/// ```
/// use crypto::{random_u64};
/// # use tests::assert;
/// let roll = random_u64().unwrap_or(0) & 255;
/// assert!(roll >= 0 && roll < 256);
/// ```
fn random_u64() -> Result<int, CryptoError> {
    let rc = coil_crypto_random_u64(coil_crypto_null(), err_ptr());
    if rc < 0 {
        raise err_from(coil_crypto_last_error());
    }
    return coil_crypto_last_i64();
}

// Seal (`cap` = message + 16) or open (`cap` = message) with one AEAD native.
fn aead_with(int which, Vec<byte> key, Vec<byte> nonce, Vec<byte> msg, Vec<byte> aad, int cap) -> Result<Vec<byte>, CryptoError> {
    let lib = native();
    let f = which;
    let out = buffer(cap);
    let w = checked(invoke(lib, f, (key, key.len(), nonce, nonce.len(), msg, msg.len(), aad, aad.len(), out, cap, 0)))?;
    return fit(out, w);
}

/// Encrypts and authenticates `plaintext` with ChaCha20-Poly1305.
///
/// `key` is 32 bytes and `nonce` 12 bytes; never reuse a nonce with the same
/// key. `aad` is extra data that is authenticated but not encrypted (it may
/// be empty) and must be passed again to decrypt. The result is the
/// ciphertext followed by the 16-byte tag, so it is `plaintext.len() + 16`
/// bytes long.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` for a key or nonce of the wrong size.
///
/// # Examples
///
/// ```
/// use crypto::{chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, random_bytes};
/// use string::{to_bytes};
/// # use tests::assert;
/// let key = random_bytes(32).unwrap_or(Vec::new());
/// let nonce: Vec<byte> = [0 as byte, 1 as byte, 2 as byte, 3 as byte, 4 as byte, 5 as byte,
///     6 as byte, 7 as byte, 8 as byte, 9 as byte, 10 as byte, 11 as byte];
/// let aad = to_bytes("header");
/// let sealed = chacha20_poly1305_encrypt(key, nonce, to_bytes("attack at dawn"), aad).unwrap_or(Vec::new());
/// assert!(sealed.len() == 14 + 16);
/// let opened = chacha20_poly1305_decrypt(key, nonce, sealed, aad).unwrap_or(Vec::new());
/// assert!(opened == to_bytes("attack at dawn"));
/// assert!(chacha20_poly1305_decrypt(key, nonce, sealed, to_bytes("other")).is_err());
/// ```
fn chacha20_poly1305_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_chacha20_poly1305_encrypt, key, nonce, plaintext, aad, plaintext.len() + 16)?;
}

/// Verifies and decrypts `ciphertext` (ciphertext plus 16-byte tag) sealed by
/// `chacha20_poly1305_encrypt` with the same `key`, `nonce` and `aad`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` for a key or nonce of the wrong size,
/// and `CryptoError::AuthenticationFailed` when the ciphertext, tag or `aad`
/// was altered, or the key or nonce differ.
fn chacha20_poly1305_decrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> ciphertext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_chacha20_poly1305_decrypt, key, nonce, ciphertext, aad, ciphertext.len())?;
}

/// Encrypts and authenticates `plaintext` with AES-256-GCM.
///
/// `key` is 32 bytes and `nonce` 12 bytes; never reuse a nonce with the same
/// key. `aad` is authenticated but not encrypted (it may be empty). The
/// result is the ciphertext followed by the 16-byte tag.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` for a key or nonce of the wrong size.
///
/// # Examples
///
/// ```
/// use crypto::{aes_256_gcm_encrypt, aes_256_gcm_decrypt, random_bytes};
/// use string::{to_bytes};
/// # use tests::assert;
/// let key = random_bytes(32).unwrap_or(Vec::new());
/// let nonce: Vec<byte> = [0 as byte, 1 as byte, 2 as byte, 3 as byte, 4 as byte, 5 as byte,
///     6 as byte, 7 as byte, 8 as byte, 9 as byte, 10 as byte, 11 as byte];
/// let empty: Vec<byte> = [];
/// let sealed = aes_256_gcm_encrypt(key, nonce, to_bytes("hi"), empty).unwrap_or(Vec::new());
/// assert!(sealed.len() == 2 + 16);
/// assert!(aes_256_gcm_decrypt(key, nonce, sealed, empty).unwrap_or(Vec::new()) == to_bytes("hi"));
/// ```
fn aes_256_gcm_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_aes_256_gcm_encrypt, key, nonce, plaintext, aad, plaintext.len() + 16)?;
}

/// Verifies and decrypts `ciphertext` (ciphertext plus 16-byte tag) sealed by
/// `aes_256_gcm_encrypt` with the same `key`, `nonce` and `aad`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` for a key or nonce of the wrong size,
/// and `CryptoError::AuthenticationFailed` when the ciphertext, tag or `aad`
/// was altered, or the key or nonce differ.
fn aes_256_gcm_decrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> ciphertext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_aes_256_gcm_decrypt, key, nonce, ciphertext, aad, ciphertext.len())?;
}

fn keypair_with(int which) -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    let lib = native();
    let f = which;
    let secret = buffer(32);
    let public = buffer(32);
    checked(invoke(lib, f, (secret, public, 0)))?;
    return (secret, public);
}

/// Generates a fresh Ed25519 signing key pair as `(secret, public)`, 32 bytes each.
///
/// Keep `secret` private; share `public` with verifiers.
///
/// # Errors
///
/// Returns `CryptoError::Other` when the OS random source fails.
///
/// # Examples
///
/// ```
/// use crypto::{ed25519_generate, ed25519_sign, ed25519_verify};
/// use string::{to_bytes};
/// # use tests::assert;
/// let (secret, public) = match ed25519_generate() {
///     Result::Ok(pair) => pair,
///     Result::Err(_) => panic "keygen failed",
/// };
/// let msg = to_bytes("release v1");
/// let sig = ed25519_sign(secret, msg).unwrap_or(Vec::new());
/// assert!(sig.len() == 64);
/// assert!(ed25519_verify(public, msg, sig).is_ok());
/// assert!(ed25519_verify(public, to_bytes("release v2"), sig).is_err());
/// ```
fn ed25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    native();
    return keypair_with(fn_ed25519_generate)?;
}

/// Signs `msg` with the 32-byte Ed25519 `secret` key and returns the
/// 64-byte signature.
///
/// Signing is deterministic: the same key and message give the same signature.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` when `secret` is not 32 bytes.
fn ed25519_sign(Vec<byte> secret, Vec<byte> msg) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_ed25519_sign, secret, msg, 64)?;
}

/// Checks that `sig` is a valid Ed25519 signature of `msg` by `public_key`.
///
/// Returns `Ok(true)` on success; it never returns `Ok(false)`. Verification
/// is strict (non-canonical signatures and weak keys are rejected).
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` when `public_key` is not 32 bytes or
/// `sig` not 64, `CryptoError::InvalidInput` when `public_key` is not a valid
/// point, and `CryptoError::AuthenticationFailed` when the signature does not verify.
fn ed25519_verify(Vec<byte> public_key, Vec<byte> msg, Vec<byte> sig) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_ed25519_verify;
    checked(invoke(lib, f, (public_key, public_key.len(), msg, msg.len(), sig, sig.len(), 0)))?;
    return true;
}

/// Generates a fresh X25519 key-agreement pair as `(secret, public)`, 32 bytes each.
///
/// # Errors
///
/// Returns `CryptoError::Other` when the OS random source fails.
///
/// # Examples
///
/// ```
/// use crypto::{x25519_generate, x25519_shared_secret};
/// # use tests::assert;
/// let (a_secret, a_public) = match x25519_generate() {
///     Result::Ok(pair) => pair,
///     Result::Err(_) => panic "keygen failed",
/// };
/// let (b_secret, b_public) = match x25519_generate() {
///     Result::Ok(pair) => pair,
///     Result::Err(_) => panic "keygen failed",
/// };
/// let a_shared = x25519_shared_secret(a_secret, b_public).unwrap_or(Vec::new());
/// let b_shared = x25519_shared_secret(b_secret, a_public).unwrap_or(Vec::new());
/// assert!(a_shared.len() == 32 && a_shared == b_shared);
/// ```
fn x25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    native();
    return keypair_with(fn_x25519_generate)?;
}

/// Computes the 32-byte X25519 shared secret of our `secret` key and the
/// peer's `public_key`.
///
/// Both sides get the same value. Run it through a key-derivation step (for
/// example `hmac_sha256`) before using it as a cipher key.
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` when either key is not 32 bytes.
fn x25519_shared_secret(Vec<byte> secret, Vec<byte> public_key) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_x25519_shared_secret, secret, public_key, 32)?;
}

/// Hashes `password` with Argon2id and returns the PHC string
/// (`$argon2id$v=19$m=19456,t=2,p=1$...`) to store.
///
/// Parameters are fixed: 19 MiB of memory, 2 iterations, parallelism 1.
/// `salt` is 1 to 64 bytes; use 16 random bytes from `random_bytes(16)`
/// (shorter salts are zero-padded to 16).
///
/// # Errors
///
/// Returns `CryptoError::InvalidLength` for an empty salt or one longer than
/// 64 bytes.
///
/// # Examples
///
/// ```
/// use crypto::{argon2id_hash, argon2id_verify, random_bytes};
/// use string::{to_bytes};
/// use text::{Searchable};
/// # use tests::assert;
/// let salt = random_bytes(16).unwrap_or(Vec::new());
/// let stored = argon2id_hash(to_bytes("hunter2"), salt).unwrap_or("");
/// assert!(stored.starts_with("$argon2id$"));
/// assert!(argon2id_verify(to_bytes("hunter2"), stored).is_ok());
/// assert!(argon2id_verify(to_bytes("hunter3"), stored).is_err());
/// ```
fn argon2id_hash(Vec<byte> password, Vec<byte> salt) -> Result<string, CryptoError> {
    native();
    let bytes = pair_with(fn_argon2id_hash, password, salt, 512)?;
    return match from_bytes(bytes) {
        Result::Ok(text) => text,
        Result::Err(_) => raise CryptoError::Other,
    };
}

/// Checks `password` against a PHC string from `argon2id_hash`.
///
/// Returns `Ok(true)` on a match; it never returns `Ok(false)`. The cost
/// parameters are read from `hash`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidInput` when `hash` is not a valid PHC string,
/// and `CryptoError::AuthenticationFailed` when the password does not match.
fn argon2id_verify(Vec<byte> password, string hash) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_argon2id_verify;
    // `ConstBytes` lends the PHC string's bytes in place.
    checked(invoke(lib, f, (password, password.len(), hash, hash.len(), 0)))?;
    return true;
}

/// Compares `a` and `b` in constant time and returns `true` when they are equal.
///
/// Use it instead of `==` for secrets such as MAC tags or tokens, so the
/// time taken does not reveal where the first difference is. Inputs of
/// different lengths are unequal.
///
/// # Examples
///
/// ```
/// use crypto::{ct_eq};
/// use string::{to_bytes};
/// # use tests::assert;
/// assert!(ct_eq(to_bytes("token"), to_bytes("token")));
/// assert!(!ct_eq(to_bytes("token"), to_bytes("tokens")));
/// ```
fn ct_eq(Vec<byte> a, Vec<byte> b) -> bool {
    let lib = native();
    let f = fn_ct_eq;
    return match invoke(lib, f, (a, a.len(), b, b.len())) {
        Result::Ok(eq) => eq != 0,
        Result::Err(_) => false,
    };
}
