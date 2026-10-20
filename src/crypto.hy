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

enum CryptoError {
    InvalidInput,
    InvalidLength,
    AuthenticationFailed,
    UnsupportedAlgorithm,
    AlreadyFinalized,
    Other,
}

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

/// A missing library or symbol is a build mismatch, as it is for the
/// `extern` block, so it panics.
fn bound(Result<int, Error> r) -> int {
    return match r {
        Result::Ok(id) => id,
        Result::Err(e) => panic e.message,
    };
}

/// The library handle, declaring every buffer native on first use.
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

/// A native's return code: the byte count (or 0), or the native's error.
/// An FFI failure of the call itself (never expected) is `Other`.
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

/// `n` zero bytes for a native to write into: a NUL string doubled up to
/// `n`, then one copy into a packed `Vec<byte>`, with no per-byte coil loop.
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

/// `out` cut down to the `n` bytes the native wrote.
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

fn sha256(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_sha256, data, 32)?;
}

fn sha512(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_sha512, data, 64)?;
}

fn blake3(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return digest_with(fn_blake3, data, 32)?;
}

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

    pub fn update(Vec<byte> data) -> Result<(), CryptoError> {
        let lib = native();
        let f = fn_hasher_update;
        checked(invoke(lib, f, (self.handle, data, data.len(), 0)))?;
        return ();
    }

    pub fn finalize() -> Result<Vec<byte>, CryptoError> {
        let lib = native();
        let f = fn_hasher_finalize;
        let out = buffer(64);
        let w = checked(invoke(lib, f, (self.handle, out, 64, 0)))?;
        return fit(out, w);
    }
}

fn update(Hasher h, Vec<byte> data) -> Result<(), CryptoError> {
    return h.update(data)?;
}

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

fn hmac_sha256(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_hmac_sha256, key, data, 32)?;
}

fn hmac_sha512(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_hmac_sha512, key, data, 64)?;
}

fn hmac_verify_sha256(Vec<byte> key, Vec<byte> data, Vec<byte> tag) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_hmac_verify_sha256;
    checked(invoke(lib, f, (key, key.len(), data, data.len(), tag, tag.len(), 0)))?;
    return true;
}

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

fn random_u64() -> Result<int, CryptoError> {
    let rc = coil_crypto_random_u64(coil_crypto_null(), err_ptr());
    if rc < 0 {
        raise err_from(coil_crypto_last_error());
    }
    return coil_crypto_last_i64();
}

/// Seal (`cap` = message + 16) or open (`cap` = message) with one AEAD native.
fn aead_with(int which, Vec<byte> key, Vec<byte> nonce, Vec<byte> msg, Vec<byte> aad, int cap) -> Result<Vec<byte>, CryptoError> {
    let lib = native();
    let f = which;
    let out = buffer(cap);
    let w = checked(invoke(lib, f, (key, key.len(), nonce, nonce.len(), msg, msg.len(), aad, aad.len(), out, cap, 0)))?;
    return fit(out, w);
}

fn chacha20_poly1305_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_chacha20_poly1305_encrypt, key, nonce, plaintext, aad, plaintext.len() + 16)?;
}

fn chacha20_poly1305_decrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> ciphertext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_chacha20_poly1305_decrypt, key, nonce, ciphertext, aad, ciphertext.len())?;
}

fn aes_256_gcm_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    native();
    return aead_with(fn_aes_256_gcm_encrypt, key, nonce, plaintext, aad, plaintext.len() + 16)?;
}

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

fn ed25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    native();
    return keypair_with(fn_ed25519_generate)?;
}

fn ed25519_sign(Vec<byte> secret, Vec<byte> msg) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_ed25519_sign, secret, msg, 64)?;
}

fn ed25519_verify(Vec<byte> public_key, Vec<byte> msg, Vec<byte> sig) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_ed25519_verify;
    checked(invoke(lib, f, (public_key, public_key.len(), msg, msg.len(), sig, sig.len(), 0)))?;
    return true;
}

fn x25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    native();
    return keypair_with(fn_x25519_generate)?;
}

fn x25519_shared_secret(Vec<byte> secret, Vec<byte> public_key) -> Result<Vec<byte>, CryptoError> {
    native();
    return pair_with(fn_x25519_shared_secret, secret, public_key, 32)?;
}

fn argon2id_hash(Vec<byte> password, Vec<byte> salt) -> Result<string, CryptoError> {
    native();
    let bytes = pair_with(fn_argon2id_hash, password, salt, 512)?;
    return match from_bytes(bytes) {
        Result::Ok(text) => text,
        Result::Err(_) => raise CryptoError::Other,
    };
}

fn argon2id_verify(Vec<byte> password, string hash) -> Result<bool, CryptoError> {
    let lib = native();
    let f = fn_argon2id_verify;
    // `ConstBytes` lends the PHC string's bytes in place.
    checked(invoke(lib, f, (password, password.len(), hash, hash.len(), 0)))?;
    return true;
}

fn ct_eq(Vec<byte> a, Vec<byte> b) -> bool {
    let lib = native();
    let f = fn_ct_eq;
    return match invoke(lib, f, (a, a.len(), b, b.len())) {
        Result::Ok(eq) => eq != 0,
        Result::Err(_) => false,
    };
}
