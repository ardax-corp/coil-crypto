//! C ABI for coil-crypto (`coil_crypto_*`).
//!
//! Port of coil-lang `machine/src/crypto.rs` (CRYPTO_WIRING, 23 ops). Hasher
//! state lives in this cdylib, not on the Coil heap.

mod hasher;

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use getrandom::fill as getrandom_fill;
use hasher::{Hasher, HasherAlg};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

/// Error tags written to `err_out` (same order as userland `CryptoError`).
#[repr(i64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CryptoErrorTag {
    InvalidInput = 0,
    InvalidLength = 1,
    AuthenticationFailed = 2,
    UnsupportedAlgorithm = 3,
    AlreadyFinalized = 4,
    Other = 5,
}

const MAX_RANDOM_BYTES: u64 = 1 << 20;
const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const ARGON2_OUT_CAP: usize = 512;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const RC_ERR: i64 = -1;
const RC_OK: i64 = 0;

unsafe fn write_err(err_out: *mut i64, tag: CryptoErrorTag) {
    if !err_out.is_null() {
        unsafe {
            *err_out = tag as i64;
        }
    }
}

unsafe fn fail(err_out: *mut i64, tag: CryptoErrorTag) -> i64 {
    unsafe { write_err(err_out, tag) };
    RC_ERR
}

unsafe fn in_slice<'a>(ptr: *const u8, len: u64) -> Result<&'a [u8], CryptoErrorTag> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(CryptoErrorTag::InvalidInput);
    }
    let n = usize::try_from(len).map_err(|_| CryptoErrorTag::InvalidInput)?;
    Ok(unsafe { std::slice::from_raw_parts(ptr, n) })
}

unsafe fn out_slice<'a>(ptr: *mut u8, len: u64) -> Result<&'a mut [u8], CryptoErrorTag> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(CryptoErrorTag::InvalidInput);
    }
    let n = usize::try_from(len).map_err(|_| CryptoErrorTag::InvalidInput)?;
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, n) })
}

fn write_bytes(dst: &mut [u8], src: &[u8]) -> Result<i64, CryptoErrorTag> {
    if dst.len() < src.len() {
        return Err(CryptoErrorTag::InvalidLength);
    }
    dst[..src.len()].copy_from_slice(src);
    i64::try_from(src.len()).map_err(|_| CryptoErrorTag::Other)
}

fn from_getrandom(_err: getrandom::Error) -> CryptoErrorTag {
    CryptoErrorTag::Other
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn sha512_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn blake3_bytes(data: &[u8]) -> Vec<u8> {
    blake3::Hasher::new()
        .update(data)
        .finalize()
        .as_bytes()
        .to_vec()
}

unsafe fn digest_call(
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
    f: fn(&[u8]) -> Vec<u8>,
) -> i64 {
    let bytes = match unsafe { in_slice(data, data_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match write_bytes(dst, &f(bytes)) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

/// Packed-buffer helper for Coil FFI marshalling (not a CRYPTO_WIRING name).
#[no_mangle]
pub unsafe extern "C" fn coil_crypto_alloc(n: u64) -> *mut u8 {
    if n == 0 {
        return std::ptr::null_mut();
    }
    let Ok(len) = usize::try_from(n) else {
        return std::ptr::null_mut();
    };
    let mut v = vec![0_u8; len];
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_free(ptr: *mut u8, n: u64) {
    if ptr.is_null() || n == 0 {
        return;
    }
    let Ok(len) = usize::try_from(n) else {
        return;
    };
    drop(unsafe { Vec::from_raw_parts(ptr, len, len) });
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_store_u8(ptr: *mut u8, i: u64, v: i64) {
    if ptr.is_null() {
        return;
    }
    let Ok(idx) = usize::try_from(i) else {
        return;
    };
    unsafe {
        *ptr.add(idx) = v as u8;
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_load_u8(ptr: *const u8, i: u64) -> i64 {
    if ptr.is_null() {
        return 0;
    }
    let Ok(idx) = usize::try_from(i) else {
        return 0;
    };
    unsafe { *ptr.add(idx) as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_sha256(
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe { digest_call(data, data_len, out, out_len, err_out, sha256_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_sha512(
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe { digest_call(data, data_len, out, out_len, err_out, sha512_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_blake3(
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe { digest_call(data, data_len, out, out_len, err_out, blake3_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hasher_init(alg: i64, err_out: *mut i64) -> *mut Hasher {
    let Some(alg) = HasherAlg::from_tag(alg) else {
        unsafe { write_err(err_out, CryptoErrorTag::UnsupportedAlgorithm) };
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(Hasher::new(alg)))
}

unsafe fn hasher_mut<'a>(handle: *mut Hasher) -> Result<&'a mut Hasher, CryptoErrorTag> {
    if handle.is_null() {
        return Err(CryptoErrorTag::InvalidInput);
    }
    Ok(unsafe { &mut *handle })
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hasher_update(
    handle: *mut Hasher,
    data: *const u8,
    data_len: u64,
    err_out: *mut i64,
) -> i64 {
    let hasher = match unsafe { hasher_mut(handle) } {
        Ok(h) => h,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let bytes = match unsafe { in_slice(data, data_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let Some(state) = hasher.state.as_mut() else {
        return unsafe { fail(err_out, CryptoErrorTag::AlreadyFinalized) };
    };
    state.update(bytes);
    RC_OK
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hasher_finalize(
    handle: *mut Hasher,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    let hasher = match unsafe { hasher_mut(handle) } {
        Ok(h) => h,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let state = match hasher.state.take() {
        Some(s) => s,
        None => return unsafe { fail(err_out, CryptoErrorTag::AlreadyFinalized) },
    };
    let digest = state.finalize();
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match write_bytes(dst, &digest) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hasher_free(handle: *mut Hasher) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512_bytes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

unsafe fn hmac_call(
    key: *const u8,
    key_len: u64,
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
    f: fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoErrorTag>,
) -> i64 {
    let key = match unsafe { in_slice(key, key_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let data = match unsafe { in_slice(data, data_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match f(key, data).and_then(|digest| write_bytes(dst, &digest)) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hmac_sha256(
    key: *const u8,
    key_len: u64,
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe { hmac_call(key, key_len, data, data_len, out, out_len, err_out, hmac_sha256_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hmac_sha512(
    key: *const u8,
    key_len: u64,
    data: *const u8,
    data_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe { hmac_call(key, key_len, data, data_len, out, out_len, err_out, hmac_sha512_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_hmac_verify_sha256(
    key: *const u8,
    key_len: u64,
    data: *const u8,
    data_len: u64,
    tag: *const u8,
    tag_len: u64,
    err_out: *mut i64,
) -> i64 {
    let key = match unsafe { in_slice(key, key_len) } {
        Ok(b) => b,
        Err(t) => return unsafe { fail(err_out, t) },
    };
    let data = match unsafe { in_slice(data, data_len) } {
        Ok(b) => b,
        Err(t) => return unsafe { fail(err_out, t) },
    };
    let tag = match unsafe { in_slice(tag, tag_len) } {
        Ok(b) => b,
        Err(t) => return unsafe { fail(err_out, t) },
    };
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) },
    };
    mac.update(data);
    match mac.verify_slice(tag) {
        Ok(()) => RC_OK,
        Err(_) => unsafe { fail(err_out, CryptoErrorTag::AuthenticationFailed) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_random_bytes(
    n: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    if n > MAX_RANDOM_BYTES {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) };
    }
    if n != out_len {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) };
    }
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    if let Err(e) = getrandom_fill(dst) {
        return unsafe { fail(err_out, from_getrandom(e)) };
    }
    i64::try_from(n).unwrap_or(RC_ERR)
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_random_u64(value_out: *mut i64, err_out: *mut i64) -> i64 {
    if value_out.is_null() {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) };
    }
    let mut buf = [0_u8; 8];
    if let Err(e) = getrandom_fill(&mut buf) {
        return unsafe { fail(err_out, from_getrandom(e)) };
    }
    unsafe {
        *value_out = u64::from_le_bytes(buf) as i64;
    }
    RC_OK
}

fn aead_chacha_encrypt(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    if key.len() != AEAD_KEY_LEN || nonce.len() != AEAD_NONCE_LEN {
        return Err(CryptoErrorTag::InvalidLength);
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidInput)?;
    let nonce: ChaChaNonce = nonce
        .try_into()
        .map_err(|_| CryptoErrorTag::InvalidLength)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: pt,
                aad,
            },
        )
        .map_err(|_| CryptoErrorTag::Other)
}

fn aead_chacha_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    if key.len() != AEAD_KEY_LEN || nonce.len() != AEAD_NONCE_LEN {
        return Err(CryptoErrorTag::InvalidLength);
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidInput)?;
    let nonce: ChaChaNonce = nonce
        .try_into()
        .map_err(|_| CryptoErrorTag::InvalidLength)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| CryptoErrorTag::AuthenticationFailed)
}

fn aead_aes_encrypt(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    if key.len() != AEAD_KEY_LEN || nonce.len() != AEAD_NONCE_LEN {
        return Err(CryptoErrorTag::InvalidLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidInput)?;
    let nonce_bytes: [u8; AEAD_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoErrorTag::InvalidLength)?;
    let nonce = AesNonce::from(nonce_bytes);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: pt,
                aad,
            },
        )
        .map_err(|_| CryptoErrorTag::Other)
}

fn aead_aes_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoErrorTag> {
    if key.len() != AEAD_KEY_LEN || nonce.len() != AEAD_NONCE_LEN {
        return Err(CryptoErrorTag::InvalidLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoErrorTag::InvalidInput)?;
    let nonce_bytes: [u8; AEAD_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoErrorTag::InvalidLength)?;
    let nonce = AesNonce::from(nonce_bytes);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| CryptoErrorTag::AuthenticationFailed)
}

unsafe fn aead_call(
    key: *const u8,
    key_len: u64,
    nonce: *const u8,
    nonce_len: u64,
    msg: *const u8,
    msg_len: u64,
    aad: *const u8,
    aad_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
    f: fn(&[u8], &[u8], &[u8], &[u8]) -> Result<Vec<u8>, CryptoErrorTag>,
) -> i64 {
    let key = match unsafe { in_slice(key, key_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let nonce = match unsafe { in_slice(nonce, nonce_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let msg = match unsafe { in_slice(msg, msg_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let aad = match unsafe { in_slice(aad, aad_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match f(key, nonce, msg, aad).and_then(|bytes| write_bytes(dst, &bytes)) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_chacha20_poly1305_encrypt(
    key: *const u8,
    key_len: u64,
    nonce: *const u8,
    nonce_len: u64,
    plaintext: *const u8,
    plaintext_len: u64,
    aad: *const u8,
    aad_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe {
        aead_call(
            key,
            key_len,
            nonce,
            nonce_len,
            plaintext,
            plaintext_len,
            aad,
            aad_len,
            out,
            out_len,
            err_out,
            aead_chacha_encrypt,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_chacha20_poly1305_decrypt(
    key: *const u8,
    key_len: u64,
    nonce: *const u8,
    nonce_len: u64,
    ciphertext: *const u8,
    ciphertext_len: u64,
    aad: *const u8,
    aad_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe {
        aead_call(
            key,
            key_len,
            nonce,
            nonce_len,
            ciphertext,
            ciphertext_len,
            aad,
            aad_len,
            out,
            out_len,
            err_out,
            aead_chacha_decrypt,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_aes_256_gcm_encrypt(
    key: *const u8,
    key_len: u64,
    nonce: *const u8,
    nonce_len: u64,
    plaintext: *const u8,
    plaintext_len: u64,
    aad: *const u8,
    aad_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe {
        aead_call(
            key,
            key_len,
            nonce,
            nonce_len,
            plaintext,
            plaintext_len,
            aad,
            aad_len,
            out,
            out_len,
            err_out,
            aead_aes_encrypt,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_aes_256_gcm_decrypt(
    key: *const u8,
    key_len: u64,
    nonce: *const u8,
    nonce_len: u64,
    ciphertext: *const u8,
    ciphertext_len: u64,
    aad: *const u8,
    aad_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    unsafe {
        aead_call(
            key,
            key_len,
            nonce,
            nonce_len,
            ciphertext,
            ciphertext_len,
            aad,
            aad_len,
            out,
            out_len,
            err_out,
            aead_aes_decrypt,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_ed25519_generate(
    secret_out: *mut u8,
    public_out: *mut u8,
    err_out: *mut i64,
) -> i64 {
    let sk = match unsafe { out_slice(secret_out, 32) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let pk = match unsafe { out_slice(public_out, 32) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let mut seed = [0_u8; 32];
    if let Err(e) = getrandom_fill(&mut seed) {
        return unsafe { fail(err_out, from_getrandom(e)) };
    }
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let verifying: VerifyingKey = signing.verifying_key();
    sk.copy_from_slice(signing.as_bytes());
    pk.copy_from_slice(verifying.as_bytes());
    RC_OK
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_ed25519_sign(
    secret: *const u8,
    secret_len: u64,
    msg: *const u8,
    msg_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    let sk_bytes = match unsafe { in_slice(secret, secret_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    if sk_bytes.len() != 32 {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) };
    }
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(sk_bytes);
    let signing = SigningKey::from_bytes(&arr);
    arr.zeroize();
    let msg = match unsafe { in_slice(msg, msg_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let sig = signing.sign(msg);
    match write_bytes(dst, &sig.to_bytes()) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_ed25519_verify(
    public: *const u8,
    public_len: u64,
    msg: *const u8,
    msg_len: u64,
    sig: *const u8,
    sig_len: u64,
    err_out: *mut i64,
) -> i64 {
    let pk_bytes = match unsafe { in_slice(public, public_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let msg = match unsafe { in_slice(msg, msg_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let sig_bytes = match unsafe { in_slice(sig, sig_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) };
    }
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) },
    };
    let verifying = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) },
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) },
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    match verifying.verify_strict(msg, &sig) {
        Ok(()) => RC_OK,
        Err(_) => unsafe { fail(err_out, CryptoErrorTag::AuthenticationFailed) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_x25519_generate(
    secret_out: *mut u8,
    public_out: *mut u8,
    err_out: *mut i64,
) -> i64 {
    let sk_out = match unsafe { out_slice(secret_out, 32) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let pk_out = match unsafe { out_slice(public_out, 32) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let mut sk = [0_u8; 32];
    if let Err(e) = getrandom_fill(&mut sk) {
        return unsafe { fail(err_out, from_getrandom(e)) };
    }
    let secret = X25519Secret::from(sk);
    sk.zeroize();
    let public = X25519Public::from(&secret);
    sk_out.copy_from_slice(secret.as_bytes());
    pk_out.copy_from_slice(public.as_bytes());
    RC_OK
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_x25519_shared_secret(
    secret: *const u8,
    secret_len: u64,
    public: *const u8,
    public_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    let sk_bytes = match unsafe { in_slice(secret, secret_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let pk_bytes = match unsafe { in_slice(public, public_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    if sk_bytes.len() != 32 || pk_bytes.len() != 32 {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) };
    }
    let sk_arr: [u8; 32] = match sk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) },
    };
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) },
    };
    let secret = X25519Secret::from(sk_arr);
    let public = X25519Public::from(pk_arr);
    let shared = secret.diffie_hellman(&public);
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match write_bytes(dst, shared.as_bytes()) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

fn base64_salt(salt: &[u8]) -> Result<SaltString, CryptoErrorTag> {
    if salt.len() >= 16 {
        SaltString::encode_b64(salt).map_err(|_| CryptoErrorTag::InvalidInput)
    } else {
        let mut padded = salt.to_vec();
        padded.resize(16, 0);
        SaltString::encode_b64(&padded).map_err(|_| CryptoErrorTag::InvalidInput)
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_argon2id_hash(
    password: *const u8,
    password_len: u64,
    salt: *const u8,
    salt_len: u64,
    out: *mut u8,
    out_len: u64,
    err_out: *mut i64,
) -> i64 {
    let password = match unsafe { in_slice(password, password_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let salt = match unsafe { in_slice(salt, salt_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    if salt.is_empty() || salt.len() > 64 {
        return unsafe { fail(err_out, CryptoErrorTag::InvalidLength) };
    }
    let salt_b64 = match base64_salt(salt) {
        Ok(s) => s,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let params = match Params::new(19 * 1024, 2, 1, None) {
        Ok(p) => p,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) },
    };
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let hash = match argon2.hash_password(password, &salt_b64) {
        Ok(h) => h,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::Other) },
    };
    let encoded = hash.to_string();
    let dst = match unsafe { out_slice(out, out_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    match write_bytes(dst, encoded.as_bytes()) {
        Ok(n) => n,
        Err(tag) => unsafe { fail(err_out, tag) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_argon2id_verify(
    password: *const u8,
    password_len: u64,
    hash: *const u8,
    hash_len: u64,
    err_out: *mut i64,
) -> i64 {
    let password = match unsafe { in_slice(password, password_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let hash_bytes = match unsafe { in_slice(hash, hash_len) } {
        Ok(b) => b,
        Err(tag) => return unsafe { fail(err_out, tag) },
    };
    let hash_str = match std::str::from_utf8(hash_bytes) {
        Ok(s) => s,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) },
    };
    let parsed = match PasswordHash::new(hash_str) {
        Ok(p) => p,
        Err(_) => return unsafe { fail(err_out, CryptoErrorTag::InvalidInput) },
    };
    match Argon2::default().verify_password(password, &parsed) {
        Ok(()) => RC_OK,
        Err(_) => unsafe { fail(err_out, CryptoErrorTag::AuthenticationFailed) },
    }
}

#[no_mangle]
pub unsafe extern "C" fn coil_crypto_ct_eq(
    a: *const u8,
    a_len: u64,
    b: *const u8,
    b_len: u64,
) -> i64 {
    let a = match unsafe { in_slice(a, a_len) } {
        Ok(x) => x,
        Err(_) => return 0,
    };
    let b = match unsafe { in_slice(b, b_len) } {
        Ok(y) => y,
        Err(_) => return 0,
    };
    if a.ct_eq(b).into() {
        1
    } else {
        0
    }
}

/// Compile-time reminder: keep the ARGON2 out buffer large enough for PHC strings.
#[allow(dead_code)]
const _: () = assert!(ARGON2_OUT_CAP >= 128);

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn err_slot() -> i64 {
        0
    }

    /// NIST SHA-256 KAT: empty string.
    #[test]
    fn sha256_empty_string_kat() {
        let mut out = [0_u8; 32];
        let mut err = unsafe { err_slot() };
        let n = unsafe {
            coil_crypto_sha256(std::ptr::null(), 0, out.as_mut_ptr(), 32, &mut err)
        };
        assert!(n >= 0, "sha256 failed tag={err}");
        const EXPECTED: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(&out[..n as usize], EXPECTED);
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip_and_tamper_fails() {
        let key = [0x11_u8; 32];
        let nonce = [0x22_u8; 12];
        let pt = b"coil-aead";
        let aad: [u8; 0] = [];
        let mut ct = vec![0_u8; pt.len() + 16];
        let mut err = 0_i64;
        let n = unsafe {
            coil_crypto_chacha20_poly1305_encrypt(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                pt.as_ptr(),
                pt.len() as u64,
                aad.as_ptr(),
                0,
                ct.as_mut_ptr(),
                ct.len() as u64,
                &mut err,
            )
        };
        assert!(n > pt.len() as i64, "ciphertext includes auth tag, got {n} err={err}");
        ct.truncate(n as usize);

        let mut recovered = vec![0_u8; pt.len()];
        let pn = unsafe {
            coil_crypto_chacha20_poly1305_decrypt(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                ct.as_ptr(),
                ct.len() as u64,
                aad.as_ptr(),
                0,
                recovered.as_mut_ptr(),
                recovered.len() as u64,
                &mut err,
            )
        };
        assert!(pn >= 0, "decrypt failed tag={err}");
        assert_eq!(&recovered[..pn as usize], pt);

        let mut tampered = ct;
        *tampered.last_mut().unwrap() ^= 0x01;
        let mut bad = vec![0_u8; pt.len()];
        err = 0;
        let fail_rc = unsafe {
            coil_crypto_chacha20_poly1305_decrypt(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                tampered.as_ptr(),
                tampered.len() as u64,
                aad.as_ptr(),
                0,
                bad.as_mut_ptr(),
                bad.len() as u64,
                &mut err,
            )
        };
        assert_eq!(fail_rc, RC_ERR);
        assert_eq!(err, CryptoErrorTag::AuthenticationFailed as i64);
    }

    #[test]
    fn hasher_finalize_twice_returns_already_finalized() {
        let mut err = 0_i64;
        let handle = unsafe { coil_crypto_hasher_init(0, &mut err) };
        assert!(!handle.is_null(), "init failed tag={err}");

        let data = b"abc";
        let upd = unsafe {
            coil_crypto_hasher_update(handle, data.as_ptr(), data.len() as u64, &mut err)
        };
        assert_eq!(upd, RC_OK, "update should succeed tag={err}");

        let mut digest = [0_u8; 32];
        let n = unsafe {
            coil_crypto_hasher_finalize(handle, digest.as_mut_ptr(), 32, &mut err)
        };
        assert!(n >= 0, "finalize failed tag={err}");
        const EXPECTED: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(&digest[..n as usize], EXPECTED);

        err = 0;
        let again = unsafe {
            coil_crypto_hasher_finalize(handle, digest.as_mut_ptr(), 32, &mut err)
        };
        assert_eq!(again, RC_ERR);
        assert_eq!(err, CryptoErrorTag::AlreadyFinalized as i64);

        unsafe { coil_crypto_hasher_free(handle) };
    }
}
