// Userland crypto — FFI to native/libcrypto.{so,dylib,dll} (dload("crypto")).
// Surface names match CRYPTO_WIRING. Hasher state lives in the .so.

use string::{from_bytes, to_bytes};

extern "crypto" {
    fn coil_crypto_alloc(int n) -> ptr;
    fn coil_crypto_free(ptr p, int n);
    fn coil_crypto_store_u8(ptr p, int i, int v);
    fn coil_crypto_load_u8(ptr p, int i) -> int;

    fn coil_crypto_sha256(ptr data, int data_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_sha512(ptr data, int data_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_blake3(ptr data, int data_len, ptr out, int out_len, ptr err_out) -> int;

    fn coil_crypto_hasher_init(int alg, ptr err_out) -> ptr;
    fn coil_crypto_hasher_update(ptr handle, ptr data, int data_len, ptr err_out) -> int;
    fn coil_crypto_hasher_finalize(ptr handle, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_hasher_free(ptr handle);

    fn coil_crypto_hmac_sha256(ptr key, int key_len, ptr data, int data_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_hmac_sha512(ptr key, int key_len, ptr data, int data_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_hmac_verify_sha256(ptr key, int key_len, ptr data, int data_len, ptr tag, int tag_len, ptr err_out) -> int;

    fn coil_crypto_random_bytes(int n, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_random_u64(ptr value_out, ptr err_out) -> int;

    fn coil_crypto_chacha20_poly1305_encrypt(ptr key, int key_len, ptr nonce, int nonce_len, ptr plaintext, int plaintext_len, ptr aad, int aad_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_chacha20_poly1305_decrypt(ptr key, int key_len, ptr nonce, int nonce_len, ptr ciphertext, int ciphertext_len, ptr aad, int aad_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_aes_256_gcm_encrypt(ptr key, int key_len, ptr nonce, int nonce_len, ptr plaintext, int plaintext_len, ptr aad, int aad_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_aes_256_gcm_decrypt(ptr key, int key_len, ptr nonce, int nonce_len, ptr ciphertext, int ciphertext_len, ptr aad, int aad_len, ptr out, int out_len, ptr err_out) -> int;

    fn coil_crypto_ed25519_generate(ptr secret_out, ptr public_out, ptr err_out) -> int;
    fn coil_crypto_ed25519_sign(ptr secret, int secret_len, ptr msg, int msg_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_ed25519_verify(ptr public_key, int public_len, ptr msg, int msg_len, ptr sig, int sig_len, ptr err_out) -> int;

    fn coil_crypto_x25519_generate(ptr secret_out, ptr public_out, ptr err_out) -> int;
    fn coil_crypto_x25519_shared_secret(ptr secret, int secret_len, ptr public_key, int public_len, ptr out, int out_len, ptr err_out) -> int;

    fn coil_crypto_argon2id_hash(ptr password, int password_len, ptr salt, int salt_len, ptr out, int out_len, ptr err_out) -> int;
    fn coil_crypto_argon2id_verify(ptr password, int password_len, ptr hash, int hash_len, ptr err_out) -> int;

    fn coil_crypto_ct_eq(ptr a, int a_len, ptr b, int b_len) -> int;
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

fn copy_in(Vec<byte> data) -> ptr {
    let n = len(data);
    let p = coil_crypto_alloc(n);
    let i = 0;
    while i < n {
        coil_crypto_store_u8(p, i, data[i] as int);
        i = i + 1;
    }
    return p;
}

fn copy_out(ptr p, int n) -> Vec<byte> {
    let out: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        out.push(coil_crypto_load_u8(p, i) as byte);
        i = i + 1;
    }
    return out;
}

fn finish_digest(ptr src, int src_n, ptr out, int cap, int rc, int tag) -> Result<Vec<byte>, CryptoError> {
    let n = rc;
    if rc < 0 {
        n = 0;
    }
    let bytes = copy_out(out, n);
    coil_crypto_free(src, src_n);
    coil_crypto_free(out, cap);
    if rc < 0 {
        raise err_from(tag);
    }
    return bytes;
}

fn sha256(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    let n = len(data);
    let src = copy_in(data);
    let out = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_sha256(src, n, out, 32, err);
    return finish_digest(src, n, out, 32, rc, err[0])?;
}

fn sha512(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    let n = len(data);
    let src = copy_in(data);
    let out = coil_crypto_alloc(64);
    let err = [0];
    let rc = coil_crypto_sha512(src, n, out, 64, err);
    return finish_digest(src, n, out, 64, rc, err[0])?;
}

fn blake3(Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    let n = len(data);
    let src = copy_in(data);
    let out = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_blake3(src, n, out, 32, err);
    return finish_digest(src, n, out, 32, rc, err[0])?;
}

fn init(int alg) -> Result<Hasher, CryptoError> {
    let err = [0];
    err[0] = -1;
    let h = coil_crypto_hasher_init(alg, err);
    if err[0] != -1 {
        raise err_from(err[0]);
    }
    return new Hasher(h, true);
}

fn update(Hasher h, Vec<byte> data) -> Result<(), CryptoError> {
    let n = len(data);
    let src = copy_in(data);
    let err = [0];
    let rc = coil_crypto_hasher_update(h.handle, src, n, err);
    coil_crypto_free(src, n);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return ();
}

fn finalize(Hasher h) -> Result<Vec<byte>, CryptoError> {
    let out = coil_crypto_alloc(64);
    let err = [0];
    let rc = coil_crypto_hasher_finalize(h.handle, out, 64, err);
    let n = rc;
    if rc < 0 {
        n = 0;
    }
    let bytes = copy_out(out, n);
    coil_crypto_free(out, 64);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

impl Hasher {
    fn drop() {
        if self.live {
            coil_crypto_hasher_free(self.handle);
            self.live = false;
        }
    }
}

fn hmac_sha256(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let dn = len(data);
    let k = copy_in(key);
    let d = copy_in(data);
    let out = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_hmac_sha256(k, kn, d, dn, out, 32, err);
    let n = rc;
    if rc < 0 {
        n = 0;
    }
    let bytes = copy_out(out, n);
    coil_crypto_free(k, kn);
    coil_crypto_free(d, dn);
    coil_crypto_free(out, 32);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

fn hmac_sha512(Vec<byte> key, Vec<byte> data) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let dn = len(data);
    let k = copy_in(key);
    let d = copy_in(data);
    let out = coil_crypto_alloc(64);
    let err = [0];
    let rc = coil_crypto_hmac_sha512(k, kn, d, dn, out, 64, err);
    let n = rc;
    if rc < 0 {
        n = 0;
    }
    let bytes = copy_out(out, n);
    coil_crypto_free(k, kn);
    coil_crypto_free(d, dn);
    coil_crypto_free(out, 64);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

fn hmac_verify_sha256(Vec<byte> key, Vec<byte> data, Vec<byte> tag) -> Result<bool, CryptoError> {
    let kn = len(key);
    let dn = len(data);
    let tn = len(tag);
    let k = copy_in(key);
    let d = copy_in(data);
    let t = copy_in(tag);
    let err = [0];
    let rc = coil_crypto_hmac_verify_sha256(k, kn, d, dn, t, tn, err);
    coil_crypto_free(k, kn);
    coil_crypto_free(d, dn);
    coil_crypto_free(t, tn);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return true;
}

fn random_bytes(int n) -> Result<Vec<byte>, CryptoError> {
    let out = coil_crypto_alloc(n);
    let err = [0];
    let rc = coil_crypto_random_bytes(n, out, n, err);
    let w = rc;
    if rc < 0 {
        w = 0;
    }
    let bytes = copy_out(out, w);
    coil_crypto_free(out, n);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

fn random_u64() -> Result<int, CryptoError> {
    let slot = [0];
    let err = [0];
    let rc = coil_crypto_random_u64(slot, err);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return slot[0];
}

fn aead_run(ptr key, int kn, ptr nonce, int nn, ptr msg, int mn, ptr aad, int an, ptr out, int cap, int rc, int tag) -> Result<Vec<byte>, CryptoError> {
    let w = rc;
    if rc < 0 {
        w = 0;
    }
    let bytes = copy_out(out, w);
    coil_crypto_free(key, kn);
    coil_crypto_free(nonce, nn);
    coil_crypto_free(msg, mn);
    coil_crypto_free(aad, an);
    coil_crypto_free(out, cap);
    if rc < 0 {
        raise err_from(tag);
    }
    return bytes;
}

fn chacha20_poly1305_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let nn = len(nonce);
    let mn = len(plaintext);
    let an = len(aad);
    let k = copy_in(key);
    let n = copy_in(nonce);
    let m = copy_in(plaintext);
    let a = copy_in(aad);
    let cap = mn + 16;
    let out = coil_crypto_alloc(cap);
    let err = [0];
    let rc = coil_crypto_chacha20_poly1305_encrypt(k, kn, n, nn, m, mn, a, an, out, cap, err);
    return aead_run(k, kn, n, nn, m, mn, a, an, out, cap, rc, err[0])?;
}

fn chacha20_poly1305_decrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> ciphertext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let nn = len(nonce);
    let mn = len(ciphertext);
    let an = len(aad);
    let k = copy_in(key);
    let n = copy_in(nonce);
    let m = copy_in(ciphertext);
    let a = copy_in(aad);
    let cap = mn;
    let out = coil_crypto_alloc(cap);
    let err = [0];
    let rc = coil_crypto_chacha20_poly1305_decrypt(k, kn, n, nn, m, mn, a, an, out, cap, err);
    return aead_run(k, kn, n, nn, m, mn, a, an, out, cap, rc, err[0])?;
}

fn aes_256_gcm_encrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> plaintext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let nn = len(nonce);
    let mn = len(plaintext);
    let an = len(aad);
    let k = copy_in(key);
    let n = copy_in(nonce);
    let m = copy_in(plaintext);
    let a = copy_in(aad);
    let cap = mn + 16;
    let out = coil_crypto_alloc(cap);
    let err = [0];
    let rc = coil_crypto_aes_256_gcm_encrypt(k, kn, n, nn, m, mn, a, an, out, cap, err);
    return aead_run(k, kn, n, nn, m, mn, a, an, out, cap, rc, err[0])?;
}

fn aes_256_gcm_decrypt(Vec<byte> key, Vec<byte> nonce, Vec<byte> ciphertext, Vec<byte> aad) -> Result<Vec<byte>, CryptoError> {
    let kn = len(key);
    let nn = len(nonce);
    let mn = len(ciphertext);
    let an = len(aad);
    let k = copy_in(key);
    let n = copy_in(nonce);
    let m = copy_in(ciphertext);
    let a = copy_in(aad);
    let cap = mn;
    let out = coil_crypto_alloc(cap);
    let err = [0];
    let rc = coil_crypto_aes_256_gcm_decrypt(k, kn, n, nn, m, mn, a, an, out, cap, err);
    return aead_run(k, kn, n, nn, m, mn, a, an, out, cap, rc, err[0])?;
}

fn keypair_from(ptr sk, ptr pk, int rc, int tag) -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    let secret = copy_out(sk, 32);
    let public = copy_out(pk, 32);
    coil_crypto_free(sk, 32);
    coil_crypto_free(pk, 32);
    if rc < 0 {
        raise err_from(tag);
    }
    return (secret, public);
}

fn ed25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    let sk = coil_crypto_alloc(32);
    let pk = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_ed25519_generate(sk, pk, err);
    return keypair_from(sk, pk, rc, err[0])?;
}

fn ed25519_sign(Vec<byte> secret, Vec<byte> msg) -> Result<Vec<byte>, CryptoError> {
    let sn = len(secret);
    let mn = len(msg);
    let s = copy_in(secret);
    let m = copy_in(msg);
    let out = coil_crypto_alloc(64);
    let err = [0];
    let rc = coil_crypto_ed25519_sign(s, sn, m, mn, out, 64, err);
    let w = rc;
    if rc < 0 {
        w = 0;
    }
    let bytes = copy_out(out, w);
    coil_crypto_free(s, sn);
    coil_crypto_free(m, mn);
    coil_crypto_free(out, 64);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

fn ed25519_verify(Vec<byte> public_key, Vec<byte> msg, Vec<byte> sig) -> Result<bool, CryptoError> {
    let pn = len(public_key);
    let mn = len(msg);
    let sn = len(sig);
    let p = copy_in(public_key);
    let m = copy_in(msg);
    let s = copy_in(sig);
    let err = [0];
    let rc = coil_crypto_ed25519_verify(p, pn, m, mn, s, sn, err);
    coil_crypto_free(p, pn);
    coil_crypto_free(m, mn);
    coil_crypto_free(s, sn);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return true;
}

fn x25519_generate() -> Result<(Vec<byte>, Vec<byte>), CryptoError> {
    let sk = coil_crypto_alloc(32);
    let pk = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_x25519_generate(sk, pk, err);
    return keypair_from(sk, pk, rc, err[0])?;
}

fn x25519_shared_secret(Vec<byte> secret, Vec<byte> public_key) -> Result<Vec<byte>, CryptoError> {
    let sn = len(secret);
    let pn = len(public_key);
    let s = copy_in(secret);
    let p = copy_in(public_key);
    let out = coil_crypto_alloc(32);
    let err = [0];
    let rc = coil_crypto_x25519_shared_secret(s, sn, p, pn, out, 32, err);
    let w = rc;
    if rc < 0 {
        w = 0;
    }
    let bytes = copy_out(out, w);
    coil_crypto_free(s, sn);
    coil_crypto_free(p, pn);
    coil_crypto_free(out, 32);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return bytes;
}

fn argon2id_hash(Vec<byte> password, Vec<byte> salt) -> Result<string, CryptoError> {
    let pn = len(password);
    let sn = len(salt);
    let p = copy_in(password);
    let s = copy_in(salt);
    let cap = 512;
    let out = coil_crypto_alloc(cap);
    let err = [0];
    let rc = coil_crypto_argon2id_hash(p, pn, s, sn, out, cap, err);
    let w = rc;
    if rc < 0 {
        w = 0;
    }
    let bytes = copy_out(out, w);
    coil_crypto_free(p, pn);
    coil_crypto_free(s, sn);
    coil_crypto_free(out, cap);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return match from_bytes(bytes) {
        Result::Ok(text) => text,
        Result::Err(_) => raise CryptoError::Other,
    };
}

fn argon2id_verify(Vec<byte> password, string hash) -> Result<bool, CryptoError> {
    let pn = len(password);
    let p = copy_in(password);
    let hb = to_bytes(hash);
    let hn = len(hb);
    let h = copy_in(hb);
    let err = [0];
    let rc = coil_crypto_argon2id_verify(p, pn, h, hn, err);
    coil_crypto_free(p, pn);
    coil_crypto_free(h, hn);
    if rc < 0 {
        raise err_from(err[0]);
    }
    return true;
}

fn ct_eq(Vec<byte> a, Vec<byte> b) -> bool {
    let an = len(a);
    let bn = len(b);
    let pa = copy_in(a);
    let pb = copy_in(b);
    let eq = coil_crypto_ct_eq(pa, an, pb, bn);
    coil_crypto_free(pa, an);
    coil_crypto_free(pb, bn);
    return eq != 0;
}
