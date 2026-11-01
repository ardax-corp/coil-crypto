// 1,000,000-byte inputs ("a" repeated, the FIPS 180 long-message vector)
// through every wrapper that takes bytes. Expected values come from Python
// hashlib / cryptography and the Rust blake3 crate.
use tests::assert;
use crypto::{sha256, sha512, blake3, init, update, finalize, Hasher, hmac_sha256, hmac_verify_sha256, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, aes_256_gcm_encrypt, aes_256_gcm_decrypt, ed25519_generate, ed25519_sign, ed25519_verify, random_bytes, ct_eq, CryptoError};
use bytes::{from_hex, eq, slice};

fn hex(string s) -> Vec<byte> {
    return match from_hex(s) {
        Result::Ok(b) => b,
        Result::Err(_) => panic "bad hex",
    };
}

fn fill_byte(int n, byte v) -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        o.push(v);
        i = i + 1;
    }
    return o;
}

fn million_a() -> Vec<byte> {
    return fill_byte(1000000, 97 as byte);
}

fn digest(Result<Vec<byte>, CryptoError> r) -> Vec<byte> {
    return match r {
        Result::Ok(d) => d,
        Result::Err(_) => panic "digest failed",
    };
}

fn must_hasher(Result<Hasher, CryptoError> r) -> Hasher {
    return match r {
        Result::Ok(h) => h,
        Result::Err(_) => panic "hasher init",
    };
}

/// Feed `data` to a fresh hasher for `alg` in `chunk`-byte pieces.
fn chunked(int alg, Vec<byte> data, int chunk) -> Vec<byte> {
    let h = must_hasher(init(alg));
    let n = data.len();
    let i = 0;
    while i < n {
        let end = i + chunk;
        match update(h, slice(data, i, end)) {
            Result::Ok(_) => {},
            Result::Err(_) => panic "hasher update",
        };
        i = end;
    }
    return digest(finalize(h));
}

test("sha256 one million a") {
    let d = digest(sha256(million_a()));
    assert!(eq(d, hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")), "sha256 1M a");
}

test("sha512 one million a") {
    let d = digest(sha512(million_a()));
    assert!(eq(d, hex("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")), "sha512 1M a");
}

test("blake3 one million a") {
    let d = digest(blake3(million_a()));
    assert!(eq(d, hex("616f575a1b58d4c9797d4217b9730ae5e6eb319d76edef6549b46f4efe31ff8b")), "blake3 1M a");
}

test("hasher one million a in one update and in chunks") {
    let a = million_a();
    let h = must_hasher(init(0));
    match update(h, a) {
        Result::Ok(_) => {},
        Result::Err(_) => panic "hasher update",
    };
    assert!(eq(digest(finalize(h)), hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")), "sha256 one update");
    assert!(eq(chunked(0, a, 65536), hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")), "sha256 64 KiB chunks");
    assert!(eq(chunked(1, a, 100000), hex("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")), "sha512 chunks");
    assert!(eq(chunked(2, a, 333333), hex("616f575a1b58d4c9797d4217b9730ae5e6eb319d76edef6549b46f4efe31ff8b")), "blake3 chunks");
}

test("hmac sha256 over one million a") {
    let key = fill_byte(32, 7 as byte);
    let a = million_a();
    let tag = digest(hmac_sha256(key, a));
    assert!(eq(tag, hex("d81ea15467426ddcbc14ee9e10de7809cd6d018b8e7203b7b3c78fec8c291ec0")), "hmac256 1M a");
    match hmac_verify_sha256(key, a, tag) {
        Result::Ok(b) => {
            assert!(b, "verify");
        },
        Result::Err(_) => panic "verify failed",
    };
}

test("aead one million a roundtrip") {
    let key = fill_byte(32, 17 as byte);
    let nonce = fill_byte(12, 34 as byte);
    let aad = fill_byte(3, 104 as byte);
    let a = million_a();
    let ct = digest(chacha20_poly1305_encrypt(key, nonce, a, aad));
    assert!(ct.len() == 1000016, "chacha ct len");
    assert!(eq(digest(chacha20_poly1305_decrypt(key, nonce, ct, aad)), a), "chacha roundtrip");
    let gct = digest(aes_256_gcm_encrypt(key, nonce, a, aad));
    assert!(gct.len() == 1000016, "gcm ct len");
    assert!(eq(digest(aes_256_gcm_decrypt(key, nonce, gct, aad)), a), "gcm roundtrip");
}

test("ed25519 sign and verify one million a") {
    let kp = match ed25519_generate() {
        Result::Ok(p) => p,
        Result::Err(_) => panic "generate",
    };
    let a = million_a();
    let sig = digest(ed25519_sign(kp[0], a));
    assert!(sig.len() == 64, "sig len");
    match ed25519_verify(kp[1], a, sig) {
        Result::Ok(b) => {
            assert!(b, "verify");
        },
        Result::Err(_) => panic "verify failed",
    };
}

test("random_bytes at the 1 MiB cap") {
    let r = digest(random_bytes(1048576));
    assert!(r.len() == 1048576, "len");
}

test("ct_eq one million a") {
    let a = million_a();
    let b = million_a();
    assert!(ct_eq(a, b), "equal");
    let c = fill_byte(999999, 97 as byte);
    c.push(98 as byte);
    assert!(!ct_eq(a, c), "last byte differs");
}
