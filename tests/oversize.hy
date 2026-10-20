// Inputs over 1 MiB (2 MiB of i % 251). The old heap-helper marshalling
// made one void `coil_crypto_store_u8` call per byte, and about 1,048,100
// of those overflowed the VM operand stack. Expected values come from
// Python hashlib / cryptography and the Rust blake3 crate.
use tests::assert;
use crypto::{sha256, sha512, blake3, hmac_sha512, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, aes_256_gcm_encrypt, aes_256_gcm_decrypt, CryptoError};
use bytes::{from_hex, eq};

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

fn pattern() -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    for i in 0..2097152 {
        o.push((i % 251) as byte);
    }
    return o;
}

fn ok(Result<Vec<byte>, CryptoError> r) -> Vec<byte> {
    return match r {
        Result::Ok(d) => d,
        Result::Err(_) => panic "call failed",
    };
}

test("hashes over 2 MiB") {
    let p = pattern();
    assert!(eq(ok(sha256(p)), hex("1e075c8d478ad21844e33e830a695ef03a4d2488b69ee275bd8947618bb1be1e")), "sha256");
    assert!(eq(ok(sha512(p)), hex("eb0e38fa0c2dd92c3ae29a6b05f74393547516089d640fc98dda8289582a36317fe359bcd9d0bda4e9d25fc0a63003d6465c729bdc98f28a318932071729d825")), "sha512");
    assert!(eq(ok(blake3(p)), hex("96fbba37478c16b7614c890b26832f67b541cf14e69ab8ebf0c739818588c9f1")), "blake3");
}

test("hmac sha512 over 2 MiB") {
    let key = fill_byte(32, 7 as byte);
    assert!(eq(ok(hmac_sha512(key, pattern())), hex("e20437f6a6fc036e0028828cc0e924ddc77e7fc5164db3b9ef1ea85b7133970fafdb6456073b0321391a9db9290b4b993eb16ae5a738f69a4f0e7877963aa9f2")), "hmac512");
}

test("aead over 2 MiB") {
    let key = fill_byte(32, 17 as byte);
    let nonce = fill_byte(12, 34 as byte);
    let aad = fill_byte(3, 104 as byte);
    let p = pattern();
    let ct = ok(chacha20_poly1305_encrypt(key, nonce, p, aad));
    assert!(ct.len() == 2097168, "chacha ct len");
    assert!(eq(ok(sha256(ct)), hex("c04d6783fd084538d409e97dcb5cb9c8d43cc8e9f8eee9fc95712038271a2fa5")), "chacha ct");
    assert!(eq(ok(chacha20_poly1305_decrypt(key, nonce, ct, aad)), p), "chacha roundtrip");
    let gct = ok(aes_256_gcm_encrypt(key, nonce, p, aad));
    assert!(eq(ok(sha256(gct)), hex("c361de00c9cd29c733567b3976c887c6f5e53039c014347d5db0aac6e65eebf4")), "gcm ct");
    assert!(eq(ok(aes_256_gcm_decrypt(key, nonce, gct, aad)), p), "gcm roundtrip");
}
