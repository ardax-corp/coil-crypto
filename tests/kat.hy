// Known-answer vectors for every wrapper that takes or returns bytes:
// RFC 4231 case 6 (key longer than a block), RFC 8439 2.8.2 ChaCha20-Poly1305,
// GCM spec test case 16 (AES-256-GCM), RFC 8032 test 1 (Ed25519),
// RFC 7748 6.1 (X25519), and a fixed-salt Argon2id PHC string.
// Expected bytes are compared with bytes::eq, not crypto::ct_eq.
use tests::assert;
use crypto::{hmac_sha256, hmac_sha512, hmac_verify_sha256, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, aes_256_gcm_encrypt, aes_256_gcm_decrypt, ed25519_sign, ed25519_verify, x25519_shared_secret, argon2id_hash, argon2id_verify, sha256, CryptoError};
use bytes::{from_hex, eq};
use string::{to_bytes};

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

fn range_bytes(int lo, int n) -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        o.push((lo + i) as byte);
    }
    return o;
}

test("hmac rfc4231 case 6 key longer than block") {
    let key = fill_byte(131, 170 as byte);
    let data = to_bytes("Test Using Larger Than Block-Size Key - Hash Key First");
    let t256 = match hmac_sha256(key, data) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hmac_sha256",
    };
    assert!(eq(t256, hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")), "hmac256 case 6");
    let t512 = match hmac_sha512(key, data) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hmac_sha512",
    };
    assert!(eq(t512, hex("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")), "hmac512 case 6");
    match hmac_verify_sha256(key, data, t256) {
        Result::Ok(b) => {
            assert!(b, "verify case 6");
        },
        Result::Err(_) => panic "verify case 6",
    };
}

test("hmac empty key and empty data") {
    let empty: Vec<byte> = Vec::new();
    let t = match hmac_sha256(empty, empty) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hmac_sha256 empty",
    };
    assert!(eq(t, hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")), "hmac256 empty");
}

test("chacha20-poly1305 rfc8439 2.8.2") {
    let key = range_bytes(128, 32);
    let nonce = hex("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let pt = to_bytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    let want = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    let ct = match chacha20_poly1305_encrypt(key, nonce, pt, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "encrypt",
    };
    assert!(ct.len() == pt.len() + 16, "ct len");
    assert!(eq(ct, want), "rfc8439 ciphertext and tag");
    let got = match chacha20_poly1305_decrypt(key, nonce, ct, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "decrypt",
    };
    assert!(eq(got, pt), "rfc8439 roundtrip");
}

test("aes-256-gcm spec test case 16") {
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    let want = hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b");
    let ct = match aes_256_gcm_encrypt(key, nonce, pt, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "encrypt",
    };
    assert!(eq(ct, want), "tc16 ciphertext and tag");
    let got = match aes_256_gcm_decrypt(key, nonce, ct, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "decrypt",
    };
    assert!(eq(got, pt), "tc16 roundtrip");
}

test("aead empty plaintext is the tag alone") {
    let key = fill_byte(32, 1 as byte);
    let nonce = fill_byte(12, 2 as byte);
    let empty: Vec<byte> = Vec::new();
    let ct = match chacha20_poly1305_encrypt(key, nonce, empty, empty) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "encrypt",
    };
    assert!(ct.len() == 16, "tag only");
    let got = match chacha20_poly1305_decrypt(key, nonce, ct, empty) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "decrypt",
    };
    assert!(got.len() == 0, "empty roundtrip");
    let gct = match aes_256_gcm_encrypt(key, nonce, empty, empty) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "gcm encrypt",
    };
    assert!(gct.len() == 16, "gcm tag only");
    let ggot = match aes_256_gcm_decrypt(key, nonce, gct, empty) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "gcm decrypt",
    };
    assert!(ggot.len() == 0, "gcm empty roundtrip");
}

test("aead ciphertext shorter than the tag fails") {
    let key = fill_byte(32, 1 as byte);
    let nonce = fill_byte(12, 2 as byte);
    let empty: Vec<byte> = Vec::new();
    let short = fill_byte(5, 9 as byte);
    match chacha20_poly1305_decrypt(key, nonce, short, empty) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            default => panic "wrong error",
        },
    };
    match aes_256_gcm_decrypt(key, nonce, short, empty) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            default => panic "wrong error",
        },
    };
}

test("ed25519 rfc8032 test 1") {
    let sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let msg: Vec<byte> = Vec::new();
    let sig = match ed25519_sign(sk, msg) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "sign",
    };
    assert!(eq(sig, hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")), "rfc8032 sig");
    match ed25519_verify(pk, msg, sig) {
        Result::Ok(b) => {
            assert!(b, "verify");
        },
        Result::Err(_) => panic "verify failed",
    };
}

test("x25519 rfc7748 6.1") {
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = match x25519_shared_secret(alice, bob_pub) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "shared",
    };
    assert!(eq(shared, hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")), "rfc7748 shared");
}

test("argon2id fixed salt PHC string") {
    let salt = fill_byte(16, 2 as byte);
    let encoded = match argon2id_hash(to_bytes("coil-password"), salt) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "hash",
    };
    assert!(encoded == "$argon2id$v=19$m=19456,t=2,p=1$AgICAgICAgICAgICAgICAg$UiGHc8c59la2bsjO4RXqCGbcEiptK9c79Q3fE0/6LQo", "phc string");
    match argon2id_verify(to_bytes("coil-password"), encoded) {
        Result::Ok(b) => {
            assert!(b, "verify");
        },
        Result::Err(_) => panic "verify failed",
    };
}

test("sha256 abc") {
    let d = match sha256(to_bytes("abc")) {
        Result::Ok(x) => x,
        Result::Err(_) => panic "sha256",
    };
    assert!(eq(d, hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")), "sha256 abc");
}
