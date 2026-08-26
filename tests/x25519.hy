// X25519: both generated sides match; RFC 7748 §6.1; short key is InvalidLength.
use crypto::{x25519_generate, x25519_shared_secret, CryptoError, ct_eq};
use string::{to_bytes};

fn nibble(int c) -> int {
    if c >= 48 && c <= 57 {
        return c - 48;
    }
    if c >= 97 && c <= 102 {
        return c - 87;
    }
    if c >= 65 && c <= 70 {
        return c - 55;
    }
    panic "bad hex";
}

fn from_hex(string s) -> Vec<byte> {
    let raw = to_bytes(s);
    let n = len(raw);
    if n % 2 != 0 {
        panic "odd hex";
    }
    let o: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        let hi = nibble(raw[i] as int);
        let lo = nibble(raw[i + 1] as int);
        o.push(((hi << 4) | lo) as byte);
        i = i + 2;
    }
    return o;
}

test("x25519 both sides match") {
    let a = match x25519_generate() {
        Result::Ok(p) => p,
        Result::Err(_) => panic "generate a",
    };
    let b = match x25519_generate() {
        Result::Ok(p) => p,
        Result::Err(_) => panic "generate b",
    };
    let ab = match x25519_shared_secret(a[0], b[1]) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "shared ab",
    };
    let ba = match x25519_shared_secret(b[0], a[1]) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "shared ba",
    };
    assert(len(ab) == 32, "shared len")?;
    assert(ct_eq(ab, ba), "dh match")?;
}

test("x25519 rfc7748 section 6.1") {
    let alice_sk = from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51dbf3c01");
    let alice_pk = from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_sk = from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pk = from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let want = from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let ab = match x25519_shared_secret(alice_sk, bob_pk) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "alice dh",
    };
    let ba = match x25519_shared_secret(bob_sk, alice_pk) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "bob dh",
    };
    assert(ct_eq(ab, want), "rfc7748 alice")?;
    assert(ct_eq(ba, want), "rfc7748 bob")?;
}

test("x25519 short key is InvalidLength") {
    let short: Vec<byte> = Vec::new();
    let i = 0;
    while i < 16 {
        short.push(1 as byte);
        i = i + 1;
    }
    match x25519_shared_secret(short, short) {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            _ => panic "wrong error",
        },
    };
}
