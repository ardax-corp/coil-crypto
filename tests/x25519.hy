// X25519: both generated sides match; short key is InvalidLength.
use crypto::{x25519_generate, x25519_shared_secret, CryptoError, ct_eq};

fn fill_byte(int n, byte v) -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        o.push(v);
        i = i + 1;
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

test("x25519 short key is InvalidLength") {
    let short = fill_byte(16, 1 as byte);
    match x25519_shared_secret(short, short) {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            _ => panic "wrong error",
        },
    };
}
