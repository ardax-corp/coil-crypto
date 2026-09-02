// Ed25519 generate/sign/verify roundtrip; tamper last byte → AuthenticationFailed.
use crypto::{ed25519_generate, ed25519_sign, ed25519_verify, CryptoError, ct_eq};
use string::{to_bytes};

fn fill_byte(int n, byte v) -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        o.push(v);
        i = i + 1;
    }
    return o;
}

fn to_int(byte x) -> int {
    return x as int;
}

fn xor1(int n) -> int {
    return n ^ 1;
}

fn xor_byte(byte x) -> byte {
    return xor1(to_int(x)) as byte;
}

fn xor_last(Vec<byte> sig) -> Vec<byte> {
    let n = len(sig);
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        if i == n - 1 {
            o.push(xor_byte(sig[i]));
        } else {
            o.push(sig[i]);
        }
    }
    return o;
}

test("ed25519 generate sign verify and tamper") {
    let kp = match ed25519_generate() {
        Result::Ok(p) => p,
        Result::Err(_) => panic "generate",
    };
    let sk = kp[0];
    let pk = kp[1];
    assert(len(sk) == 32, "sk len")?;
    assert(len(pk) == 32, "pk len")?;
    let msg = to_bytes("coil-ed25519");
    let sig = match ed25519_sign(sk, msg) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "sign",
    };
    assert(len(sig) == 64, "sig len")?;
    match ed25519_verify(pk, msg, sig) {
        Result::Ok(b) => assert(b, "verify ok")?,
        Result::Err(_) => panic "verify failed",
    };
    let bad = xor_last(sig);
    match ed25519_verify(pk, msg, bad) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            default => panic "wrong error",
        },
    };
}

test("ed25519 sign short key is InvalidLength") {
    let msg = to_bytes("x");
    let short = fill_byte(16, 1 as byte);
    match ed25519_sign(short, msg) {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            default => panic "wrong error",
        },
    };
}
