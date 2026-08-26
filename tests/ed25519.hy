// Ed25519 generate/sign/verify roundtrip + tamper, and RFC 8032 test 1.
use crypto::{ed25519_generate, ed25519_sign, ed25519_verify, CryptoError, ct_eq};
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

fn xor_last(Vec<byte> sig) -> Vec<byte> {
    let n = len(sig);
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        if i == n - 1 {
            o.push(((sig[i] as int) ^ 1) as byte);
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
            _ => panic "wrong error",
        },
    };
}

test("ed25519 rfc8032 test 1 empty message") {
    let sk = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let msg = to_bytes("");
    let want = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522c217c309a6f8115c8908b7e21df4c2297e52d798c54645d42981eaa3494acb4185aa0d");
    let sig = match ed25519_sign(sk, msg) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "sign rfc",
    };
    assert(ct_eq(sig, want), "rfc8032 sig")?;
    match ed25519_verify(pk, msg, sig) {
        Result::Ok(b) => assert(b, "rfc8032 verify")?,
        Result::Err(_) => panic "rfc8032 verify failed",
    };
}

test("ed25519 sign short key is InvalidLength") {
    let msg = to_bytes("x");
    let short: Vec<byte> = Vec::new();
    let i = 0;
    while i < 16 {
        short.push(1 as byte);
        i = i + 1;
    }
    match ed25519_sign(short, msg) {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            _ => panic "wrong error",
        },
    };
}
