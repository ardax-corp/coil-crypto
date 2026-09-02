// RFC 4231 HMAC-SHA256 / HMAC-SHA512 test case 1; verify ok and bad tag.
use crypto::{hmac_sha256, hmac_sha512, hmac_verify_sha256, CryptoError, ct_eq};
use string::{to_bytes};

fn to_int(byte x) -> int {
    return x as int;
}

fn to_byte(int n) -> byte {
    return n as byte;
}

fn xor1(int n) -> int {
    return n ^ 1;
}

fn xor_byte(byte x) -> byte {
    return to_byte(xor1(to_int(x)));
}

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

fn mix_nibbles(int hi, int lo) -> byte {
    let shifted = hi << 4;
    let v = shifted | lo;
    return to_byte(v);
}

fn from_hex(string s) -> Vec<byte> {
    let raw = to_bytes(s);
    let n = len(raw);
    if n % 2 != 0 {
        panic "odd hex";
    }
    let o: Vec<byte> = Vec::new();
    let i: int = 0;
    while i < n {
        let b0: byte = raw[i];
        let j: int = i + 1;
        let b1: byte = raw[j];
        o.push(mix_nibbles(nibble(to_int(b0)), nibble(to_int(b1))));
        i = i + 2;
    }
    return o;
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

fn xor_last(Vec<byte> tag) -> Vec<byte> {
    let n = len(tag);
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        if i == n - 1 {
            o.push(xor_byte(tag[i]));
        } else {
            o.push(tag[i]);
        }
    }
    return o;
}

test("hmac sha256 rfc4231 case 1") {
    let key = fill_byte(20, 11 as byte);
    let data = to_bytes("Hi There");
    let tag = match hmac_sha256(key, data) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hmac_sha256",
    };
    let want = from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert(len(tag) == 32, "tag len")?;
    assert(ct_eq(tag, want), "rfc4231 hmac256")?;
}

test("hmac sha512 rfc4231 case 1") {
    let key = fill_byte(20, 11 as byte);
    let data = to_bytes("Hi There");
    let tag = match hmac_sha512(key, data) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hmac_sha512",
    };
    let want = from_hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    assert(len(tag) == 64, "tag len")?;
    assert(ct_eq(tag, want), "rfc4231 hmac512")?;
}

test("hmac verify sha256 ok and bad tag") {
    let key = fill_byte(20, 11 as byte);
    let data = to_bytes("Hi There");
    let tag = from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    match hmac_verify_sha256(key, data, tag) {
        Result::Ok(b) => assert(b, "verify ok")?,
        Result::Err(_) => panic "verify failed",
    };
    let bad = xor_last(tag);
    match hmac_verify_sha256(key, data, bad) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            default => panic "wrong error",
        },
    };
}
