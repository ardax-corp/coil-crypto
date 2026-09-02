// ChaCha20-Poly1305 roundtrip; tamper last byte → AuthenticationFailed.
use crypto::{chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, CryptoError, ct_eq};
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

fn xor_last(Vec<byte> ct) -> Vec<byte> {
    let n = len(ct);
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        if i == n - 1 {
            o.push(xor_byte(ct[i]));
        } else {
            o.push(ct[i]);
        }
    }
    return o;
}

test("chacha20 roundtrip and tamper") {
    let key = fill_byte(32, 17 as byte);
    let nonce = fill_byte(12, 34 as byte);
    let pt = to_bytes("coil-aead");
    let aad = to_bytes("");
    let ct = match chacha20_poly1305_encrypt(key, nonce, pt, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "encrypt failed",
    };
    assert(len(ct) > len(pt), "tag present")?;
    let got = match chacha20_poly1305_decrypt(key, nonce, ct, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "decrypt failed",
    };
    assert(ct_eq(got, pt), "roundtrip")?;
    let bad = xor_last(ct);
    match chacha20_poly1305_decrypt(key, nonce, bad, aad) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            default => panic "wrong error",
        },
    };
}
