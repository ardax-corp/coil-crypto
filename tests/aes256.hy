// AES-256-GCM roundtrip; tamper last byte → AuthenticationFailed.
use crypto::{aes_256_gcm_encrypt, aes_256_gcm_decrypt, CryptoError, ct_eq};
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

fn xor_last(Vec<byte> ct) -> Vec<byte> {
    let n = len(ct);
    let o: Vec<byte> = Vec::new();
    for i in 0..n {
        if i == n - 1 {
            o.push(((ct[i] as int) ^ 1) as byte);
        } else {
            o.push(ct[i]);
        }
    }
    return o;
}

test("aes256-gcm roundtrip and tamper") {
    let key = fill_byte(32, 17 as byte);
    let nonce = fill_byte(12, 34 as byte);
    let pt = to_bytes("coil-aead");
    let aad = to_bytes("");
    let ct = match aes_256_gcm_encrypt(key, nonce, pt, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "encrypt failed",
    };
    assert(len(ct) > len(pt), "tag present")?;
    let got = match aes_256_gcm_decrypt(key, nonce, ct, aad) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "decrypt failed",
    };
    assert(ct_eq(got, pt), "roundtrip")?;
    let bad = xor_last(ct);
    match aes_256_gcm_decrypt(key, nonce, bad, aad) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            _ => panic "wrong error",
        },
    };
}
