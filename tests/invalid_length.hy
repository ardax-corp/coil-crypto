// Wrong AEAD key/nonce sizes are CryptoError::InvalidLength.
use crypto::{aes_256_gcm_encrypt, chacha20_poly1305_encrypt, CryptoError};
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

fn expect_invalid_length(Result<Vec<byte>, CryptoError> r) {
    match r {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            _ => panic "wrong error",
        },
    };
}

test("aes256-gcm short key is InvalidLength") {
    let key = fill_byte(16, 1 as byte);
    let nonce = fill_byte(12, 2 as byte);
    expect_invalid_length(aes_256_gcm_encrypt(key, nonce, to_bytes("pt"), to_bytes("")));
}

test("aes256-gcm short nonce is InvalidLength") {
    let key = fill_byte(32, 1 as byte);
    let nonce = fill_byte(8, 2 as byte);
    expect_invalid_length(aes_256_gcm_encrypt(key, nonce, to_bytes("pt"), to_bytes("")));
}

test("chacha20 short key is InvalidLength") {
    let key = fill_byte(31, 1 as byte);
    let nonce = fill_byte(12, 2 as byte);
    expect_invalid_length(chacha20_poly1305_encrypt(key, nonce, to_bytes("pt"), to_bytes("")));
}

test("chacha20 short nonce is InvalidLength") {
    let key = fill_byte(32, 1 as byte);
    let nonce = fill_byte(11, 2 as byte);
    expect_invalid_length(chacha20_poly1305_encrypt(key, nonce, to_bytes("pt"), to_bytes("")));
}
