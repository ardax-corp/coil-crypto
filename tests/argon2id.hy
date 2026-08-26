// Argon2id hash then verify; bad password fails; empty salt / garbage hash named errors.
use crypto::{argon2id_hash, argon2id_verify, CryptoError};
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

test("argon2id hash then verify") {
    let password = to_bytes("coil-password");
    let salt = fill_byte(16, 2 as byte);
    let encoded = match argon2id_hash(password, salt) {
        Result::Ok(s) => s,
        Result::Err(_) => panic "hash",
    };
    match argon2id_verify(password, encoded) {
        Result::Ok(b) => assert(b, "verify ok")?,
        Result::Err(_) => panic "verify failed",
    };
    match argon2id_verify(to_bytes("wrong-password"), encoded) {
        Result::Ok(_) => panic "expected AuthenticationFailed",
        Result::Err(e) => match e {
            CryptoError::AuthenticationFailed => {},
            _ => panic "wrong error",
        },
    };
}

test("argon2id empty salt is InvalidLength") {
    let empty: Vec<byte> = Vec::new();
    match argon2id_hash(to_bytes("pw"), empty) {
        Result::Ok(_) => panic "expected InvalidLength",
        Result::Err(e) => match e {
            CryptoError::InvalidLength => {},
            _ => panic "wrong error",
        },
    };
}

test("argon2id verify garbage hash is InvalidInput") {
    match argon2id_verify(to_bytes("pw"), "not-a-phc-string") {
        Result::Ok(_) => panic "expected InvalidInput",
        Result::Err(e) => match e {
            CryptoError::InvalidInput => {},
            _ => panic "wrong error",
        },
    };
}
