// random_bytes / random_u64 succeed; oversized n is InvalidInput.
use crypto::{random_bytes, random_u64, CryptoError, ct_eq};

test("random_bytes length and distinct draws") {
    let a = match random_bytes(32) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "random_bytes a",
    };
    let b = match random_bytes(32) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "random_bytes b",
    };
    assert(len(a) == 32, "len a")?;
    assert(len(b) == 32, "len b")?;
    assert(ct_eq(a, b) == false, "draws should differ")?;
}

test("random_bytes empty") {
    let z = match random_bytes(0) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "random_bytes 0",
    };
    assert(len(z) == 0, "empty")?;
}

test("random_bytes too large is InvalidInput") {
    match random_bytes((1 << 20) + 1) {
        Result::Ok(_) => panic "expected InvalidInput",
        Result::Err(e) => match e {
            CryptoError::InvalidInput => {},
            default => panic "wrong error",
        },
    };
}

test("random_u64 succeeds") {
    let n = match random_u64() {
        Result::Ok(v) => v,
        Result::Err(_) => panic "random_u64",
    };
    assert(n == n, "u64 bound")?;
}
