// Hasher init(0) + update("abc") + finalize = SHA-256("abc");
// second finalize is CryptoError::AlreadyFinalized.
use crypto::{init, update, finalize, Hasher, CryptoError, ct_eq};
use string::{to_bytes};

fn abc_digest() -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    o.push(186 as byte);
    o.push(120 as byte);
    o.push(22 as byte);
    o.push(191 as byte);
    o.push(143 as byte);
    o.push(1 as byte);
    o.push(207 as byte);
    o.push(234 as byte);
    o.push(65 as byte);
    o.push(65 as byte);
    o.push(64 as byte);
    o.push(222 as byte);
    o.push(93 as byte);
    o.push(174 as byte);
    o.push(34 as byte);
    o.push(35 as byte);
    o.push(176 as byte);
    o.push(3 as byte);
    o.push(97 as byte);
    o.push(163 as byte);
    o.push(150 as byte);
    o.push(23 as byte);
    o.push(122 as byte);
    o.push(156 as byte);
    o.push(180 as byte);
    o.push(16 as byte);
    o.push(255 as byte);
    o.push(97 as byte);
    o.push(242 as byte);
    o.push(0 as byte);
    o.push(21 as byte);
    o.push(173 as byte);
    return o;
}

fn must_hasher(Result<Hasher, CryptoError> r) -> Hasher {
    return match r {
        Result::Ok(h) => h,
        Result::Err(_) => panic "hasher init",
    };
}

test("hasher abc then AlreadyFinalized") {
    let h = must_hasher(init(0));
    match update(h, to_bytes("abc")) {
        Result::Ok(_) => {},
        Result::Err(_) => panic "hasher update",
    };
    let digest = match finalize(h) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hasher finalize",
    };
    assert(len(digest) == 32, "digest len")?;
    assert(ct_eq(digest, abc_digest()), "sha256 abc")?;
    match finalize(h) {
        Result::Ok(_) => panic "expected AlreadyFinalized",
        Result::Err(e) => match e {
            CryptoError::AlreadyFinalized => {},
            _ => panic "wrong error",
        },
    };
}
