// NIST SHA-256 KAT: empty string (same bytes as native/src/lib.rs).
use crypto::{sha256, ct_eq, CryptoError};
use string::{to_bytes};

fn empty_digest() -> Vec<byte> {
    let o: Vec<byte> = Vec::new();
    o.push(227 as byte);
    o.push(176 as byte);
    o.push(196 as byte);
    o.push(66 as byte);
    o.push(152 as byte);
    o.push(252 as byte);
    o.push(28 as byte);
    o.push(20 as byte);
    o.push(154 as byte);
    o.push(251 as byte);
    o.push(244 as byte);
    o.push(200 as byte);
    o.push(153 as byte);
    o.push(111 as byte);
    o.push(185 as byte);
    o.push(36 as byte);
    o.push(39 as byte);
    o.push(174 as byte);
    o.push(65 as byte);
    o.push(228 as byte);
    o.push(100 as byte);
    o.push(155 as byte);
    o.push(147 as byte);
    o.push(76 as byte);
    o.push(164 as byte);
    o.push(149 as byte);
    o.push(153 as byte);
    o.push(27 as byte);
    o.push(120 as byte);
    o.push(82 as byte);
    o.push(184 as byte);
    o.push(85 as byte);
    return o;
}

test("sha256 empty string NIST") {
    let digest = match sha256(to_bytes("")) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "sha256 empty",
    };
    assert(len(digest) == 32, "digest len")?;
    assert(ct_eq(digest, empty_digest()), "nist empty")?;
}
