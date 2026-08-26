// ct_eq: equal, mismatch, unequal lengths.
use crypto::{ct_eq};
use string::{to_bytes};

test("ct_eq equal") {
    let a = to_bytes("same");
    let b = to_bytes("same");
    assert(ct_eq(a, b), "equal")?;
}

test("ct_eq mismatch") {
    let a = to_bytes("same");
    let b = to_bytes("diff");
    assert(ct_eq(a, b) == false, "mismatch")?;
}

test("ct_eq unequal lengths") {
    let a = to_bytes("abc");
    let b = to_bytes("ab");
    assert(ct_eq(a, b) == false, "unequal lengths")?;
}

test("ct_eq empty") {
    let a = to_bytes("");
    let b = to_bytes("");
    assert(ct_eq(a, b), "empty")?;
}
