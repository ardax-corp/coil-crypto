// Hasher.drop frees the native handle; a second drop is a no-op.
// Going out of scope then gc::collect exercises the finalizer path.
use crypto::{init, Hasher, CryptoError};
use gc::{collect};

fn must_hasher(Result<Hasher, CryptoError> r) -> Hasher {
    return match r {
        Result::Ok(h) => h,
        Result::Err(_) => panic "hasher init",
    };
}

test("hasher drop is idempotent") {
    let h = must_hasher(init(0));
    h.drop();
    assert(h.live == false, "live after drop")?;
    h.drop();
    assert(h.live == false, "live after second drop")?;
}

fn ephemeral_hasher() {
    let _h = must_hasher(init(2));
}

test("hasher drop across collect") {
    ephemeral_hasher();
    collect();
    assert(true)?;
}

test("hasher explicit drop then collect") {
    let h = must_hasher(init(1));
    h.drop();
    collect();
    assert(h.live == false, "live after collect")?;
}
