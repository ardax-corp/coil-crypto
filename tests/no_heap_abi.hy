// COI-235: release libcrypto must not export heap helpers.
// declare() of those names is ErrorKind::SymbolNotFound. Do not invoke them.
use ffi::{dload, declare, ErrorKind};
use ffi::types::{Int};

fn crypto_lib() -> int {
    return match dload("crypto") {
        Result::Ok(h) => h,
        Result::Err(_) => panic "dload crypto",
    };
}

fn expect_missing(string name) {
    let lib = crypto_lib();
    match declare(lib, name, (Int,), Int) {
        Result::Ok(_) => panic "heap helper still exported",
        Result::Err(e) => match e.kind {
            ErrorKind::SymbolNotFound => {},
            _ => panic "expected SymbolNotFound",
        },
    };
}

test("coil_crypto_alloc is not exported") {
    expect_missing("coil_crypto_alloc");
}

test("coil_crypto_store_u8 is not exported") {
    expect_missing("coil_crypto_store_u8");
}

test("coil_crypto_load_u8 is not exported") {
    expect_missing("coil_crypto_load_u8");
}

test("coil_crypto_free is not exported") {
    expect_missing("coil_crypto_free");
}
