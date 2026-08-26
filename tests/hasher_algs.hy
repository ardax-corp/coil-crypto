// Incremental hasher: init(1)=SHA-512, init(2)=BLAKE3, init(99)=UnsupportedAlgorithm.
use crypto::{init, update, finalize, Hasher, CryptoError, ct_eq};
use string::{to_bytes};

fn nibble(int c) -> int {
    if c >= 48 && c <= 57 {
        return c - 48;
    }
    if c >= 97 && c <= 102 {
        return c - 87;
    }
    if c >= 65 && c <= 70 {
        return c - 55;
    }
    panic "bad hex";
}

fn from_hex(string s) -> Vec<byte> {
    let raw = to_bytes(s);
    let n = len(raw);
    if n % 2 != 0 {
        panic "odd hex";
    }
    let o: Vec<byte> = Vec::new();
    let i = 0;
    while i < n {
        let hi = nibble(raw[i] as int);
        let lo = nibble(raw[i + 1] as int);
        o.push(((hi << 4) | lo) as byte);
        i = i + 2;
    }
    return o;
}

fn must_hasher(Result<Hasher, CryptoError> r) -> Hasher {
    return match r {
        Result::Ok(h) => h,
        Result::Err(_) => panic "hasher init",
    };
}

fn must_digest(Hasher h, Vec<byte> data) -> Vec<byte> {
    match update(h, data) {
        Result::Ok(_) => {},
        Result::Err(_) => panic "hasher update",
    };
    return match finalize(h) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hasher finalize",
    };
}

test("hasher sha512 abc") {
    let h = must_hasher(init(1));
    let digest = must_digest(h, to_bytes("abc"));
    let want = from_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    assert(len(digest) == 64, "digest len")?;
    assert(ct_eq(digest, want), "sha512 abc")?;
}

test("hasher blake3 input_len 3") {
    let data: Vec<byte> = Vec::new();
    data.push(0 as byte);
    data.push(1 as byte);
    data.push(2 as byte);
    let h = must_hasher(init(2));
    let digest = must_digest(h, data);
    let want = from_hex("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
    assert(len(digest) == 32, "digest len")?;
    assert(ct_eq(digest, want), "blake3 inlen3")?;
}

test("hasher init 99 is UnsupportedAlgorithm") {
    match init(99) {
        Result::Ok(_) => panic "expected UnsupportedAlgorithm",
        Result::Err(e) => match e {
            CryptoError::UnsupportedAlgorithm => {},
            _ => panic "wrong error",
        },
    };
}
