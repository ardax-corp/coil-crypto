// Incremental hasher: init(1)=SHA-512, init(2)=BLAKE3, init(99)=UnsupportedAlgorithm.
use crypto::{init, update, finalize, Hasher, CryptoError, ct_eq};
use string::{to_bytes};

fn to_int(byte x) -> int {
    return x as int;
}

fn to_byte(int n) -> byte {
    return n as byte;
}

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

fn mix_nibbles(int hi, int lo) -> byte {
    let shifted = hi << 4;
    let v = shifted | lo;
    return to_byte(v);
}

fn from_hex(string s) -> Vec<byte> {
    let raw = to_bytes(s);
    let n = len(raw);
    if n % 2 != 0 {
        panic "odd hex";
    }
    let o: Vec<byte> = Vec::new();
    let i: int = 0;
    while i < n {
        let b0: byte = raw[i];
        let j: int = i + 1;
        let b1: byte = raw[j];
        o.push(mix_nibbles(nibble(to_int(b0)), nibble(to_int(b1))));
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

test("hasher sha512 abc") {
    let h = must_hasher(init(1));
    match update(h, to_bytes("abc")) {
        Result::Ok(_) => {},
        Result::Err(_) => panic "hasher update",
    };
    let digest = match finalize(h) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hasher finalize",
    };
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
    match update(h, data) {
        Result::Ok(_) => {},
        Result::Err(_) => panic "hasher update",
    };
    let digest = match finalize(h) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "hasher finalize",
    };
    let want = from_hex("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
    assert(len(digest) == 32, "digest len")?;
    assert(ct_eq(digest, want), "blake3 inlen3")?;
}

test("hasher init 99 is UnsupportedAlgorithm") {
    match init(99) {
        Result::Ok(_) => panic "expected UnsupportedAlgorithm",
        Result::Err(e) => match e {
            CryptoError::UnsupportedAlgorithm => {},
            default => panic "wrong error",
        },
    };
}
