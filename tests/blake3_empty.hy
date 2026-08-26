// BLAKE3 KAT: empty input, 32-byte default hash
// (BLAKE3-team test_vectors.json, input_len=0).
use crypto::{blake3, ct_eq, CryptoError};
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

test("blake3 empty official") {
    let digest = match blake3(to_bytes("")) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "blake3 empty",
    };
    let want = from_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    assert(len(digest) == 32, "digest len")?;
    assert(ct_eq(digest, want), "official empty")?;
}
