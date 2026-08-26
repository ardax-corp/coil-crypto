// NIST SHA-512 KAT: empty string (FIPS 180-4 / SHA512.pdf).
use crypto::{sha512, ct_eq, CryptoError};
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

test("sha512 empty string NIST") {
    let digest = match sha512(to_bytes("")) {
        Result::Ok(d) => d,
        Result::Err(_) => panic "sha512 empty",
    };
    let want = from_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert(len(digest) == 64, "digest len")?;
    assert(ct_eq(digest, want), "nist empty")?;
}
