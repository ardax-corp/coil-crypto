# coil-crypto

Userland cryptography for [coil](https://github.com/ardax-corp/coil-lang). RustCrypto lives in a cdylib (`libcrypto.so` / `.dylib` / `.dll`) plus Coil wrappers. `use crypto::{…}` is this package, not a compiler builtin.

It covers hashing (SHA-256, SHA-512, BLAKE3, and an incremental `Hasher`), HMAC-SHA256/512, OS randomness, AEAD (ChaCha20-Poly1305, AES-256-GCM), Ed25519 signatures, X25519 key agreement, Argon2id password hashing and a constant-time compare. Every fallible call returns `Result<_, CryptoError>`.

## Example

```coil
use crypto::{sha256, hmac_sha256, hmac_verify_sha256, random_bytes};
use bytes::{to_hex};
use io::sync::{println};
use string::{to_bytes};

fn main() {
    let digest = sha256(to_bytes("hello")).unwrap_or(Vec::new());
    println("sha256: " + to_hex(digest))?;

    let key = random_bytes(32).unwrap_or(Vec::new());
    let tag = hmac_sha256(key, to_bytes("message")).unwrap_or(Vec::new());
    let ok = hmac_verify_sha256(key, to_bytes("message"), tag).is_ok();
    println("tag verifies: " + ok.show())?;
}
```

```bash
make -C ../coil-crypto   # builds native/libcrypto.so (or .dylib / .dll)
coil --root ../coil-crypto/src --root ../coil-stdlib/src \
  --ffi-search-path ../coil-crypto/native \
  --allow-dload crypto --dload-trusted crypto main.hy
```

## Layout

| Path | Role |
|------|------|
| `src/crypto.hy` | Package exports (`sha256`, `init` / `update` / `finalize`, HMAC, AEAD, Ed25519 / X25519, Argon2id, `ct_eq`) |
| `native/` | Rust cdylib, C ABI `coil_crypto_*` |
| `coil.toml` | spool manifest (`[package] name = "crypto"`); coil does not read it |

`extern "crypto"` / `dload("crypto")` resolves to `libcrypto.so` in `native/` (`--ffi-search-path ./native`; spool passes it from `[ffi] search_paths`). Hasher state is an opaque pointer in the `.so` (`Object::CryptoHasher` is gone). `Hasher.drop` calls `coil_crypto_hasher_free`.

The wrappers bind every native that takes or fills a buffer with `declare` and pass each `Vec<byte>` (or the Argon2id PHC `string`) as `ffi::types::ConstBytes` for input and `Bytes` for output, so the VM lends the bytes to C instead of copying them through native heap helpers; `libcrypto` exports none. `native/crypto.h` lists the exported C ABI.

## Build

```bash
make          # native/libcrypto.{so,dylib,dll}
make test     # cargo test in native/
```

Or:

```bash
cd native && cargo test && cargo build --release
# copy libcrypto.so / .dylib / crypto.dll into native/ (the FFI search path)
```

Argon2id MVP params are fixed (19 MiB, 2 iterations, parallelism 1) and not caller-tunable.

Consume with `spool add crypto --git https://github.com/ardax-corp/coil-crypto.git --rev <commit SHA>` (no tags yet), or a sibling checkout plus `--root`, `--ffi-search-path`, `--allow-dload crypto` and `--dload-trusted crypto` (or `--dload-pin`). See [docs/consume.md](docs/consume.md).

## License

MIT. See [LICENSE](LICENSE).
