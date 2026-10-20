# coil-crypto

Userland cryptography for [coil](https://github.com/ardax-corp/coil-lang). RustCrypto lives in a cdylib (`libcrypto.so` / `.dylib` / `.dll`) plus Coil wrappers. `use crypto::{…}` is this package, not a compiler builtin.

Locked design (accepted [COI-214](https://linear.app/ardax/issue/COI-214/accept-coil-crypto-design)): [coil-crypto design (v1)](https://linear.app/ardax/document/coil-crypto-design-v1-f48b4876e457).

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
