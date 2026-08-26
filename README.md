# coil-crypto

Userland cryptography for [coil](https://github.com/ardax-corp/coil-lang). RustCrypto lives in a cdylib (`libcrypto.so` / `.dylib` / `.dll`) plus Coil wrappers. `use crypto::{…}` is this package, not a compiler builtin.

Locked design (accepted [COI-214](https://linear.app/ardax/issue/COI-214/accept-coil-crypto-design)): [coil-crypto design (v1)](https://linear.app/ardax/document/coil-crypto-design-v1-f48b4876e457).

## Layout

| Path | Role |
|------|------|
| `src/crypto.hy` | Package exports (`sha256`, `init` / `update` / `finalize`, HMAC, AEAD, Ed25519 / X25519, Argon2id, `ct_eq`) |
| `native/` | Rust cdylib, C ABI `coil_crypto_*` |
| `coil.toml` | `[package] name = "crypto"` so `use crypto::{…}` survives |

`extern "crypto"` / `dload("crypto")` resolves to `libcrypto.so` via `[ffi] search_paths = ["./native"]`. Hasher state is an opaque pointer in the `.so` (`Object::CryptoHasher` is gone). `Hasher.drop` calls `coil_crypto_hasher_free`.

## Build

```bash
make          # native/libcrypto.{so,dylib,dll}
make test     # cargo test in native/
```

Or:

```bash
cd native && cargo test && cargo build --release
# copy libcrypto.so / .dylib / crypto.dll into native/ so [ffi] search_paths finds it
```

Argon2id MVP params are fixed (19 MiB, 2 iterations, parallelism 1) and not caller-tunable.

Consume from a sibling checkout or a `coil.lock` pin (`rev` + `content_hash`). See [docs/consume.md](docs/consume.md).

Spool will own Coil-to-Coil deps once it exists ([COI-219](https://linear.app/ardax/issue/COI-219)). Until then there is no `spool add` and this repo has no tags. Native libs stay on `[ffi] search_paths` until [COI-60](https://linear.app/ardax/issue/COI-60).

## License

MIT. See [LICENSE](LICENSE).
