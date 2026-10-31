# Consuming coil-crypto

This package is `crypto`. `use crypto::{sha256}` resolves from this repo's `src/`. RustCrypto lives in `libcrypto.so` / `.dylib` / `crypto.dll`. `extern "crypto"` in `src/crypto.coil` already calls `dload("crypto")`. Put the built library on the FFI search path (`--ffi-search-path`). The VM does not register crypto HostInvoke slots. `use crypto` without this package's `src/` as a `--root` is a module-not-found error.

## Depend on it

With [spool](https://github.com/ardax-corp/spool):

```bash
spool add crypto --git https://github.com/ardax-corp/coil-crypto.git --rev <commit SHA>
```

This repo has no tags, so pin a commit with `--rev`. spool records the dep in `coil.toml`, writes `coil.lock` (`rev` + `content_hash`), links `.spool/deps/crypto`, and passes `--root` for it and coil-stdlib to `coil`.

spool links only `src/`. Build the native library in a checkout of this repo (`make` copies `libcrypto.so` / `.dylib` / `crypto.dll` into `native/`) and grant it in the consumer `coil.toml`:

```toml
[ffi]
search_paths = ["../coil-crypto/native"]
allow = ["crypto"]

[dependencies]
crypto = { git = "https://github.com/ardax-corp/coil-crypto.git", rev = "<commit SHA>", trusted = true }
```

spool turns these into `--ffi-search-path ../coil-crypto/native --allow-dload crypto --dload-trusted crypto`. Instead of `trusted = true`, a `[[package.native]]` row with the library's `sha256` under the `crypto` package in `coil.lock` gives `--dload-pin crypto=SHA256`.

## Plain coil

Clone this repo next to your project, run `make` there, and pass everything as flags. coil reads no `coil.toml` and no `coil.lock`.

```bash
make -C ../coil-crypto
coil --root ../coil-crypto/src \
  --ffi-search-path ../coil-crypto/native \
  --allow-dload crypto --dload-trusted crypto main.coil
```

Use `--dload-pin crypto=<sha256 of libcrypto.so>` instead of `--dload-trusted crypto` to pin the build. Application code imports the Coil wrappers. It does not call `dload` itself.

```coil
use crypto::{sha256, random_bytes, ct_eq, CryptoError};
use string::{to_bytes};

let digest = sha256(to_bytes("hello"))?;
```

## Call it

```coil
use crypto::{init, update, finalize, Hasher, CryptoError};
use string::{to_bytes};

let h = init(0)?;
update(h, to_bytes("abc"))?;
let digest = finalize(h)?;
```

`init` takes `0` (SHA-256), `1` (SHA-512), or `2` (BLAKE3). Anything else is `CryptoError::UnsupportedAlgorithm`. `Hasher.drop` frees the native handle. Do not use the hasher after drop.

ChaCha20-Poly1305 and AES-256-GCM take a 32-byte key and a 12-byte nonce. Ciphertext is plaintext plus a 16-byte tag. Wrong sizes are `InvalidLength`. Tampered ciphertext is `AuthenticationFailed`.

Argon2id MVP params are fixed (19 MiB, 2 iterations, parallelism 1) and not caller-tunable. `argon2id_hash` returns a PHC string.

`hmac_verify_sha256`, `ed25519_verify`, and `argon2id_verify` return `Ok(true)` or `Err(AuthenticationFailed)`. They do not return `Ok(false)`.

`ct_eq` is a `bool`, not a `Result`.

Shipped names in `src/crypto.coil`:

| Name | Notes |
|------|--------|
| `sha256` / `sha512` / `blake3` | `Vec<byte>` in, digest out |
| `init` / `update` / `finalize` | Incremental hasher. `init` alg tag above |
| `hmac_sha256` / `hmac_sha512` / `hmac_verify_sha256` | Verify fails as `AuthenticationFailed` |
| `random_bytes` / `random_u64` | `random_bytes` rejects `n > 1 MiB` (`InvalidInput`) |
| `chacha20_poly1305_encrypt` / `decrypt` | 32-byte key, 12-byte nonce |
| `aes_256_gcm_encrypt` / `decrypt` | Same key and nonce sizes |
| `ed25519_generate` / `sign` / `verify` | `(secret, public)` is 32 + 32 bytes |
| `x25519_generate` / `shared_secret` | Same key sizes |
| `argon2id_hash` / `argon2id_verify` | Hash is a PHC string |
| `ct_eq` | Constant-time compare |
| `CryptoError` | `InvalidInput`, `InvalidLength`, `AuthenticationFailed`, `UnsupportedAlgorithm`, `AlreadyFinalized`, `Other` |
| `Hasher` | Opaque native handle. Drop frees it |

Do not call `coil_crypto_*` from application code. Those symbols are the C ABI behind the wrappers.
