# Consuming coil-crypto

Package name is `crypto`. `use crypto::{sha256}` is a module-not-found error unless this package's `src/` is on `[module] roots`. The VM does not register crypto HostInvoke slots.

## Sibling checkout

Clone this repo beside your project. In the consumer `coil.toml`:

```toml
[module]
roots = ["./src", "../coil-crypto/src"]

[ffi]
search_paths = ["../coil-crypto/native"]
```

A path dep is optional metadata for spool later. The compiler still needs those two lists:

```toml
[dependencies]
crypto = { path = "../coil-crypto" }
```

Build the native library from this package root so `dload("crypto")` can find it:

```bash
make
```

That copies `libcrypto.so` (or `libcrypto.dylib` / `crypto.dll`) next to `native/crypto.h`. Coil resolves `dload("crypto")` via `[ffi] search_paths` to `libcrypto.so` / `libcrypto.dylib` / `crypto.dll`. `extern "crypto"` in `src/crypto.hy` already does that load. Application code imports the Coil wrappers. It does not call `dload` itself.

Then:

```coil
use crypto::{sha256, random_bytes, ct_eq, CryptoError};
use string::{to_bytes};

let digest = sha256(to_bytes("hello"))?;
```

## Until spool

There is no public `spool` CLI and this repo has no git tags. Do not put `spool add` or `version = "^0.1"` in a consumer manifest.

Spool will own Coil-to-Coil deps once it exists. Until [COI-219](https://linear.app/ardax/issue/COI-219) tags tls, crypto, and regex together, a git pin lives in `coil.lock` as `rev` plus `content_hash`:

```
# spool lockfile v1
[[package]]
name = 'crypto'
git = 'https://github.com/ardax-corp/coil-crypto.git'
rev = '<commit sha>'
content_hash = '<git tree id>'
```

The compiler does not read `coil.lock` and does not inject roots. Point `[module] roots` at the checkout of that rev.

Native `libcrypto` stays on `[ffi] search_paths` until [COI-60](https://linear.app/ardax/issue/COI-60). Spool does not ship the `.so`.

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

Shipped names in `src/crypto.hy`:

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

Design: [coil-crypto design (v1)](https://linear.app/ardax/document/coil-crypto-design-v1-f48b4876e457).
