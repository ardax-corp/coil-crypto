# Consuming coil-crypto

This package is `crypto`. `use crypto::{sha256}` resolves from this repo's `src/`. RustCrypto lives in `libcrypto.so` / `.dylib` / `crypto.dll`. `extern "crypto"` in `src/crypto.hy` already calls `dload("crypto")`. Put the built library on `[ffi] search_paths`. The VM does not register crypto HostInvoke slots. `use crypto` without this package on `roots` is a module-not-found error.

Coil-to-Coil deps will be spool-owned once a public `spool` CLI exists. Until [COI-219](https://linear.app/ardax/issue/COI-219) this repo has no git tags and there is no `spool add`. Pin `rev` + `content_hash` in `coil.lock` if you are not on a sibling checkout. Native libs stay on `[ffi] search_paths` until [COI-60](https://linear.app/ardax/issue/COI-60).

## Sibling checkout

In the consumer `coil.toml`:

```toml
[module]
roots = ["./src", "../coil-crypto/src"]

[ffi]
search_paths = ["../coil-crypto/native"]
```

Build the native library from this package root:

```bash
make
```

`libcrypto.so` (or `.dylib` / `crypto.dll`) must sit on `[ffi] search_paths` so `dload("crypto")` resolves. `roots` must include this package's `src/` so `use crypto::{…}` resolves here. Application code imports the Coil wrappers. It does not call `dload` itself.

Then:

```coil
use crypto::{sha256, random_bytes, ct_eq, CryptoError};
use string::{to_bytes};

let digest = sha256(to_bytes("hello"))?;
```

## coil.lock pin (until spool)

[COI-219](https://linear.app/ardax/issue/COI-219) is the cut that tags tls, crypto, and regex together and switches consumers to `spool add`. Until then, do not write `crypto = { git = "…", version = "^0.1" }` and do not run `spool add crypto`. Those do not resolve. The compiler does not read `coil.lock` and does not inject roots.

Pin this package in the consumer `coil.lock` with `git`, `rev`, and `content_hash`. Omit `tag`.

```
# spool lockfile v1
[[package]]
name = 'crypto'
git = 'https://github.com/ardax-corp/coil-crypto.git'
rev = '5934ada57c4eb580dea81881c0419ed12b53a2ad'
content_hash = '808dec9957d989eb20315f41b50740ff34afba85'
```

`rev` is the commit. `content_hash` is that commit's git tree (`git rev-parse 'HEAD^{tree}'`). Replace both when you move the pin. The values above are `main` at `5934ada` (userland package + RustCrypto cdylib). They are an example, not a release.

Clone that rev onto a path you then list in `coil.toml`. `.spool/deps/crypto` is the layout spool will use later:

```bash
git clone https://github.com/ardax-corp/coil-crypto.git .spool/deps/crypto
git -C .spool/deps/crypto checkout --detach 5934ada57c4eb580dea81881c0419ed12b53a2ad
test "$(git -C .spool/deps/crypto rev-parse 'HEAD^{tree}')" = 808dec9957d989eb20315f41b50740ff34afba85
make -C .spool/deps/crypto
```

```toml
[module]
roots = ["./src", "./.spool/deps/crypto/src"]

[ffi]
search_paths = ["./.spool/deps/crypto/native"]
```

`make` copies `libcrypto.so` (or `.dylib` / `crypto.dll`) into that `native/` dir. Leave it on `[ffi] search_paths`. Spool will not fetch the cdylib until [COI-60](https://linear.app/ardax/issue/COI-60).

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
