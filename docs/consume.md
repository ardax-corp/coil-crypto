# Consuming coil-crypto

Sibling checkout (until spool), in the consumer `coil.toml`:

```toml
[module]
roots = ["./src", "../coil-crypto/src"]

[ffi]
search_paths = ["../coil-crypto/native"]
```

Build the native library from this repo (`make`, or `cargo build --release` in `native/` and copy `libcrypto.so` / `.dylib` / `.dll` next to `native/crypto.h`).

```coil
use crypto::{sha256, random_bytes, ct_eq, CryptoError};
```

`dload("crypto")` is what `extern "crypto"` in this package already does.

Design: [coil-crypto design (v1)](https://linear.app/ardax/document/coil-crypto-design-v1-f48b4876e457).
