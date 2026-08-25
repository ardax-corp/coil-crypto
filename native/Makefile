# Build libcrypto for coil-crypto FFI (Rust cdylib).

UNAME_S := $(shell uname -s 2>/dev/null)

ifdef MSYSTEM
  LIB := libcrypto.dll
else ifeq ($(OS),Windows_NT)
  LIB := crypto.dll
else ifeq ($(UNAME_S),Darwin)
  LIB := libcrypto.dylib
else
  LIB := libcrypto.so
endif

CARGO_TARGET := target/release/$(LIB)
# Windows GNU/MSVC may emit crypto.dll without the lib prefix.
CARGO_TARGET_ALT := target/release/crypto.dll

.PHONY: all artifact test clean print-artifact

all: artifact

artifact: $(LIB)

$(LIB):
	cargo build --release
	@if [ -f "$(CARGO_TARGET)" ]; then cp "$(CARGO_TARGET)" "$(LIB)"; \
	elif [ -f "$(CARGO_TARGET_ALT)" ]; then cp "$(CARGO_TARGET_ALT)" "$(LIB)"; \
	else ls target/release/; exit 1; fi

test:
	cargo test

print-artifact:
	@echo $(CURDIR)/$(LIB)

clean:
	cargo clean
	rm -f libcrypto.so libcrypto.dylib libcrypto.dll crypto.dll
