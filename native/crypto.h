/* coil-crypto C ABI — RustCrypto cdylib loaded via dload("crypto"). */
#ifndef COIL_CRYPTO_H
#define COIL_CRYPTO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CoilCryptoHasher CoilCryptoHasher;

/* Error tags written to err_out (CryptoError). */
#define COIL_CRYPTO_ERR_INVALID_INPUT 0
#define COIL_CRYPTO_ERR_INVALID_LENGTH 1
#define COIL_CRYPTO_ERR_AUTHENTICATION_FAILED 2
#define COIL_CRYPTO_ERR_UNSUPPORTED_ALGORITHM 3
#define COIL_CRYPTO_ERR_ALREADY_FINALIZED 4
#define COIL_CRYPTO_ERR_OTHER 5

/* Return: byte count on success, -1 on error (err_out set). Empty input may use a null ptr. */
int64_t coil_crypto_sha256(const uint8_t *data, uint64_t data_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_sha512(const uint8_t *data, uint64_t data_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_blake3(const uint8_t *data, uint64_t data_len, uint8_t *out, uint64_t out_len, int64_t *err_out);

CoilCryptoHasher *coil_crypto_hasher_init(int64_t alg, int64_t *err_out);
int64_t coil_crypto_hasher_update(CoilCryptoHasher *handle, const uint8_t *data, uint64_t data_len, int64_t *err_out);
int64_t coil_crypto_hasher_finalize(CoilCryptoHasher *handle, uint8_t *out, uint64_t out_len, int64_t *err_out);
void coil_crypto_hasher_free(CoilCryptoHasher *handle);

int64_t coil_crypto_hmac_sha256(const uint8_t *key, uint64_t key_len, const uint8_t *data, uint64_t data_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_hmac_sha512(const uint8_t *key, uint64_t key_len, const uint8_t *data, uint64_t data_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_hmac_verify_sha256(const uint8_t *key, uint64_t key_len, const uint8_t *data, uint64_t data_len, const uint8_t *tag, uint64_t tag_len, int64_t *err_out);

int64_t coil_crypto_random_bytes(uint64_t n, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_random_u64(int64_t *value_out, int64_t *err_out);

int64_t coil_crypto_chacha20_poly1305_encrypt(const uint8_t *key, uint64_t key_len, const uint8_t *nonce, uint64_t nonce_len, const uint8_t *plaintext, uint64_t plaintext_len, const uint8_t *aad, uint64_t aad_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_chacha20_poly1305_decrypt(const uint8_t *key, uint64_t key_len, const uint8_t *nonce, uint64_t nonce_len, const uint8_t *ciphertext, uint64_t ciphertext_len, const uint8_t *aad, uint64_t aad_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_aes_256_gcm_encrypt(const uint8_t *key, uint64_t key_len, const uint8_t *nonce, uint64_t nonce_len, const uint8_t *plaintext, uint64_t plaintext_len, const uint8_t *aad, uint64_t aad_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_aes_256_gcm_decrypt(const uint8_t *key, uint64_t key_len, const uint8_t *nonce, uint64_t nonce_len, const uint8_t *ciphertext, uint64_t ciphertext_len, const uint8_t *aad, uint64_t aad_len, uint8_t *out, uint64_t out_len, int64_t *err_out);

int64_t coil_crypto_ed25519_generate(uint8_t *secret_out, uint8_t *public_out, int64_t *err_out);
int64_t coil_crypto_ed25519_sign(const uint8_t *secret, uint64_t secret_len, const uint8_t *msg, uint64_t msg_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_ed25519_verify(const uint8_t *public_key, uint64_t public_len, const uint8_t *msg, uint64_t msg_len, const uint8_t *sig, uint64_t sig_len, int64_t *err_out);

int64_t coil_crypto_x25519_generate(uint8_t *secret_out, uint8_t *public_out, int64_t *err_out);
int64_t coil_crypto_x25519_shared_secret(const uint8_t *secret, uint64_t secret_len, const uint8_t *public_key, uint64_t public_len, uint8_t *out, uint64_t out_len, int64_t *err_out);

int64_t coil_crypto_argon2id_hash(const uint8_t *password, uint64_t password_len, const uint8_t *salt, uint64_t salt_len, uint8_t *out, uint64_t out_len, int64_t *err_out);
int64_t coil_crypto_argon2id_verify(const uint8_t *password, uint64_t password_len, const uint8_t *hash, uint64_t hash_len, int64_t *err_out);

int64_t coil_crypto_ct_eq(const uint8_t *a, uint64_t a_len, const uint8_t *b, uint64_t b_len);

uint8_t *coil_crypto_alloc(uint64_t n);
void coil_crypto_free(uint8_t *ptr, uint64_t n);
void coil_crypto_store_u8(uint8_t *ptr, uint64_t i, int64_t v);
int64_t coil_crypto_load_u8(const uint8_t *ptr, uint64_t i);

#ifdef __cplusplus
}
#endif

#endif
