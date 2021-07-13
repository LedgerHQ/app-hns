#pragma once

#include "cx.h"
#include "ledger.h"

/**
 * Blake2b context.
 */
typedef cx_blake2b_t ledger_blake2b_ctx;

/**
 * BIP32 ECDSA Extended Public Key.
 */
typedef struct ledger_ecdsa_xpub_s {
  uint8_t code[32];
  uint8_t key[33];
  uint8_t fp[4];
  uint8_t depth;
  uint32_t path[LEDGER_MAX_DEPTH];
} ledger_ecdsa_xpub_t;

/**
 * Helper function that generates a blake2b digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data, in bytes.
 * @param digest_sz is the length of the hash digest, in bytes.
 *
 * Out:
 * @param digest is the hash digest.
 */
int
ledger_blake2b(
  void const *data,
  size_t data_sz,
  void const *digest,
  size_t digest_sz
);

/**
 * Initializes the blake2b hash context.
 *
 * In:
 * @param ctx is the blake2b context.
 * @param digest_sz is the length of the hash digest, in bytes.
 */
void
ledger_blake2b_init(ledger_blake2b_ctx *ctx, size_t digest_sz);

/**
 * Updates the blake2b hash context.
 *
 * In:
 * @param ctx is the blake2b context.
 * @param data is the data to hash.
 * @param data_sz is the length of the data, in bytes.
 */
void
ledger_blake2b_update(
  ledger_blake2b_ctx *ctx,
  void const *data,
  size_t data_sz
);

/**
 * Returns blake2b hash digest.
 *
 * In:
 * @param ctx is the blake2b context.
 *
 * Out:
 * @param digest is the hash digest.
 */
void
ledger_blake2b_final(ledger_blake2b_ctx *ctx, void *digest);

/**
 * Derives an ECDSA extended public key.
 *
 * Out:
 * @param xpub is the extended public key.
 */
void
ledger_ecdsa_derive_xpub(ledger_ecdsa_xpub_t *xpub);

/**
 * Returns an ECDSA signature.
 *
 * In:
 * @param path is an array of indices used to derive the signing key.
 * @param depth is the number of levels to derive in the HD tree.
 * @param hash is the hash to be signed.
 * @param hash_len is the length of the hash.
 *
 * Out:
 * @param sig is the resultant signature.
 */
bool
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  uint8_t *sig,
  uint8_t sig_len
);

/**
 * Returns sha256 hash digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data.
 *
 * Out:
 * @param digest is the hash digest.
 * @return boolean indicating success or failure.
 */
bool
ledger_sha256(const void *data, size_t data_sz, void *digest);

/**
 * Returns sha3 hash digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data.
 *
 * Out:
 * @param digest is the hash digest.
 * @return boolean indicating success or failure.
 */
bool
ledger_sha3(const void *data, size_t data_sz, void *digest);
