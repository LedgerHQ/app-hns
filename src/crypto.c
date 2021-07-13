#include "crypto.h"

#include "cx.h"

int
ledger_blake2b(
  void const * data,
  size_t data_sz,
  void const *digest,
  size_t digest_sz
) {
  if (digest_sz < 1 || digest_sz > 64)
    return 1;

  cx_blake2b_t ctx;
  cx_blake2b_init(&ctx, digest_sz * 8);
  cx_hash(&ctx.header, CX_LAST, data, data_sz, (uint8_t *) digest, digest_sz);
  return 0;
}

void
ledger_blake2b_init(ledger_blake2b_ctx *ctx, size_t digest_sz) {
  cx_blake2b_init(ctx, digest_sz * 8);
}

void
ledger_blake2b_update(
  ledger_blake2b_ctx *ctx,
  void const *data,
  size_t data_sz
) {
  cx_hash(&ctx->header, 0, (uint8_t *) data, data_sz, NULL, 0);
}

void
ledger_blake2b_final(ledger_blake2b_ctx *ctx, void *digest) {
  cx_hash(&ctx->header, CX_LAST, NULL, 0, digest, ctx->output_size);
}

/**
 * ECDSA BIP32 HD node.
 */
typedef struct ledger_ecdsa_bip32_node_s {
  uint8_t chaincode[32];
  cx_ecfp_private_key_t prv;
  cx_ecfp_public_key_t pub;
} ledger_ecdsa_bip32_node_t;

static void
ledger_ecdsa_derive_node(
  uint32_t *path,
  uint8_t depth,
  ledger_ecdsa_bip32_node_t *n
) {
  uint8_t priv[32];
  os_perso_derive_node_bip32(CX_CURVE_256K1, path, depth, priv, n->chaincode);
  cx_ecdsa_init_private_key(CX_CURVE_256K1, priv, 32, &n->prv);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &n->pub, &n->prv, true);
  n->pub.W[0] = n->pub.W[64] & 1 ? 0x03 : 0x02;
}

void
ledger_ecdsa_derive_xpub(ledger_ecdsa_xpub_t *xpub) {
  /* Derive child node and store pubkey & chain code. */
  ledger_ecdsa_bip32_node_t n;
  ledger_ecdsa_derive_node(xpub->path, xpub->depth, &n);
  memmove(xpub->key, n.pub.W, sizeof(xpub->key));
  memmove(xpub->code, n.chaincode, sizeof(xpub->code));
  memset(&n.prv, 0, sizeof(n.prv));

  /* Set parent fingerprint to 0x00000000. */
  memset(xpub->fp, 0, sizeof(xpub->fp));

  /* If parent exists, store fingerprint. */
  if (xpub->depth > 1) {
    uint8_t buf32[32];
    uint8_t buf20[20];
    union {
      cx_sha256_t sha256;
      cx_ripemd160_t ripemd;
    } ctx;

    ledger_ecdsa_derive_node(xpub->path, xpub->depth - 1, &n);
    cx_sha256_init(&ctx.sha256);
    cx_hash(&ctx.sha256.header, CX_LAST, n.pub.W, 33, buf32, sizeof(buf32));
    cx_ripemd160_init(&ctx.ripemd);
    cx_hash(&ctx.ripemd.header, CX_LAST, buf32, sizeof(buf32), buf20, sizeof(buf20));
    memmove(xpub->fp, buf20, sizeof(xpub->fp));
    memset(&n.prv, 0, sizeof(n.prv));
  }
}

/**
 * Parses a DER encoded signature and returns a 64 byte buffer of R & S.
 *
 * Based on:
 * https://github.com/bitcoin-core/secp256k1/blob/abe2d3e/src/ecdsa_impl.h#L145
 *
 * In:
 * @param der is the DER encoded signature.
 * @param der_len is the length of the DER encoded signature.
 * @param sig_sz is the size of the signature buffer.
 *
 * Out:
 * @param sig is the decoded signature.
 * @return a boolean indicating success or failure.
 */
static inline bool
parse_der(uint8_t *der, uint8_t der_len, uint8_t *sig, uint8_t sig_sz) {
  if (der == NULL || der_len < 70 || der_len > 72)
    return false;

  if (sig == NULL || sig_sz < 64)
    return false;

  uint8_t const *der_end = der + der_len;
  int overflow = 0;
  int len = 0;

  /* Prepare signature for padding. */
  memset(sig, 0, sig_sz);

  /* Check initial byte for correct format. */
  if (der == der_end || *(der++) != 0x30)
    return false;

  /* Check length of remaining data. */
  len = *(der++);

  if ((len & 0x80) != 0x00)
    return false;

  if (len <= 0 || der + len > der_end)
    return false;

  if (der + len != der_end)
    return false;

  /* Check tag byte for R. */
  if (der == der_end || *(der++) != 0x02)
    return false;

  /* Check length of R. */
  len = *(der++);

  if ((len & 0x80) != 0)
    return false;

  if (len <= 0 || der + len > der_end)
    return false;

  /* Check padding of R. */

  /* Excessive 0x00 padding. */
  if (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00)
    return false;

  /* Excessive 0xff padding. */
  if (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80)
    return false;

  /* Check sign of the length. */
  if ((der[0] & 0x80) == 0x80)
    overflow = 1;

  /* Skip leading zero bytes. */
  while (len > 0 && der[0] == 0) {
    len--;
    der++;
  }

  if (len > 32)
    overflow = 1;

  if (!overflow)
    memmove(sig + 32 - len, der, len);

  if (overflow)
    memset(sig, 0, 32);

  der += len;
  sig += 32;
  overflow = 0;

  /* Check tag byte for S. */
  if (der == der_end || *(der++) != 0x02)
    return false;

  /* Check length of S. */
  len = *(der++);

  if ((len & 0x80) != 0)
    return false;

  if (len <= 0 || der + len > der_end)
    return false;

  /* Check padding of S. */

  /* Excessive 0x00 padding. */
  if (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00)
    return false;

  /* Excessive 0xff padding. */
  if (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80)
    return false;

  /* Check sign of the length. */
  if ((der[0] & 0x80) == 0x80)
    overflow = 1;

  /* Skip leading zero bytes. */
  while (len > 0 && der[0] == 0) {
    len--;
    der++;
  }

  if (len > 32)
    overflow = 1;

  if (!overflow)
    memmove(sig + 32 - len, der, len);

  if (overflow)
    memset(sig, 0, 32);

  der += len;

  if (der != der_end)
    return false;

  return true;
}

bool
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  uint8_t *sig,
  uint8_t sig_sz
) {
  uint8_t der_sig[72];
  ledger_ecdsa_bip32_node_t n;
  ledger_ecdsa_derive_node(path, depth, &n);
  cx_ecdsa_sign(&n.prv, CX_RND_RFC6979 | CX_LAST, CX_SHA256,
    hash, hash_len, der_sig, sizeof(der_sig), NULL);

  return parse_der(der_sig, der_sig[1] + 2, sig, sig_sz);
}

bool
ledger_sha256(const void *data, size_t data_sz, void *digest) {
  if (digest == NULL)
    return false;

  if (data == NULL)
    return false;

  if (data_sz < 1)
    return false;

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash(&sha256.header, CX_LAST, data, data_sz, digest, 32);

  return true;
}

bool
ledger_sha3(const void *data, size_t data_sz, void *digest) {
  if (digest == NULL)
    return false;

  if (data == NULL)
    return false;

  if (data_sz < 1)
    return false;

  cx_sha3_t sha3;
  cx_sha3_init(&sha3, 256);
  cx_hash(&sha3.header, CX_LAST, data, data_sz, digest, 32);

  return true;
}
