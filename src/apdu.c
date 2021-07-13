#include "apdu.h"

/**
 * Size of the apdu cache buffer.
 */
#define LEDGER_APDU_CACHE_SIZE 114

/**
 * IO exchange buffer for the APDU protocol messages.
 */
static uint8_t *g_ledger_apdu_buffer;

/**
 * Size of the IO exchange buffer.
 */
static uint16_t g_ledger_apdu_buffer_size;

/**
 * Cache buffer used to save data between APDU calls.
 */
static uint8_t g_ledger_apdu_cache[LEDGER_APDU_CACHE_SIZE];

/**
 * Total size of the cache buffer.
 */
static uint8_t g_ledger_apdu_cache_size;

/**
 * Length of data currently stored in the cache.
 */
static uint8_t g_ledger_apdu_cache_len;

void
ledger_apdu_init(void) {
  g_ledger_apdu_buffer = G_io_apdu_buffer;
  g_ledger_apdu_buffer_size = sizeof(G_io_apdu_buffer);
  g_ledger_apdu_cache_size = sizeof(g_ledger_apdu_cache);
  g_ledger_apdu_cache_len = 0;

  memset(g_ledger_apdu_buffer, 0, g_ledger_apdu_buffer_size);
  memset(g_ledger_apdu_cache, 0, g_ledger_apdu_cache_size);
}

void
ledger_apdu_buffer_clear(void) {
  memset(g_ledger_apdu_buffer, 0, g_ledger_apdu_buffer_size);
}

bool
ledger_apdu_cache_write(const uint8_t *src, uint8_t src_len) {
  if (src_len < 1)
    return false;

  if (src_len > g_ledger_apdu_cache_size)
    return false;

  if (src == NULL)
    src = g_ledger_apdu_buffer;

  memmove(g_ledger_apdu_cache, src, src_len);
  g_ledger_apdu_cache_len = src_len;
  ledger_apdu_buffer_clear();

  return true;
}

uint8_t
ledger_apdu_cache_flush(uint16_t *len) {
  uint8_t *cache = g_ledger_apdu_cache;
  uint8_t *buffer = g_ledger_apdu_buffer;
  uint8_t cache_len = g_ledger_apdu_cache_len;
  uint16_t buffer_len = 0;

  if (cache_len == 0)
    return 0;

  if (len == NULL)
    len = &buffer_len;

  if (*len + cache_len > g_ledger_apdu_buffer_size)
    return 0;

  if (*len > 0) {
    buffer += 5; /* Don't overwrite APDU header. */
    memmove(buffer + cache_len, buffer, *len);
  }

  memmove(buffer, cache, cache_len);
  *len += cache_len;
  ledger_apdu_cache_clear();

  return cache_len;
}

uint8_t
ledger_apdu_cache_check(void) {
  return g_ledger_apdu_cache_len;
}

void
ledger_apdu_cache_clear(void) {
  memset(g_ledger_apdu_cache, 0, g_ledger_apdu_cache_size);
  g_ledger_apdu_cache_len = 0;
}

uint16_t
ledger_apdu_exchange(uint8_t flags, uint16_t len, uint16_t sw) {
  if (sw) {
    g_ledger_apdu_buffer[len++] = sw >> 8;
    g_ledger_apdu_buffer[len++] = sw & 0xff;
  }

  return io_exchange(CHANNEL_APDU | flags, len);
}
