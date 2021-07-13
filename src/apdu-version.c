/**
 * apdu-version.c - app version number for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#include "apdu.h"
#include "ledger.h"

uint8_t
hns_apdu_get_app_version(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  uint8_t *in __attribute__((unused)),
  uint8_t *out,
  volatile uint8_t *flags __attribute__((unused))
) {
  if (!ledger_unlocked())
    THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

  if(p1 != 0)
    THROW(HNS_INCORRECT_P1);

  if(p2 != 0)
    THROW(HNS_INCORRECT_P2);

  if(len != 0)
    THROW(HNS_INCORRECT_LC);

  /* Constants defined in Makefile. */
  out[0] = HNS_APP_MAJOR_VERSION;
  out[1] = HNS_APP_MINOR_VERSION;
  out[2] = HNS_APP_PATCH_VERSION;

  return 3;
}
