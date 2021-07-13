/**
 * ledger.c - wrapper for the Ledger Nanos Secure SDK
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#include <stdbool.h>
#include "ledger.h"

uint8_t *
ledger_init(void) {
  ledger_apdu_init();
  io_seproxyhal_init();

#ifdef TARGET_NANOX
  G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif

  USB_power(false);
  USB_power(true);

  ledger_ui_init();

#ifdef HAVE_BLE
  BLE_power(0, NULL);
  BLE_power(1, "Nano X");
#endif

  return G_io_apdu_buffer;
}

void
ledger_boot(void) {
  os_boot();
}

void
ledger_reset(void) {
  reset();
}

void
ledger_exit(uint32_t code) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(code);
    }
    FINALLY_L(exit);
  }
  END_TRY_L(exit);
}

bool
ledger_unlocked(void) {
  return os_global_pin_is_validated() == BOLOS_UX_OK;
}

/**
 * BOLOS SDK variable definitions.
 *
 * All variables below this point are never called within the app
 * source code, but are necessary for the SDK to function properly.
 *
 * For more details see:
 * https://github.com/ledgerhq/nanos-secure-sdk
 */

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#if defined(HAVE_UX_FLOW)
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
#else
ux_state_t ux;
#endif

/**
 * BOLOS SDK function definitions.
 *
 * All functions below this point are never called within the app
 * source code, but are necessary for the SDK to function properly.
 *
 * For more details see:
 * https://github.com/ledgerhq/nanos-secure-sdk
 */

uint8_t
io_event(uint8_t channel __attribute__((unused))) {
  switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
      UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
      break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
      UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
      break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
      UX_DISPLAYED_EVENT({});
      break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
      UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
      break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
      if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
          !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
            SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
        THROW(EXCEPTION_IO_RESET);
      }
      // Intentional fall through.
    default:
      UX_DEFAULT_EVENT();
      break;
  }

  if (!io_seproxyhal_spi_is_status_sent())
    io_seproxyhal_general_status();

  return 1;
}

uint16_t
io_exchange_al(uint8_t channel, uint16_t tx_len) {
  switch (channel & ~IO_FLAGS) {
    case CHANNEL_SPI:
      if (tx_len) {
        io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

        if (channel & IO_RESET_AFTER_REPLIED)
          reset();

        return 0;
      } else {
        return io_seproxyhal_spi_recv(
          G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
      }
      break;

    case CHANNEL_KEYBOARD:
      break;

    default:
      THROW(INVALID_PARAMETER);
      break;
  }

  return 0;
}

void
io_seproxyhal_display(const bagl_element_t *element) {
  if ((element->component.type & ~BAGL_TYPE_FLAGS_MASK) != BAGL_NONE)
    io_seproxyhal_display_default((bagl_element_t *)element);
}
