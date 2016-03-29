#ifndef WPA_PRINTF_H
#define WPA_PRINTF_H

/*
 * Emanuele Faranda
 *
 * Dummy header: redirect calls
 */

enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};

#define wpa_printf(lv, fmt, ...) printf("%s:" fmt, #lv, __VA_ARGS__)

#endif
