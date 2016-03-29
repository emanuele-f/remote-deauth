#ifndef _IEEE_801_11_H
#define _IEEE_801_11_H

/*
 * Emanuele Faranda
 */
/* Includes the necessary libraries */

#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "ieee802_11_common.h"
#include "ieee802_11_defs.h"

typedef u8 wlan_bssid_t[6];

#define WLAN_FC_GET_FLAGS(fc) (((fc) & 0xFF00) >> 8)
#define WLAN_FC_FLAG(fc, mask) ((bool)((fc) & mask))

#endif
