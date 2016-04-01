/*
 * Copyright (c) 2016 Emanuele Faranda <black.silver@hotmail.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

#include <unistd.h>
#include <errno.h>
#include "util.h"
#include "model.h"

static char hex[] = "0123456789ABCDEF";
static u_char BROADCAST_BSSID[] = "\xFF\xFF\xFF\xFF\xFF\xFF";
static char TimeString[15+1];
static int32_t thiszone = 0;

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* Excludes uncommon MAC address ranges: http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml */
int is_valid_mac(const u_char addr[6]) {
    const uint32_t mecH = (addr[0] << 16) | (addr[1] << 8) | (addr[2]);

    return !(
        (mecH == 0x00005E) ||                      // IANA OUI Unicast
        (mecH == 0x01005E) ||                      // IANA OUI Multicast
        (mecH >= 0x333300 && mecH <= 0x33FFFF)     // IPv6 Multicast
    );
}

/* Based on the packet type, returns a pair (bssid, apstation).
 * Pointers are set to NULL when no relevant information is found.
 */
void get_bssid_and_station(const struct ieee80211_hdr * pck, const u_char ** bssid, const u_char ** station) {
    //~ u8 flags = WLAN_FC_GET_FLAGS(pck->frame_control);
    //~ const bool fromds = WLAN_FC_FLAG(pck->frame_control, WLAN_FC_FROMDS);
    //~ const bool tods = WLAN_FC_FLAG(pck->frame_control, WLAN_FC_TODS);
    //~ printf("FLAGS: 0x%02x %d %d\n", flags, fromds, tods);

    const u8 ds = (pck->frame_control & (WLAN_FC_FROMDS | WLAN_FC_TODS)) >> 8;
    //~ printf("DS: 0x%x\n", ds);

    switch(ds) {
        case 0x0:
            // AD-HOC mode or DS internal packet (eg. beacon)
            *bssid = pck->addr3;
            *station = NULL;
            break;
        case 0x1:
            // From an host to the DS
            *bssid = pck->addr1;
            *station = pck->addr2;
            break;
        case 0x2:
            // From a DS to an host
            *station = pck->addr1;
            *bssid = pck->addr2;
            break;
        case 0x3:
            // From a DS to another: Transmitter taken as BSSID
            *station = NULL;
            *bssid = pck->addr2;
            break;
        default:
            *station = NULL;
            *bssid = NULL;
    }

    // esclude broadcasts
    if (*bssid && (memcmp(*bssid, BROADCAST_BSSID, 6) == 0 || ! is_valid_mac(*bssid)) )
        *bssid = NULL;
    if (*station && (memcmp(*station, BROADCAST_BSSID, 6) == 0 || ! is_valid_mac(*station)) )
        *station = NULL;
}

const char * time_format(time_t t) {
    const int s = (t + thiszone) % 86400;
    snprintf(TimeString, sizeof(TimeString), "%02d:%02d:%02d.%06u",
      s / 3600, (s % 3600) / 60, s % 60, (unsigned)t);

    return (const char *)TimeString;
}

void init_timezone() {
    // Init timezone
    thiszone = gmt2local(0);
}

size_t write_checked(int fd, const void * data, size_t size) {
    size_t count = write(fd, data, size);
    if (count < 0) {
        perror("write()");
        return -1;
    }

    if (count < size) {
        fprintf(stderr, "Error: written only %u/%u\n", count, size);
        return -1;
    }

    return count;
}

/* Wait to read exactly [bytes] or disconnection */
size_t read_checked(int fd, void * out, size_t bytes) {
    size_t ctr = 0;

    while (ctr < bytes) {
        size_t count = read(fd, ((u_char *)out) + ctr, bytes-ctr);

        if (count < 0) {
            perror("read()");
            return -1;
        } else if (count == 0) {
            fprintf(stderr, "Disconnected\n");
            return 0;
        }

        ctr += count;
    }

    return ctr;
}

/* From http://man7.org/tlpi/code/online/book/sockets/read_line.c.html */
ssize_t read_line(int fd, void *buffer, size_t n) {
    ssize_t numRead;                    /* # of bytes fetched by last read() */
    size_t totRead;                     /* Total bytes read so far */
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = buffer;                       /* No pointer arithmetic on "void *" */

    totRead = 0;
    for (;;) {
        numRead = read(fd, &ch, 1);

        if (numRead == -1) {
            if (errno == EINTR)         /* Interrupted --> restart read() */
                continue;
            else
                return -1;              /* Some other error */

        } else if (numRead == 0) {      /* EOF */
            if (totRead == 0)           /* No bytes read; return 0 */
                return 0;
            else                        /* Some bytes read; add '\0' */
                break;

        } else {                        /* 'numRead' must be 1 if we get here */
            if (totRead < n - 1) {      /* Discard > (n - 1) bytes */
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n')
                break;
        }
    }

    *buf = '\0';
    return totRead;
}

uint8_t get_channel(uint16_t frequency) {
	switch(frequency){
		case 2412:
			return 1;
		case 2417:
			return 2;
		case 2422:
			return 3;
		case 2427:
			return 4;
		case 2432:
			return 5;
		case 2437:
			return 6;
		case 2442:
			return 7;
		case 2447:
			return 8;
		case 2452:
			return 9;
		case 2457:
			return 10;
		case 2462:
			return 11;
		case 2467:
			return 12;
		case 2472:
			return 13;
		case 2484:
			return 14;
	}
	return 0;
}

/**************************************************************************/

void free_fn(void * item) {
    free(item);
}

guint mac_hash_fn(gconstpointer key) {
    const u8 * k = (u8 *)key;

    // 32 bit integer VS 48 bit MAC address: [0][3][4][5]
    return (k[0] << 24) | (k[3] << 16) | (k[4] << 8) | (k[5] << 0);
}

gboolean mac_equal_fn(gconstpointer a, gconstpointer b) {
    const u8 * k1 = (u8 *) a;
    const u8 * k2 = (u8 *) b;

    return memcmp(k1, k2, 6) == 0;
}

int ssid_in_list_fn(const void * item, const void * macaddr) {
    struct ssid_record * host = (struct ssid_record * )item;
    return memcmp(host->ssid, macaddr, 6);
}
