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

#include <stdio.h>

#include "debug.h"
#include "util.h"
#include "model.h"

static void bssid_iterate_print_fn(gpointer key, gpointer value, gpointer udata) {
    GHashTable * whois = (GHashTable *)udata;
    char * essid = NULL;

    struct bssid_record * rec = (struct bssid_record *)value;
    char * manualname = (char *) g_hash_table_lookup(whois, rec->ssid.ssid);
    if (manualname)
        essid = manualname;
    else
        essid = (char *)rec->essid;

    printf("BSSID %s <%s>\n", rec->ssid.ssid_s, essid);
    for (GSList * item = rec->hosts; item != NULL; item = item->next) {
        const struct ssid_record * host = (const struct ssid_record *) item->data;

        const char * stationame = (char *) g_hash_table_lookup(whois, host->ssid);
        if (stationame)
            printf("\t%s <%s> (seen %s)\n", host->ssid_s, stationame, time_format(host->lseen));
        else
            printf("\t%s (seen %s)\n", host->ssid_s, time_format(host->lseen));
    }
}

/**************************************************************************/

void print_wlan_header(const struct ieee80211_hdr * data,
  size_t size,
  const struct ieee802_11_elems * elems) {
    const int type = WLAN_FC_GET_TYPE(data->frame_control);
    char * type_s;
    WLANSTR_switch(type)
        WLANSTR_case(WLAN_FC_TYPE_MGMT)
        WLANSTR_case(WLAN_FC_TYPE_CTRL)
        WLANSTR_case(WLAN_FC_TYPE_DATA)
        WLANSTR_default(WLANSTR_UNKNOWN)
    WLANSTR_esac(type_s)
    printf("\t   Type: %s\n", type_s);

    const int subtype = WLAN_FC_GET_STYPE(data->frame_control);
    char * subtype_s;
    if (type == WLAN_FC_TYPE_MGMT) {
        WLANSTR_switch(subtype)
            WLANSTR_case(WLAN_FC_STYPE_ASSOC_REQ)
            WLANSTR_case(WLAN_FC_STYPE_ASSOC_RESP)
            WLANSTR_case(WLAN_FC_STYPE_REASSOC_REQ)
            WLANSTR_case(WLAN_FC_STYPE_REASSOC_RESP)
            WLANSTR_case(WLAN_FC_STYPE_PROBE_REQ)
            WLANSTR_case(WLAN_FC_STYPE_PROBE_RESP)
            WLANSTR_case(WLAN_FC_STYPE_BEACON)
            WLANSTR_case(WLAN_FC_STYPE_ATIM)
            WLANSTR_case(WLAN_FC_STYPE_DISASSOC)
            WLANSTR_case(WLAN_FC_STYPE_AUTH)
            WLANSTR_case(WLAN_FC_STYPE_DEAUTH)
            WLANSTR_case(WLAN_FC_STYPE_ACTION)
            WLANSTR_default(WLANSTR_UNKNOWN)
        WLANSTR_esac(subtype_s)
    } else if (type == WLAN_FC_TYPE_CTRL) {
        WLANSTR_switch(subtype)
            WLANSTR_case(WLAN_FC_STYPE_PSPOLL)
            WLANSTR_case(WLAN_FC_STYPE_RTS)
            WLANSTR_case(WLAN_FC_STYPE_CTS)
            WLANSTR_case(WLAN_FC_STYPE_ACK)
            WLANSTR_case(WLAN_FC_STYPE_CFEND)
            WLANSTR_case(WLAN_FC_STYPE_CFENDACK)
            WLANSTR_default(WLANSTR_UNKNOWN)
        WLANSTR_esac(subtype_s)
    } else if (type == WLAN_FC_TYPE_DATA) {
        // TODO maybe
        subtype_s = "*data subtype*";
    } else {
        subtype_s = WLANSTR_UNKNOWN;
    }

    printf("\tSubtype: %s\n", subtype_s);
    printf("\tFragment #: %u\n", WLAN_GET_SEQ_FRAG(data->seq_ctrl));
    printf("\tSequence #: %u\n", WLAN_GET_SEQ_SEQ(data->seq_ctrl));

    if (type == WLAN_FC_TYPE_MGMT) {
        const struct ieee80211_mgmt * frame = (struct ieee80211_mgmt *)data;

        char src[MAC_ADDRESS_CHAR_SIZE];
        char dst[MAC_ADDRESS_CHAR_SIZE];
        char bssid[MAC_ADDRESS_CHAR_SIZE];

        etheraddr_string(frame->sa, src);
        etheraddr_string(frame->da, dst);
        etheraddr_string(frame->bssid, bssid);

        printf("\tBSSID: %s\n\t From: %s\n\t   To: %s\n", bssid, src, dst);

        if (subtype == WLAN_FC_STYPE_BEACON) {
            if (elems->ssid_len > 0) {
                char name[elems->ssid_len + 1];
                strncpy(name, (char *)elems->ssid, elems->ssid_len);
                name[elems->ssid_len] = '\0';

                printf("\t SSID: %s\n", name);
            }


            //~ } else
                //~ hexDump("---", frame->u.beacon.variable, elen);
            //~ }
        }
    }
}

void hex_dump(const char *desc, const void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

void debug_print_bssids(const GHashTable * aps, const GHashTable * whois) {
    printf("\n---Report\n");
    g_hash_table_foreach((GHashTable *)aps, bssid_iterate_print_fn, (GHashTable *)whois);
    printf("---\n");
}
