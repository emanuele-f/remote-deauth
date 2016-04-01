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

#ifndef __INTERNALS_H
#define __INTERNALS_H

#include <pcap/pcap.h>
#include <glib.h>
#include "ieee802_11.h"
#include "util.h"
#include "model.h"

#define SNAPLEN 4000
#define READ_TIMEOUT 1

#define DEAUTH_INTERVAL 1
#define BETWEEN_DIRECTED_TIMEOUT_USEC 10
#define DEAUTH_DIRECTED 64

#define RADIOTAP_WR_LEN 0x0c
#define BUF_LEN 4096
#define WRBUF_LEN (BUF_LEN - RADIOTAP_WR_LEN)

extern GSList * blacklist;  // contains owns MAC addresses * which are blacklisted
extern GSList * attacking;  // contains ssid_record * under attack
extern pcap_t * capdev;

extern const u_char NULL_MAC[6];

/*#define DEAUTH_REQ      \
    "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"*/

int read_packet(const u_char ** dataptr, size_t * len);
int init_internals(const char * ifname);
int destroy_internals();

void perform_attack();
void pckdata_handler(const u_char * radiodata, size_t radiolen);

int host_blacklist(u_char host[6]);
int host_unblacklist(u_char host[6]);

#endif
