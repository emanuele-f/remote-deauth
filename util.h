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

#ifndef __UTIL_H
#define __UTIL_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "ieee802_11.h"

#define WLANSTR_switch(t) { char * __hrmxe = NULL; switch((t)) {
#define WLANSTR_case(c) case (c): __hrmxe = #c; break;
#define WLANSTR_default(d) default: __hrmxe = d; break;
#define WLANSTR_esac(store) } (store) = __hrmxe; }
#define min(x, y) ((x) <= (y) ? (x) : (y))
#define max(x, y) ((x) >= (y) ? (x) : (y))

#define WLANSTR_UNKNOWN "*unknown*"

enum pck_direction_e {
    PCKDIR_UNKNOWN,
    PCKDIR_AP_TO_STATION,
    PCKDIR_STATION_TO_AP,
};

char* etheraddr_string(const u_char *ep, char *buf);
const char * human_format_u32(uint32_t value);
int32_t gmt2local(time_t t);
int is_valid_mac(const u_char addr[6]);
void get_bssid_and_station(const struct ieee80211_hdr * pck,
  const u_char ** bssid,
  const u_char ** station,
  enum pck_direction_e * dir);
const char * time_format(time_t t);
void free_fn(void * item);

size_t write_checked(int clsock, const void * data, size_t size);
size_t read_checked(int fd, void * out, size_t bytes);
ssize_t read_line(int fd, void *buffer, size_t n);
uint8_t get_channel(uint16_t frequency);

int ssid_in_list_fn(const void * item, const void * macaddr);
guint mac_hash_fn(gconstpointer key);
gboolean mac_equal_fn(gconstpointer a, gconstpointer b);
void init_timezone();

#endif
