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

#ifndef __MODEL_H
#define __MODEL_H

/* Defines common structures, so that Server and Client can use same functions
 *
 * 'owned' means the structure itself holds malloc-ed data and is responsible
 * for freeing it.
 *
 */

#include <glib.h>
#include "ieee802_11/common.h"

#define MAC_ADDRESS_CHAR_SIZE (17+1)
#define HOST_NAME_MAX_SIZE (31+1)
#define SSID_MAX_SIZE (31+1)

struct ssid_record {
    u_char ssid[6];
    u_char assoc[6];
    char ssid_s[MAC_ADDRESS_CHAR_SIZE];
    char hostname_s[HOST_NAME_MAX_SIZE];
    u8 blacklisted;       // 1: if host its currently blacklisted

    le32 fseen;           // first seen
    le32 lseen;           // last seen
    le32 ldeauth;         // last deauth sent
} STRUCT_PACKED;

struct bssid_record {
    struct ssid_record ssid;
    char essid[SSID_MAX_SIZE];

    GSList * hosts; // ssid_record list
};

extern GSList * aps;        // contains owned AP Bssid information
extern GHashTable * hosts;  // contains owned station information

struct ssid_record * host_create(const u_char * mac);
struct bssid_record * ap_create(const u_char * bssid);
struct bssid_record * ap_lookup(const u_char * bssid);
int ap_add_host(const u_char * bssid, const struct ssid_record * host);
int ap_remove_host(const u_char * bssid, const struct ssid_record * host);

int init_model();
int destroy_model();

int write_model(int fd);
int read_model(int fd);

#endif
