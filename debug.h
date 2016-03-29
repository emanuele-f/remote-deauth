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

#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdlib.h>
#include <glib.h>
#include "ieee802_11.h"

void print_wlan_header(const struct ieee80211_hdr * data, size_t size, const struct ieee802_11_elems * elems);
void hex_dump(const char *desc, const void *addr, int len);
void debug_print_bssids(const GHashTable * aps, const GHashTable * whois);

#endif
