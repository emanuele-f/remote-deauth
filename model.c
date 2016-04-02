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
#include <stdlib.h>
#include <glib.h>
#include "model.h"
#include "util.h"

GSList * aps = NULL;
GHashTable * hosts = NULL;

static void ap_destroy_fn(void * rec) {
    struct bssid_record * host = (struct bssid_record *) rec;

    g_slist_free(host->hosts);
    free(host);
}

static inline int send_client_data(int sock) {
    struct ssid_record lehost = {0};

    // 4 bytes: number of APs
    const le32 naps = host_to_le32(g_slist_length(aps));
    if (write_checked(sock, &naps, sizeof(naps)) < 0)
        return -1;

    for (GSList * link = aps; link != NULL; link = link->next) {
        const struct bssid_record * ap = (struct bssid_record *) link->data;

        // AP ssid
        if (write_checked(sock, &(ap->ssid), sizeof(struct ssid_record)) < 0)
            return -1;

        // AP channel
        if (write_checked(sock, &(ap->channel), 1) < 0)
            return -1;

        // AP signal
        if (write_checked(sock, &(ap->signal), 1) < 0)
            return -1;

        // AP essid
        if (write_checked(sock, ap->essid, SSID_MAX_SIZE) < 0)
            return -1;

        // 4 bytes: number of hosts
        const le32 nhosts = host_to_le32(g_slist_length(ap->hosts));
        if (write_checked(sock, &nhosts, sizeof(nhosts)) < 0)
            return -1;

        for (GSList * i=ap->hosts; i!=NULL; i = i->next) {
            const struct ssid_record * host = (struct ssid_record *) i->data;
            lehost = *host;
            lehost.fseen = host_to_le32(lehost.fseen);
            lehost.lseen = host_to_le32(lehost.lseen);
            lehost.ldeauth = host_to_le32(lehost.ldeauth);
            lehost.datasent = host_to_le32(lehost.datasent);
            lehost.datarecv = host_to_le32(lehost.datarecv);

            if (write_checked(sock, &lehost, sizeof(struct ssid_record)) < 0)
                return -1;
        }
    }

    return 0;
}

static inline int read_server_data(int fd) {
    le32 naps;

    if (read_checked(fd, &naps, sizeof(naps)) <= 0)
        return -1;
    naps = le_to_host32(naps);

    //~ printf("Reading %u ap elements\n", naps);lehost.fseen = host_to_le32(lehost.fseen);

    struct ssid_record ap;
    for (uint i=0; i<naps; i++) {
        // AP info
        if (read_checked(fd, &ap, sizeof(ap)) <= 0)
            return -1;

        struct bssid_record * newap = ap_create(ap.ssid);
        newap->ssid = ap;

        if (read_checked(fd, &(newap->channel), 1) < 0)
            return -1;

        if (read_checked(fd, &(newap->signal), 1) < 0)
            return -1;

        if (read_checked(fd, newap->essid, SSID_MAX_SIZE) < 0)
            return -1;

        le32 nhosts;
        if (read_checked(fd, &nhosts, sizeof(nhosts)) <= 0)
            return -1;
        nhosts = le_to_host32(nhosts);

        //~ printf("Has %u hosts\n", nhosts);

        struct ssid_record host;
        for (uint j=0; j < nhosts; j++) {

            if (read_checked(fd, &host, sizeof(struct ssid_record)) <= 0)
                return -1;
            host.fseen = le_to_host32(host.fseen);
            host.lseen = le_to_host32(host.lseen);
            host.ldeauth = le_to_host32(host.ldeauth);
            host.datasent = le_to_host32(host.datasent);
            host.datarecv = le_to_host32(host.datarecv);
            //~ printf("Host: %s\n", host.ssid_s);

            struct ssid_record * newhost = host_create(host.ssid);
            memcpy(newhost, &host, sizeof(struct ssid_record));

            ap_add_host(ap.ssid, newhost);
        }
    }

    return 0;
}

static int bssid_in_list_fn(const void * item, const void * macaddr) {
    struct bssid_record * host = (struct bssid_record * )item;
    return memcmp(host->ssid.ssid, macaddr, 6);
}

struct bssid_record * ap_lookup(const u_char * bssid) {
    GSList * link = g_slist_find_custom(aps, bssid, bssid_in_list_fn);
    if (! link)
        return NULL;
    return (struct bssid_record *) link->data;
}

/**************************************************************************/

struct ssid_record * host_create(const u_char * mac) {
    struct ssid_record * host = (struct ssid_record *)calloc(sizeof(struct ssid_record), 1);
    if (host == NULL) {
        perror("Cannot allocate station memory:");
        return NULL;
    }

    memcpy(host->ssid, mac, 6);
    etheraddr_string(mac, host->ssid_s);

    g_hash_table_insert(hosts, host->ssid, host);
    return host;
}

/*
int host_destroy(struct ssid_record * host) {
    if (memcmp(host->assoc, NULL_MAC, 6) != 0)
        ap_remove_host(host->assoc, host);

    if (! g_hash_table_remove(hosts, host->ssid))
        return -1;

    attacking = g_slist_remove_all(attacking, host->ssid);

    free(host);
    return 0;
}*/

struct bssid_record * ap_create(const u_char * bssid) {
    if (g_slist_find_custom(aps, bssid, bssid_in_list_fn) != NULL)
        return NULL;

    struct bssid_record * rec = (struct bssid_record *)calloc(sizeof(struct bssid_record), 1);
    memcpy(rec->ssid.ssid, bssid, 6);
    etheraddr_string(rec->ssid.ssid, (char *)rec->ssid.ssid_s);
    rec->hosts = NULL;

    aps = g_slist_append(aps, rec);
    return rec;
}

int ap_add_host(const u_char * bssid, const struct ssid_record * host) {
    struct bssid_record * ap = ap_lookup(bssid);
    if (! ap)
        return -1;

    ap->hosts = g_slist_append(ap->hosts, (void *) host);
    return 0;
}

int ap_remove_host(const u_char * bssid, const struct ssid_record * host) {
    struct bssid_record * ap = ap_lookup(bssid);
    if (! ap)
        return -1;

    ap->hosts = g_slist_remove(ap->hosts, host);
    return 0;
}

int init_model() {
    hosts = g_hash_table_new_full(mac_hash_fn, mac_equal_fn, NULL, free_fn);
    if (hosts == NULL) {
        fprintf(stderr, "Cannot allocate hosts memory\n");
        return -1;
    }

    return 0;
}

int destroy_model() {
    g_slist_free_full(aps, ap_destroy_fn);      // frees values(aps)
    g_hash_table_destroy(hosts);                // frees values(hosts)
    aps = NULL;
    hosts = NULL;

    return 0;
}

int write_model(int fd) {
    return send_client_data(fd);
}

int read_model(int fd) {
    // create a new model
    if (destroy_model() < 0)
        return -1;
    if (init_model() < 0)
        return -1;

    return read_server_data(fd);
}
