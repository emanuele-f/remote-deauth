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
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "model.h"
#include "config.h"
#include "util.h"

#include "debug.h"

static GHashTable * whois = NULL;  // contains owns MAC -> Name mapping
static int serverfd = -1;

#define BLACKLIST_CMD_PRE "blacklist "
#define CLEAR_CMD_PRE "clear "

enum Section {
    Section_Hosts, Section_Blacklist, Section_Whitelist
};

#define _send_generic_mac_command(mac, preamble) do{\
    char buf[MAC_ADDRESS_CHAR_SIZE + sizeof(preamble) -1] = preamble;\
    etheraddr_string(mac, buf + sizeof(preamble)-1);\
    buf[sizeof(buf)-1] = '\n';\
    if (write_checked(serverfd, buf, sizeof(buf)) < 0)\
        return -1;\
    return 0;\
} while(0)

static int send_blacklist_command(u_char * mac) {
    _send_generic_mac_command(mac, BLACKLIST_CMD_PRE);
}

static int send_clear_command(u_char * mac) {
    _send_generic_mac_command(mac, CLEAR_CMD_PRE);
}

static int read_names_mapping(const char * fname) {
    FILE * f = fopen(fname, "rt");
    if (!f) {
        perror("Cannot open names mapping: ");
        return -1;
    }

    char buf[256];
    char sec[32];
    uint intmac[6];
    uint defctr = 0;
    uint whitectr = 0;
    uint blackctr = 0;
    enum Section section = Section_Hosts;

    while(fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "[%[^]]]\n", sec) == 1) {
            // Section specifier
            if (strcmp(sec, "hosts") == 0)
                section = Section_Hosts;
            else if (strcmp(sec, "blacklist") == 0)
                section = Section_Blacklist;
            else if (strcmp(sec, "whitelist") == 0)
                section = Section_Whitelist;
        } else {
            //TODO add malloc check
            u_char * mac = (u_char *)malloc(6);
            char * name = (char *)calloc(128, 1);

            if (sscanf(buf, "%2x:%2x:%2x:%2x:%2x:%2x | %127s\n",
              intmac, intmac+1, intmac+2, intmac+3, intmac+4, intmac+5, name) == 7) {
                for (int i=0; i<6; i++)
                    mac[i] = (u_char)intmac[i];

                // table retains ownership on mac and name: it's up to it to free
                g_hash_table_insert(whois, mac, name);

                switch(section) {
                    case Section_Hosts:
                        if (send_clear_command(mac) < 0)
                            return -1;
                        defctr++;
                        break;
                    case Section_Blacklist:
                        //// blacklist has own macs
                        //TODO maybe blacklist into model
                        if (send_blacklist_command(mac) < 0)
                            return -1;
                        blackctr++;
                        break;
                    case Section_Whitelist:
                        //TODO whitelist
                        whitectr++;
                        break;
                }
            } else {
                free(mac);
                free(name);
            }
        }
    }
    fclose(f);

    printf("Loaded %u MAC mappings (%d black, %d white)\n", (defctr+whitectr+blackctr), blackctr, whitectr);

    return 0;
}

static int init_env() {
    init_timezone();

    whois = g_hash_table_new_full(mac_hash_fn, mac_equal_fn, free_fn, free_fn);
    if (whois == NULL) {
        g_hash_table_destroy(aps);
        g_hash_table_destroy(hosts);
        aps = NULL;
        fprintf(stderr, "Cannot allocate whois memory\n");
        return -1;
    }

    if (init_model() < 0)
        return -1;

    return 0;
}

static int server_connect() {
    struct sockaddr_in serv_addr = {0};
    struct hostent * serveraddr;

    serverfd = socket(AF_INET, SOCK_STREAM, 0);

    if (serverfd < 0) {
        perror("Cannot create socket");
        return -1;
    }

    serveraddr = gethostbyname(SERVER_ADDRESS);
    if (serveraddr == NULL) {
        fprintf(stderr, "Cannot resolve server address\n");
        return -1;
    }

    memcpy(&serv_addr.sin_addr.s_addr, serveraddr->h_addr, serveraddr->h_length);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (connect(serverfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect()");
        return -1;
    }

    return 0;
}

int main() {
    if(init_env() < 0)
        return 1;

    if(server_connect() < 0)
        return 1;

    printf("Connected\n");

    read_names_mapping("hosts.cfg");

    while(1) {
        if (read_model(serverfd) < 0)
            break;

        // clear screen
        printf("\033[2J\033[1;1H");
        debug_print_bssids(aps, whois);
    }

    close(serverfd);

    g_hash_table_destroy(whois);        // frees keys(macs) and values(names)
    whois = NULL;
    destroy_model();

    return 0;
}
