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

//~ #include "debug.h"

static GHashTable * whois = NULL;  // contains owns MAC -> Name mapping
static int serverfd = -1;

/**********************************************************************/
#include <ncurses.h>

#define UI_INPUT_DELAY 1
#define UI_WINDOW_H 24
#define UI_WINDOW_W 80
#define UI_WINDOW_PADDING_X 2
#define UI_WINDOW_PADDING_Y 1
#define UI_WINDOW_HEADER_H 1
#define UI_WINDOW_HEADER_RIGHT 50
#define UI_WINDOW_HEADER_TOTH (UI_WINDOW_HEADER_H + UI_WINDOW_PADDING_Y)
#define UI_WINDOW_HOSTS_TOTH (UI_WINDOW_H - 4 * UI_WINDOW_PADDING_Y - UI_WINDOW_HEADER_TOTH)

static WINDOW * mainw = NULL;
static WINDOW * headerw = NULL;
static WINDOW * wbox = NULL;
static WINDOW * hostsw = NULL;

static void init_ui() {
    initscr();
    noecho();

    // Nonblocking getch: return after UI_INPUT_DELAY/10 seconds
    halfdelay(UI_INPUT_DELAY);
    curs_set(0);

    // Colors init where available
    if(has_colors() == TRUE) {
    }
    
    mainw = newwin(UI_WINDOW_H, UI_WINDOW_W, 0, 0);
    headerw = derwin(mainw,
      UI_WINDOW_HEADER_TOTH,
      UI_WINDOW_W - 2 * UI_WINDOW_PADDING_X,
      UI_WINDOW_PADDING_Y, UI_WINDOW_PADDING_X);
    wbox = derwin(mainw,
      UI_WINDOW_HOSTS_TOTH + 2 * UI_WINDOW_PADDING_Y,
      UI_WINDOW_W - 2 * UI_WINDOW_PADDING_X,
      UI_WINDOW_HEADER_TOTH + UI_WINDOW_PADDING_Y, UI_WINDOW_PADDING_X);
      
    hostsw = derwin(wbox,
      UI_WINDOW_HOSTS_TOTH,
      UI_WINDOW_W - 4 * UI_WINDOW_PADDING_X,
      UI_WINDOW_PADDING_Y, UI_WINDOW_PADDING_X);
    
    //~ box(mainw, 0, 0);
    //~ box(headerw, 0, 0);
    box(wbox, 0, 0);
    //~ box(hostsw, 0, 0);
    wrefresh(mainw);
}

#define debug_msg(msg, ...) do {\
    wclear(headerw);\
    wprintw(headerw, msg, ##__VA_ARGS__);\
    wrefresh(headerw);\
}while(0)

#define error_msg(msg, ...) do{\
    sleep(1);\
    debug_msg(msg, ##__VA_ARGS__ );\
    exit(1);\
}while(0)

static void end_ui() {
    delwin(hostsw);
    delwin(wbox);
    delwin(headerw);
    delwin(mainw);
    endwin();
}

static void bssid_iterate_fn(gpointer key, gpointer value, gpointer udata) {
    char * essid = NULL;

    struct bssid_record * rec = (struct bssid_record *)value;
    char * manualname = (char *) g_hash_table_lookup(whois, rec->ssid.ssid);
    if (manualname)
        essid = manualname;
    else
        essid = (char *)rec->essid;

    wprintw(hostsw, "BSSID %s <%s>\n", rec->ssid.ssid_s, essid);
    for (GSList * item = rec->hosts; item != NULL; item = item->next) {
        const struct ssid_record * host = (const struct ssid_record *) item->data;

        const char * stationame = (char *) g_hash_table_lookup(whois, host->ssid);
        if (stationame)
            wprintw(hostsw, "\t%s <%s> (seen %s)\n", host->ssid_s, stationame, time_format(host->lseen));
        else
            wprintw(hostsw, "\t%s (seen %s)\n", host->ssid_s, time_format(host->lseen));
    }
}

void ui_update_hosts() {
    wclear(hostsw);
    g_hash_table_foreach((GHashTable *)aps, bssid_iterate_fn, NULL);
    wrefresh(hostsw);
}

/**********************************************************************/

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

    debug_msg("Loaded %u MAC mappings (%d black, %d white)", (defctr+whitectr+blackctr), blackctr, whitectr);

    return 0;
}

static int init_env() {
    init_timezone();

    whois = g_hash_table_new_full(mac_hash_fn, mac_equal_fn, free_fn, free_fn);
    if (whois == NULL) {
        g_hash_table_destroy(aps);
        g_hash_table_destroy(hosts);
        aps = NULL;
        error_msg("Cannot allocate whois memory");
        return -1;
    }

    if (init_model() < 0)
        return -1;

    return 0;
}

static void destroy_env() {
    g_hash_table_destroy(whois);        // frees keys(macs) and values(names)
    whois = NULL;
    destroy_model();
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
        error_msg("Cannot resolve server address");
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
    init_ui();
    
    if(init_env() < 0)
        return 1;
        
    debug_msg("Connecting to the server...");

    if(server_connect() < 0)
        return 1;
        
    debug_msg("Connected!");

    read_names_mapping("hosts.cfg");
    sleep(1);

    while(1) {
        if (read_model(serverfd) < 0)
            break;
            
        wclear(headerw);
        wprintw(headerw, "Scanned 3 APs with 10 total hosts");
        mvwprintw(headerw, 0, UI_WINDOW_HEADER_RIGHT, "updated: %s", time_format(time(0)));
        wrefresh(headerw);
        
        ui_update_hosts();
    }

    close(serverfd);

    destroy_env();
    
    end_ui();
    return 0;
}
