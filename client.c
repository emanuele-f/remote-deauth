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
#include <errno.h>

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
static sigset_t unblock_mask;
static int serverfd = -1;
static int curline = 0;
static int maxlines = 10;

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
#define UI_WINDOW_HOSTS_RIGHT 55

static WINDOW * mainw = NULL;
static WINDOW * headerw = NULL;
static WINDOW * wbox = NULL;
static WINDOW * hostsw = NULL;

static void init_ui() {
    initscr();
    noecho();
    cbreak();
    curs_set(FALSE);

    // Nonblocking getch: return after UI_INPUT_DELAY/10 seconds
    halfdelay(UI_INPUT_DELAY);

    // Colors init where available
    if(has_colors() == TRUE) {
    }
    
    mainw = newwin(UI_WINDOW_H, UI_WINDOW_W, 0, 0);
    
    // NOTE: this must be set on the top window!!
    keypad(mainw, TRUE);
    
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
    debug_msg(msg, ##__VA_ARGS__ );\
    sleep(1);\
}while(0)

#define perror_msg(msg) do{\
    error_msg("%s: %s", msg, strerror(errno));\
}while(0)

static void end_ui() {
    delwin(hostsw);
    delwin(wbox);
    delwin(headerw);
    delwin(mainw);
    endwin();
}

/*#define xprintw(win, x, ...) do{\
    int _y, _x;\
    (void)(_x);\
    getyx(win, _y, _x);\
    mvwprintw(win, _y, x, ##__VA_ARGS__);\
}while(0)*/

static void bssid_iterate_fn(gpointer key, gpointer value, gpointer udata) {
    char * essid = NULL;
    int x, y;
    (void)x;
    getyx(hostsw, y, x);

    struct bssid_record * rec = (struct bssid_record *)value;
    char * manualname = (char *) g_hash_table_lookup(whois, rec->ssid.ssid);
    if (manualname)
        essid = manualname;
    else
        essid = (char *)rec->essid;

    if (y == curline) {
        wprintw(hostsw, "*");
    } else {
        wprintw(hostsw, "-");
    }
    wprintw(hostsw, "BSSID %s <%s>", rec->ssid.ssid_s, essid);
    mvwprintw(hostsw, y, UI_WINDOW_HOSTS_RIGHT, "%s\n", time_format(rec->ssid.lseen));
    
    for (GSList * item = rec->hosts; item != NULL; item = item->next) {
        const struct ssid_record * host = (const struct ssid_record *) item->data;
        y++;

        const char * stationame = (char *) g_hash_table_lookup(whois, host->ssid);
        
        if (y == curline) {
            //~ wprintw(hostsw, "*");
        } else {
            //~ wprintw(hostsw, "-");
        }
        
        wprintw(hostsw, "\t%s ", host->ssid_s);
        
        if (stationame)
            wprintw(hostsw, "<%s>", stationame);
            
        mvwprintw(hostsw, y, UI_WINDOW_HOSTS_RIGHT, "%s\n", time_format(host->lseen));
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
        perror_msg("Cannot open names mapping: ");
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
        perror_msg("Cannot create socket");
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
        perror_msg("connect()");
        return -1;
    }

    return 0;
}

static void now_exit(int code) {
    if (serverfd >= 0)
        close(serverfd);
    serverfd = -1;
    destroy_env();
    end_ui();
    exit(code);
}

static void sigHandler(int signo) {
    if (signo == SIGINT || signo == SIGTERM || signo == SIGHUP)
        now_exit(0);
}

static int process_setup() {
    // disable signals now
    if (sigprocmask(0, NULL, &unblock_mask) == -1) {
        perror_msg("sigprocmask() error while getting set:");
        return -1;
    }
    sigset_t block_mask = unblock_mask;
    if (sigaddset(&block_mask, SIGINT) == -1 ||
      sigaddset(&block_mask, SIGTERM) == -1 ||
      sigaddset(&block_mask, SIGHUP) == -1) {
        perror_msg("sigaddset() error");
        return -1;
    }
    if (sigprocmask(SIG_SETMASK, &block_mask, NULL) == -1) {
        perror_msg("sigprocmask() error while setting set");
        return -1;
    }

    struct sigaction sa = {};
    sa.sa_handler = sigHandler;
    sa.sa_mask = block_mask;

    if(sigaction(SIGINT, &sa, NULL) == -1) {
        perror_msg("sigaction(SIGINT) error");
        return -1;
    }
    if(sigaction(SIGTERM, &sa, NULL) == -1) {
        perror_msg("sigaction(SIGTERM) error");
        return -1;
    }
    if(sigaction(SIGHUP, &sa, NULL) == -1) {
        perror_msg("sigaction(SIGHUP) error");
        return -1;
    }

    return 0;
}

int main() {
    init_ui();
    
    if (process_setup() < 0) {
        end_ui();
        return 1;
    }
    
    if(init_env() < 0) {
        end_ui();
        return 1;
    }
        
    debug_msg("Connecting to the server...");

    if(server_connect() < 0) {
        destroy_env();
        end_ui();
        return 1;
    }
        
    debug_msg("Connected!");

    read_names_mapping("hosts.cfg");
    //~ usleep(1000*500);
    
    fd_set readfds;
    struct timespec timeout = {0};
    FD_ZERO(&readfds);
    int ch;

    while(1) {
        // re-init on each cycle
        FD_SET(serverfd, &readfds);
            
        switch(pselect(serverfd+1, &readfds, NULL, NULL, &timeout, &unblock_mask)) {
            case -1:
                if (errno != EINTR) {
                    perror_msg("select() error:");
                    now_exit(1);
                }
                break;
            case 0:
                // this slows down the loop
                if ((ch = wgetch(mainw)) != ERR) {
                    switch(ch) {
                        case KEY_UP:
                            if (curline > 0) {
                                curline--;
                                ui_update_hosts();
                            }
                            break;
                        case KEY_DOWN:
                            if (curline < maxlines-1) {
                                curline++;
                                ui_update_hosts();
                            }
                            break;
                        case ' ':
                            break;
                        case 'q':
                        case 0x1b:
                            now_exit(0);
                            break;
                    }
                }
                break;
            default:
                if (FD_ISSET(serverfd, &readfds)) {
                    if (read_model(serverfd) < 0)
                        now_exit(1);
                        
                    wclear(headerw);
                    wprintw(headerw, "Scanned 3 APs with 10 total hosts");
                    mvwprintw(headerw, 0, UI_WINDOW_HEADER_RIGHT, "updated: %s", time_format(time(0)));
                    wrefresh(headerw);
                    
                    ui_update_hosts();
                }
        }
    }

    now_exit(0);
    return 0;
}
