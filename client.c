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

static GHashTable * whois = NULL;   // contains owns MAC -> Name mapping
static GSList * notexpanded = NULL; // contains onwn MAC: list of not expdanded aps
static sigset_t unblock_mask;
static int serverfd = -1;
static int curline = 0;             // the current selected line
static int vpsize = 0;              // the lines the viewport lines available
static int voffset = 0;             // the first displayed line of the viewport
static u_char curmac[6] = {0};      // the current selected mac

/**********************************************************************/
#include <ncurses.h>

#define UI_INPUT_DELAY 1
#define UI_WINDOW_H 24
#define UI_WINDOW_W 80
#define UI_WINDOW_PADDING_X 2
#define UI_WINDOW_PADDING_Y 1
#define UI_WINDOW_HEADER_H 1
#define UI_WINDOW_HOSTS_CHAN 49
#define UI_WINDOW_HEADER_RIGHT 50
#define UI_WINDOW_HEADER_TOTH (UI_WINDOW_HEADER_H + UI_WINDOW_PADDING_Y)
#define UI_WINDOW_HOSTS_TOTH (UI_WINDOW_H - 4 * UI_WINDOW_PADDING_Y - UI_WINDOW_HEADER_TOTH)
#define UI_WINDOW_HOSTS_RIGHT 56
#define UI_PALETTE_NORMAL 1
#define UI_PALETTE_BLACKLISTED 2

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
        start_color();
        use_default_colors();
        init_pair(UI_PALETTE_NORMAL, COLOR_CYAN, COLOR_BLACK);
        init_pair(UI_PALETTE_BLACKLISTED, COLOR_BLACK, COLOR_RED);
    }
    //TODO decide what to do if colors are unavailable

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

static int is_expanded(const u_char * bssid) {
    return g_slist_find_custom(notexpanded, bssid, ssid_in_list_fn) == NULL;
}

static int toggle_expansion() {
    // must be an ap to expand
    if (! ap_lookup(curmac))
        return -1;

    GSList * node = g_slist_find_custom(notexpanded, curmac, ssid_in_list_fn);

    if (node == NULL) {
        // do not expand
        u_char * ownmac = (u_char *) malloc(6);
        memcpy(ownmac, curmac, 6);
        notexpanded = g_slist_append(notexpanded, ownmac);
    } else {
        // expand
        free(node->data);
        notexpanded = g_slist_delete_link(notexpanded, node);
    }

    return 0;
}

/*#define xprintw(win, x, ...) do{\
    int _y, _x;\
    (void)(_x);\
    getyx(win, _y, _x);\
    mvwprintw(win, _y, x, ##__VA_ARGS__);\
}while(0)*/

void ui_update_hosts() {
    int y = 0;              // window real y
    int vpy = 0;            // viewport virtual y

    wclear(hostsw);

    for (GSList * link = aps; link != NULL; link=link->next) {
        char * essid = NULL;
        struct bssid_record * rec = (struct bssid_record *)link->data;
        char * manualname = (char *) g_hash_table_lookup(whois, rec->ssid.ssid);
        if (manualname)
            essid = manualname;
        else
            essid = (char *)rec->essid;

        int isexpanded =  is_expanded(rec->ssid.ssid);

        if (vpy >= voffset && vpy < (voffset + UI_WINDOW_HOSTS_TOTH)) {
            int palette = UI_PALETTE_NORMAL;
            if (rec->ssid.blacklisted)
                palette = UI_PALETTE_BLACKLISTED;

            if (vpy == curline) {
                wprintw(hostsw, "*");
            } else if (isexpanded) {
                wprintw(hostsw, "-");
            } else {
                wprintw(hostsw, "+");
            }

            wprintw(hostsw, "BSSID ");
            wattron(hostsw, COLOR_PAIR(palette));
            wprintw(hostsw, "%s", rec->ssid.ssid_s);
            wattroff(hostsw, COLOR_PAIR(palette));
            if (essid[0])
                wprintw(hostsw, " %s", essid);
            wprintw(hostsw, " [%u]  %d dBm", g_slist_length(rec->hosts), rec->signal);

            if (rec->channel > 0)
                mvwprintw(hostsw, y, UI_WINDOW_HOSTS_CHAN, "CH %u", rec->channel);
            mvwprintw(hostsw, y, UI_WINDOW_HOSTS_RIGHT, "%s\n", time_format(rec->ssid.lseen));

            y++;
        }
        vpy++;

        if (isexpanded) {
            for (GSList * item = rec->hosts; item != NULL; item = item->next) {
                const struct ssid_record * host = (const struct ssid_record *) item->data;

                const char * stationame = (char *) g_hash_table_lookup(whois, host->ssid);

                if (vpy >= voffset && vpy < (voffset + UI_WINDOW_HOSTS_TOTH)) {
                    if (vpy == curline) {
                        wprintw(hostsw, "*   ");
                    } else if (host->blacklisted) {
                        wprintw(hostsw, "B   ");
                    }
                    else {
                        wprintw(hostsw, "    ");
                    }

                    int palette = UI_PALETTE_NORMAL;
                    if (host->blacklisted) {
                        palette = UI_PALETTE_BLACKLISTED;
                    }

                    wattron(hostsw, COLOR_PAIR(palette));
                    wprintw(hostsw, "%s", host->ssid_s);
                    wattroff(hostsw, COLOR_PAIR(palette));

                    if (stationame)
                        wprintw(hostsw, " %s", stationame);
                    else if (host->hostname_s)
                        wprintw(hostsw, " %s", host->hostname_s);

                    mvwprintw(hostsw, y, UI_WINDOW_HOSTS_RIGHT, "%s\n", time_format(host->lseen));
                    y++;
                }
                vpy++;
            }
        }
    }

    wrefresh(hostsw);
}

/**********************************************************************/

#define BLACKLIST_CMD_PRE "blacklist "
#define CLEAR_CMD_PRE "clear "

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

/* Saves selected mac based on curline variable */
static int ui_save_selection() {
    int l = 0;
    u_char * found = NULL;

    for(GSList * aplink = aps; aplink != NULL; aplink=aplink->next) {
        struct bssid_record * ap = (struct bssid_record *)aplink->data;

        if (curline == l) {
            found = ap->ssid.ssid;
            break;
        }

        if (is_expanded(ap->ssid.ssid)) {
            for (GSList * link = ap->hosts; link != NULL; link=link->next) {
                l++;

                if (curline == l) {
                    found = ((struct ssid_record *)link->data)->ssid;
                    break;
                }
            }

            if (found)
                break;
        }

        l++;
    }

    if (found) {
        memcpy(curmac, found, 6);
        return 0;
    }

    return -1;
}

/* Updates the current selection and the view over the viewport */
static void ui_update_sel(int newv) {
    const int corrected = max(min(newv, vpsize-1), 0);

    curline = corrected;

    if (curline < voffset)
        voffset = curline;
    else if (curline >= voffset + UI_WINDOW_HOSTS_TOTH)
        voffset = curline - UI_WINDOW_HOSTS_TOTH + 1;

    ui_save_selection();
    ui_update_hosts();
}


/*
 * Restores curline based on selected mac variable.
 *
 * Defaults to 0.
 *
 * Also update vpsize variable
 *
 */
static int ui_restore_selection() {
    int l = 0;
    int found = -1;

    for(GSList * aplink = aps; aplink != NULL; aplink=aplink->next) {
        struct bssid_record * ap = (struct bssid_record *)aplink->data;

        if(memcmp(ap->ssid.ssid, curmac, 6) == 0)
            found = l;

        if (is_expanded(ap->ssid.ssid)) {
            for (GSList * link = ap->hosts; link != NULL; link=link->next) {
                struct ssid_record * host = (struct ssid_record *)link->data;
                l++;

                if (memcmp(host->ssid, curmac, 6) == 0)
                    found = l;
            }
        }

        l++;
    }

    vpsize = l;

    if (found >= 0) {
        ui_update_sel(found);
        return 0;
    } else {
        ui_update_sel(0);
        return -1;
    }
}

static int read_names_mapping(const char * fname) {
    FILE * f = fopen(fname, "rt");
    if (!f) {
        perror_msg("Cannot open names mapping: ");
        return -1;
    }

    char buf[256];
    uint intmac[6];
    uint count;

    while(fgets(buf, sizeof(buf), f)) {
        u_char * mac = (u_char *)malloc(6);
        char * name = (char *)calloc(128, 1);

        if (sscanf(buf, "%2x:%2x:%2x:%2x:%2x:%2x | %127s\n",
          intmac, intmac+1, intmac+2, intmac+3, intmac+4, intmac+5, name) == 7) {
            for (int i=0; i<6; i++)
                mac[i] = (u_char)intmac[i];

            // table retains ownership on mac and name: it's up to it to free
            g_hash_table_insert(whois, mac, name);

            count++;
        } else {
            free(mac);
            free(name);
        }
    }
    fclose(f);

    debug_msg("Loaded %u MAC mappings", count);

    return 0;
}

static int init_env() {
    init_timezone();

    whois = g_hash_table_new_full(mac_hash_fn, mac_equal_fn, free_fn, free_fn);
    if (whois == NULL) {
        error_msg("Cannot allocate whois memory");
        return -1;
    }

    if (init_model() < 0)
        return -1;

    return 0;
}

static void destroy_env() {
    g_hash_table_destroy(whois);        // frees keys(macs) and values(names)
    g_slist_free_full(notexpanded, free_fn);
    whois = NULL;
    destroy_model();
}

static int toggle_host_blacklist() {
    int bl = -1;

    struct bssid_record * ap = ap_lookup(curmac);
    if (ap) {
        bl = ! ap->ssid.blacklisted;
        ap->ssid.blacklisted = bl;
    } else {
        struct ssid_record * host = (struct ssid_record *) g_hash_table_lookup(hosts, curmac);
        if (host) {
            bl = ! host->blacklisted;
            host->blacklisted = bl;
        }
    }

    if (bl < 0)
        return -1;

    if (bl)
        send_blacklist_command(curmac);
    else
        send_clear_command(curmac);
    return 0;
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

    if (process_setup() < 0) {
        end_ui();
        return 1;
    }

    if (read_names_mapping("hosts.cfg") == 0)
        usleep(1000*600);

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
                            ui_update_sel(curline - 1);
                            break;
                        case KEY_DOWN:
                            ui_update_sel(curline + 1);
                            break;
                        case KEY_PPAGE:
                            ui_update_sel(curline - UI_WINDOW_HOSTS_TOTH);
                            break;
                        case KEY_NPAGE:
                            ui_update_sel(curline + UI_WINDOW_HOSTS_TOTH);
                            break;
                        case KEY_HOME:
                            ui_update_sel(0);
                            break;
                        case KEY_END:
                            ui_update_sel(vpsize-1);
                            break;
                        case ' ':
                            if (toggle_host_blacklist() == 0)
                                ui_update_hosts();
                            break;
                        case KEY_ENTER:
                        case 0x0a:
                            if (toggle_expansion() == 0) {
                                ui_restore_selection();
                                ui_update_hosts();
                            }
                            break;
                        case 'q':
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
                    wprintw(headerw, "Scanned %u APs with %u total hosts", g_slist_length(aps), g_hash_table_size(hosts));
                    mvwprintw(headerw, 0, UI_WINDOW_HEADER_RIGHT, "updated: %s", time_format(time(0)));
                    wrefresh(headerw);

                    ui_restore_selection();
                }
        }
    }

    now_exit(0);
    return 0;
}
