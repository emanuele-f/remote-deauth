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
#include <signal.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "internals.h"
#include "config.h"

static char * ifname = "mon0";
static sigset_t unblock_mask;
static int sockfd = -1;
static int clsock = -1;

static char readbuf[256];

static void sigHandler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        puts("Shutting down...");

        if (clsock >= 0)
            close(clsock);

        if (sockfd >= 0)
            close(sockfd);

        destroy_internals();
        exit(0);
    } /*else if (signo == SIGALRM) {
        alarm(ALARM_SLEEP);
    }*/
}

static inline int process_setup() {
    // disable signals now
    if (sigprocmask(0, NULL, &unblock_mask) == -1) {
        perror("sigprocmask() error while getting set:");
        return -1;
    }
    sigset_t block_mask = unblock_mask;
    if (sigaddset(&block_mask, SIGINT) == -1 ||
      sigaddset(&block_mask, SIGTERM) == -1 ||
      sigaddset(&block_mask, SIGALRM) == -1) {
        perror("sigaddset() error:");
        return -1;
    }
    if (sigprocmask(SIG_SETMASK, &block_mask, NULL) == -1) {
        perror("sigprocmask() error while setting set:");
        return -1;
    }

    struct sigaction sa = {};
    sa.sa_handler = sigHandler;
    sa.sa_mask = block_mask;

    if(sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction(SIGINT) error:");
        return -1;
    }
    if(sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction(SIGTERM) error:");
        return -1;
    }
    if(sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction(SIGALRM) error:");
        return -1;
    }

    //~ alarm(ALARM_SLEEP);

    return 0;
}

static int handle_client_connection() {
    struct sockaddr_in cli_addr;
    socklen_t clsize = sizeof(cli_addr);

    int newsock = accept(sockfd, (struct sockaddr *) &cli_addr, &clsize);
    const char *ip = inet_ntoa(cli_addr.sin_addr);

    if (clsock > 0) {
        close(newsock);
        printf("Client %s rejected\n", ip);
        return -1;
    } else {
        clsock = newsock;
        printf("Client %s connected\n", ip);

        // try to set keep alive stuff
        int rv = 0;
        const int optlen = 1;
        rv -= setsockopt(clsock, SOL_SOCKET, SO_KEEPALIVE, &optlen, sizeof(int));
        const int seconds = SERVER_KEEPALIVE_TIMEOUT;
        rv -= setsockopt(clsock, SOL_TCP, TCP_KEEPIDLE, &seconds, sizeof(int));
        const int interval = SERVER_KEEPALIVE_INTERVAL;
        rv -= setsockopt(clsock, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
        const int maxpck = SERVER_KEEPALIVE_COUNT;
        rv -= setsockopt(clsock, SOL_TCP, TCP_KEEPCNT, &maxpck, sizeof(int));
        if (rv < 0)
            fprintf(stderr, "Errors setting KEEPALIVE options\n");

        return 0;
    }
}

enum ServerCommand {
    SC_UNKNOWN,
    SC_ADDTO_BLACKLIST,
    SC_ADDTO_WHITELIST,
    SC_CLEAR_HOST,
    //~ SC_MODE_BLACKLIST,
    //~ SC_MODE_WHITELIST,
};

static void handle_client_read() {
    size_t count = read_line(clsock, readbuf, sizeof(readbuf));

    if (count == 0) {
        printf("Client disconnected\n");
        close(clsock);
        clsock = -1;
    } else {
        char cmd[32] = {0};

        if (sscanf(readbuf, "%31s", cmd) == 1) {
            enum ServerCommand cmdtype = SC_UNKNOWN;

            if (strcmp(cmd, "blacklist") == 0)
                cmdtype = SC_ADDTO_BLACKLIST;
            else if (strcmp(cmd, "whitelist") == 0)
                cmdtype = SC_ADDTO_WHITELIST;
            else if (strcmp(cmd, "clear") == 0)
                cmdtype = SC_CLEAR_HOST;

            if (cmdtype != SC_UNKNOWN) {
                uint intmac[6];

                if (sscanf(readbuf + strlen(cmd), "%02x:%02x:%02x:%02x:%02x:%02x",
                  intmac, intmac+1, intmac+2, intmac+3, intmac+4, intmac+5) == 6) {
                    u_char mac[6];

                    for(int i=0; i<6; i++)
                        mac[i] = (u_char) intmac[i];

                    switch(cmdtype) {
                        case SC_ADDTO_BLACKLIST:
                            host_blacklist(mac);
                            printf("Blacklist command done\n");
                            break;
                        case SC_ADDTO_WHITELIST:
                            //TODO implement
                            break;
                        case SC_CLEAR_HOST:
                            host_unblacklist(mac);
                            printf("Clear command done\n");
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
}

static void main_loop() {
    const int capfd = pcap_fileno(capdev);
    int highest;
    struct timespec timeout = {0};
    time_t lastsent = 0;
    fd_set readfds;
    FD_ZERO(&readfds);

    while(1) {
        // re-init on each cycle
        FD_SET(capfd, &readfds);
        FD_SET(sockfd, &readfds);
        if (clsock > 0) {
            FD_SET(clsock, &readfds);
            highest = clsock + 1;
        } else {
            highest = sockfd + 1;
        }
        timeout.tv_nsec = READ_TIMEOUT * 1000 * 1000;

        switch(pselect(highest, &readfds, NULL, NULL, &timeout, &unblock_mask)) {
            case -1:
                if (errno != EINTR)
                    perror("select() error:");
                break;
            case 0:
                // No incoming data
                perform_attack();

                if (clsock > 0 && (time(0) - lastsent) > SERVER_SENDATA_INTERVAL_SEC) {
                    write_model(clsock);
                    lastsent = time(0);
                }
                break;
            default:
                if (FD_ISSET(capfd, &readfds)) {
                    struct pcap_pkthdr h;
                    const u_char * data;
                    const size_t datalen = read_packet(&data);

                    if (datalen > 0)
                        pckdata_handler(data, datalen, &h);
                }
                if (FD_ISSET(sockfd, &readfds)) {
                    handle_client_connection();
                }
                if (clsock>0 && FD_ISSET(clsock, &readfds)) {
                    handle_client_read();
                }
        }
    }
}

static int server_setup() {
    struct sockaddr_in serv_addr = {0};
    const int enable = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("Cannot create socket");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("Cannot set SO_REUSEADDR on socket");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("Cannot bind socket");
        return -1;
    }

    if (listen(sockfd, SERVER_BACKLOCK) < 0) {
        perror("Cannot listen on socket");
        return -1;
    }

    printf("Server listening on port %u\n", SERVER_PORT);

    return 0;
}

int main() {
    if (init_internals(ifname) < 0)
        return 1;

    if (process_setup() < 0)
        return 1;

    if (server_setup() < 0)
        return 1;

    main_loop();

    destroy_internals();
    return 0;
}

