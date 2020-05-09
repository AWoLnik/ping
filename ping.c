/**
 * Copyright © 2020 Adam Wolnikowski
 * adam.wolnikowski@yale.edu - awolnik.github.io
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PACKETSIZE 64

// Global for controlling the ping loop
int pinging = 1;

struct packet {
    struct icmphdr header;
    char body[PACKETSIZE - sizeof(struct icmphdr)]; // pad the packet to 64 bytes
};

struct packet6 {
    struct icmp6_hdr header;
    char body[PACKETSIZE - sizeof(struct icmp6_hdr)]; // pad the packet to 64 bytes
};

struct rtt {
    long double rtt;
    struct rtt* next;
};

void freerttlist(struct rtt* rttlist) {
    if(rttlist->next != NULL) {
        freerttlist(rttlist->next);
    }
    free(rttlist);
}

// Handler for SIGINT, disables ping loop, prompting report and exit
void interruptHandler(int sig) {
    pinging = 0;
}

// Standard One's Complement checksum function
unsigned short checksum(void *b, int len) {
       unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int ping(int socket_fd, struct sockaddr_storage* send_addr, char* host, int ttl, struct rtt* rttlist, int ipversion) {
    int sent_count=0, received_count=0;
    char ipstr[INET6_ADDRSTRLEN];
    void *spkt, *rpkt;
    unsigned char rbuf[128];
    int received_bytes;
    struct sockaddr_storage receive_addr;
    struct timespec pkt_t_0, pkt_t_1, total_t_0, total_t_1;
    struct timeval timeout;
    timeout.tv_sec = 1.0;
    timeout.tv_usec = 0.0;

    clock_gettime(CLOCK_MONOTONIC, &total_t_0);

    if(ipversion == 6) {
        if(setsockopt(socket_fd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
        {printf("Error\n"); return 1;}

        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)send_addr)->sin6_addr), ipstr, INET6_ADDRSTRLEN);

        spkt = malloc(sizeof(struct packet6));
    } else {
        if(setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
        {printf("Error\n"); return 1;}

        inet_ntop(AF_INET, &(((struct sockaddr_in*)send_addr)->sin_addr), ipstr, INET_ADDRSTRLEN);

        spkt = malloc(sizeof(struct packet));
    }

    if(setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &timeout, sizeof(timeout)) < 0)
    {printf("Error\n"); return 1;}

    printf("PING %s (%s) %ld bytes of data.\n", host, ipstr, sizeof(struct packet));

    // loop pings until SIGINT handler stops it
    while(pinging) {
        memset(spkt, 0, PACKETSIZE);

        if(ipversion == 6) {
            // configure ICMP6 echo packet
            ((struct packet6*)spkt)->header.icmp6_type = ICMP6_ECHO_REQUEST;
            ((struct packet6*)spkt)->header.icmp6_dataun.icmp6_un_data16[0] = (uint16_t) getpid();
            ((struct packet6*)spkt)->header.icmp6_dataun.icmp6_un_data16[1] = (uint16_t) sent_count+1;

            // fill body with chars, leaving null byte at the end
            memset(&(((struct packet6*)spkt)->body), 'A', sizeof(((struct packet6*)spkt)->body)-1);
            // Don't set ICMP6 checksum, as the Linux kernel does it for you
        } else {
            // configure ICMP echo packet
            ((struct packet*)spkt)->header.type = ICMP_ECHO;
            ((struct packet*)spkt)->header.un.echo.id = getpid();
            ((struct packet*)spkt)->header.un.echo.sequence = sent_count+1;

            // fill body with chars, leaving null byte at the end
            memset(&(((struct packet*)spkt)->body), 'A', sizeof(((struct packet*)spkt)->body)-1);
            ((struct packet*)spkt)->header.checksum = checksum(spkt, PACKETSIZE);
        }

        sleep(1);
        clock_gettime(CLOCK_MONOTONIC, &pkt_t_0);

        // send
        if(sendto(socket_fd, spkt, PACKETSIZE, 0, (struct sockaddr*) send_addr,
            sizeof(struct sockaddr_storage)) < PACKETSIZE)
        {
            printf("Send #%d failed!\n", sent_count+1);
            if(ipversion == 6) {printf("Ensure that your system and network support IPV6.\n");}
            continue;
        }

        // receive
        memset(&rbuf, 0, sizeof(rbuf));
        socklen_t addr_len = sizeof(struct sockaddr_storage);
        if((received_bytes = recvfrom(socket_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr*) &receive_addr,
            (socklen_t*) &addr_len)) < PACKETSIZE)
        {printf("Receive #%d failed!\n", received_count+1); continue;}

        clock_gettime(CLOCK_MONOTONIC, &pkt_t_1);

        long double rtt = ((pkt_t_1.tv_sec - pkt_t_0.tv_sec) * 1000.0) +
            ((pkt_t_1.tv_nsec - pkt_t_0.tv_nsec) / 1000000.0);


        if(pinging) { // don't report packets after interrupt
            sent_count++;

            if(ipversion == 6) {
                // skip ipv6 header
                rpkt = (struct packet6*) &rbuf + 40;
                struct packet6* rpktptr = (struct packet6*) rpkt;

                if(rpktptr->header.icmp6_type == ICMP6_ECHO_REPLY && rpktptr->header.icmp6_code == 0) {
                    printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1Lfms\n",
                        received_bytes, host, ipstr, sent_count, ttl, rtt);
                    received_count++;
                } else {
                    printf("Error: received packet %d with ICMP6 type %d and code %d\n",
                        sent_count, rpktptr->header.icmp6_type, rpktptr->header.icmp6_code);
                }
            } else {
                // skip ipv4 header
                struct iphdr *ip = (struct iphdr *)rbuf;
                rpkt = (struct packet*) &rbuf + 20;
                struct packet* rpktptr = (struct packet*) rpkt;

                // TTL-exceeded packets are bigger (112 bytes) than normal echo reply packets (84 bytes).
                // I'm aware that this isn't the cleanest solution, but for some reason the iphdr->ihl
                // header length field was not changing accordingly in the incoming packets.
                if(received_bytes > 84) {
                    char ip_s_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ip->saddr), ip_s_str, INET_ADDRSTRLEN);
                    printf("From %s (%s) icmp_seq=%d Time to live exceeded\n",
                        ip_s_str, ip_s_str, sent_count);
                } else if(rpktptr->header.type == ICMP_ECHOREPLY && rpktptr->header.code == 0) {
                    printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1Lfms\n",
                        received_bytes, host, ipstr, sent_count, ttl, rtt);
                    received_count++;

                    // store rtt for statistics
                    struct rtt* r = (struct rtt*) malloc(sizeof(struct rtt));
                    r->rtt = rtt;
                    if(rttlist == NULL) {
                        rttlist = r;
                    } else {
                        struct rtt* n = rttlist;
                        while(n->next != NULL) {
                            n = n->next;
                        }
                        n->next = r;
                    }
                } else {
                    printf("Error: received packet %d with ICMP type %d and code %d\n",
                        sent_count, rpktptr->header.type, rpktptr->header.code);
                }
            }
        } else { // cleanup dynamic memory
            free(spkt);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &total_t_1);
    long double total_time = ((total_t_1.tv_sec - total_t_0.tv_sec) * 1000.0) +
            ((total_t_1.tv_nsec - total_t_0.tv_nsec) / 1000000.0);

    double packet_loss;
    if(sent_count == 0) {
        packet_loss = 0.0;
    } else {
        packet_loss = ((double)(sent_count - received_count))/((double)sent_count) * 100.0;
    }

    printf("\n--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, %d received, %.1f%% packet loss, time %.0Lfms\n",
        sent_count, received_count, packet_loss, total_time);

    if(rttlist != NULL) {
        long double min=rttlist->rtt, avg=0, max=rttlist->rtt, mdev=0, cnt=1;
        struct rtt* n = rttlist;

        // traverse rrtlist to find min, max, and avg
        while(n->next != NULL) {
            n = n->next;
            cnt++;
            avg += n->rtt;
            if(n->rtt < min) min = n->rtt;
            if(n->rtt > max) max = n->rtt;
        }

        avg = avg / cnt;

        // traverse rttlist to find standard deviation
        n = rttlist;
        while(n->next != NULL) {
            n = n->next;
            mdev += (n->rtt - avg) * (n->rtt - avg);
        }

        mdev = mdev / cnt;
        mdev = sqrt((double) mdev);

        printf("rtt min/avg/max/mdev = %.3Lf/%.3Lf/%.3Lf/%.3Lf ms\n", min, avg, max, mdev);

        freerttlist(rttlist);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    int socket_fd=-1, ipversion = 4, ttl=54;
    struct addrinfo hints, *res;
    struct sockaddr_storage* send_addr;
    struct rtt* rttlist = NULL;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if(!(argc == 2 || argc == 4)) {
        printf("Error: Invalid number of arguments.\n"); return 1;
    }

    if(argc == 4 && !strcmp(argv[2], "-t")) {
        if(!strcmp(argv[2], "-t")) {
            ttl = strtol(argv[3], NULL, 10);
        } else {
            printf("Error: Unkown option indicated.\n"); return 1;
        }
    }

    if(getaddrinfo(argv[1], NULL, &hints, &res) < 0) {printf("Error\n"); return 1;}

    send_addr = (struct sockaddr_storage*) res->ai_addr;

    if(res->ai_family == AF_INET6) {
        ipversion = 6;
    }

    if(ipversion == 6) {
        socket_fd = socket(res->ai_family, SOCK_RAW, IPPROTO_ICMPV6);
    } else {
        socket_fd = socket(res->ai_family, SOCK_RAW, IPPROTO_ICMP);
    }
    if(socket_fd < 0) {printf("Error\n"); return 1;}

    // ensure socket is blocking so we can measure RTTs
    int flags = fcntl(socket_fd, F_GETFL);
    if(flags < 0) {printf("Error\n"); return 1;}
    if(fcntl(socket_fd, F_SETFL, flags &= ~O_NONBLOCK) < 0) {printf("Error\n"); return 1;}

    signal(SIGINT, interruptHandler);

    int ret = ping(socket_fd, send_addr, argv[1], ttl, rttlist, ipversion);

    freeaddrinfo(res);

    return ret;
}