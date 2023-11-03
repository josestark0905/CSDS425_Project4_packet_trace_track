#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <map>
#include <unistd.h>
#include <cstring>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "socket_methods.h"

using namespace std;

/* if the input arguments is INVALID, show the way to specify each option and the function of each option */
void usage(char *program_name) {
    fprintf(stderr, "%s -r <trace_file> -s|-l|-p|-c\n", program_name);
    fprintf(stderr, "-r <trace_file>       MUST CONTAIN: set the trace file\n");
    fprintf(stderr, "-s|-l|-p|-c           MUST CONTAIN: select exactly one mode\n");
    fprintf(stderr, "-s                    MODE CHOICE1: summary\n");
    fprintf(stderr, "-l                    MODE CHOICE2: length analysis\n");
    fprintf(stderr, "-p                    MODE CHOICE3: packet printing\n");
    fprintf(stderr, "-c                    MODE CHOICE4: packet counting\n");
    exit(ERROR);
}

/* throw an error and exit */
void err_exit(const string &format) {
    cerr << format << endl;
    exit(ERROR);
}

void err_exit(const string &format, const string &arg) {
    cerr << format << arg << endl;
    exit(ERROR);
}

string address_transfer(uint32_t address) {
    char ip_str[INET_ADDRSTRLEN];
    string ip_addr;
    address = htonl(address);
    if (inet_ntop(AF_INET, &address, ip_str, sizeof(ip_str))) {
        ip_addr = ip_str;
    } else {
        // Handle error
        err_exit("ip address can not be parsed.");
    }
    return ip_addr;
}

/* extract the opts into a structure */
void parseargs(Opts *opts, int argc, char *argv[]) {
    int opt;
    int index = INITIAL_ARGV;
    bool ALL_valid = true;
    //initialize the opts
    opts->r_flag = false;
    opts->s_flag = false;
    opts->l_flag = false;
    opts->p_flag = false;
    opts->c_flag = false;
    opts->trace_file = "";

    if (argc < REQUIRED_ARGC) {
        fprintf(stderr, "no enough arguments.\n");
        usage(argv[PROJECT_POSITION]);
    } else if (argc > REQUIRED_ARGC) {
        fprintf(stderr, "too many arguments.\n");
        usage(argv[PROJECT_POSITION]);
    } else {
        while (index < argc) {
            if (strlen(argv[index]) == 2) {
                if (argv[index][0] == '-') {
                    if (argv[index][1] == 'r') {
                        index++;
                    }
                } else {
                    fprintf(stderr, "invalid parameter %s\n", argv[index]);
                    ALL_valid = false;
                }
            } else {
                fprintf(stderr, "invalid parameter %s\n", argv[index]);
                ALL_valid = false;
            }
            index++;
        }
        if (!ALL_valid) {
            usage(argv[PROJECT_POSITION]);
        }
    }
    while ((opt = getopt(argc, argv, "r:slpc")) != OPTION_END) {
        switch (opt) {
            case 'r':
                opts->r_flag = true;
                opts->trace_file = optarg;
                break;
            case 's':
                opts->s_flag = true;
                break;
            case 'l':
                opts->l_flag = true;
                break;
            case 'p':
                opts->p_flag = true;
                break;
            case 'c':
                opts->c_flag = true;
                break;
            case '?':
                ALL_valid = false;
                if (optopt == 'r') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else {
                    fprintf(stderr, "Unknown option -%c\n", optopt);
                }
                break;
            default:
                usage(argv[PROJECT_POSITION]);
        }
    }
    if (!ALL_valid || !opts->r_flag) {
        usage(argv[PROJECT_POSITION]);
    }
}

/* fd - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

   returns:
   1 - a packet was read and pinfo is set up for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int fd, pkt_info *pinfo) {
    meta_info meta{};
    size_t bytes_read;

    memset(pinfo, 0x0, sizeof(pkt_info));
    memset(&meta, 0x0, sizeof(meta_info));

    /* read the meta information */
    bytes_read = read(fd, &meta, sizeof(meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < sizeof(meta))
        err_exit("cannot read meta information");
    pinfo->caplen = ntohs(meta.caplen);
    /* TODO: set pinfo->now based on meta.secs & meta.usecs */
    pinfo->now = ntohl(meta.secs) + ntohl(meta.usecs) / 1000000.0;

    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        err_exit("packet too big");

    /* read the packet contents */
    bytes_read = read(fd, pinfo->pkt, pinfo->caplen);
    /*if (bytes_read < 0)
        err_exit("error reading packet");*/
    if (bytes_read < pinfo->caplen)
        err_exit("unexpected end of file encountered");

    /* find the ether_header part */
    if (bytes_read < sizeof(ether_header))
        return (1);
    pinfo->ethh = (ether_header *) pinfo->pkt;
    pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);

    if (pinfo->caplen == sizeof(ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);
    /* TODO:
       set pinfo->iph to start of IP header
       if TCP packet,
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed
       if UDP packet,
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */

    /* find the ip part */
    if (pinfo->caplen < sizeof(ether_header) + 20)
        return (1);
    pinfo->iph = (iphdr *) (pinfo->pkt + sizeof(ether_header));
    pinfo->iph->tot_len = ntohs(pinfo->iph->tot_len);
    pinfo->iph->id = ntohs(pinfo->iph->id);
    pinfo->iph->frag_off = ntohs(pinfo->iph->frag_off);
    pinfo->iph->check = ntohs(pinfo->iph->check);
    pinfo->iph->saddr = ntohl(pinfo->iph->saddr);
    pinfo->iph->daddr = ntohl(pinfo->iph->daddr);

    /* find the tcp/udp part */
    if (pinfo->iph->protocol == 6) {
        if (pinfo->caplen < sizeof(ether_header) + (pinfo->iph->ihl * 4) + sizeof(tcphdr))
            return (1);
        pinfo->tcph = (tcphdr *) (pinfo->pkt + sizeof(ether_header) + (pinfo->iph->ihl * 4));
        /*pinfo->tcph->th_sport = ntohs(pinfo->tcph->th_sport);
        pinfo->tcph->th_dport = ntohs(pinfo->tcph->th_dport);
        pinfo->tcph->th_seq = ntohl(pinfo->tcph->th_seq);
        pinfo->tcph->th_ack = ntohl(pinfo->tcph->th_ack);
        pinfo->tcph->th_win = ntohs(pinfo->tcph->th_win);
        pinfo->tcph->th_sum = ntohs(pinfo->tcph->th_sum);
        pinfo->tcph->th_urp = ntohs(pinfo->tcph->th_urp);*/
        pinfo->tcph->source = ntohs(pinfo->tcph->source);
        pinfo->tcph->dest = ntohs(pinfo->tcph->dest);
        pinfo->tcph->seq = ntohl(pinfo->tcph->seq);
        pinfo->tcph->ack_seq = ntohl(pinfo->tcph->ack_seq);
        pinfo->tcph->window = ntohs(pinfo->tcph->window);
        pinfo->tcph->check = ntohs(pinfo->tcph->check);
        pinfo->tcph->urg_ptr = ntohs(pinfo->tcph->urg_ptr);
    } else if (pinfo->iph->protocol == 17) {
        if (pinfo->caplen < sizeof(ether_header) + (pinfo->iph->ihl * 4) + sizeof(udphdr))
            return (1);
        pinfo->udph = (udphdr *) (pinfo->pkt + sizeof(ether_header) + (pinfo->iph->ihl * 4));
        /*pinfo->udph->uh_sport = ntohs(pinfo->udph->uh_sport);
        pinfo->udph->uh_dport = ntohs(pinfo->udph->uh_dport);
        pinfo->udph->uh_ulen = ntohs(pinfo->udph->uh_ulen);
        pinfo->udph->uh_sum = ntohs(pinfo->udph->uh_sum);*/
        pinfo->udph->source = ntohs(pinfo->udph->source);
        pinfo->udph->dest = ntohs(pinfo->udph->dest);
        pinfo->udph->len = ntohs(pinfo->udph->len);
        pinfo->udph->check = ntohs(pinfo->udph->check);
    }
    return (1);
}

void mode_s(int fd, pkt_info *pinfo) {
    int count = 0, ip_count = 0;
    double first, last;
    while (next_packet(fd, pinfo)) {
        count++;
        if (pinfo->ethh && pinfo->ethh->ether_type == ETHERTYPE_IP)
            ip_count++;
        if (count == 1)
            first = pinfo->now;
        last = pinfo->now;
    }
    cout << fixed << "time: first: " << first << " last: " << last << " duration: " << last - first
         << endl;
    cout << "pkts: total: " << count << " ip: " << ip_count << endl;
}

void mode_l(int fd, pkt_info *pinfo) {
    while (next_packet(fd, pinfo)) {
        if (pinfo->caplen < sizeof(ether_header) || pinfo->ethh->ether_type != ETHERTYPE_IP) {
            continue;
        }
        cout << fixed << pinfo->now << " " << pinfo->caplen;
        if (pinfo->iph) {
            cout << " " << pinfo->iph->tot_len << " " << pinfo->iph->ihl * 4;
            if (pinfo->iph->protocol == 6) {
                cout << " T";
                if (pinfo->tcph) {
                    cout << " " << pinfo->tcph->doff * 4 << " "
                         << pinfo->iph->tot_len - pinfo->iph->ihl * 4 - pinfo->tcph->doff * 4;
                } else {
                    cout << " - -";
                }
            } else if (pinfo->iph->protocol == 17) {
                cout << " U";
                if (pinfo->udph) {
                    cout << " 8 " << pinfo->udph->len - 8;
                } else {
                    cout << " - -";
                }
            } else {
                cout << " ? ? ?";
            }
        } else {
            cout << " - - - - -";
        }
        cout << endl;
    }
}

void mode_p(int fd, pkt_info *pinfo) {
    while (next_packet(fd, pinfo)) {
        if (pinfo->tcph) {
            cout << fixed << pinfo->now << " " << address_transfer(pinfo->iph->saddr) << " " << pinfo->tcph->source
                 << " " << address_transfer(pinfo->iph->daddr) << " " << pinfo->tcph->dest << " " << pinfo->iph->id
                 << " " << static_cast<int>(pinfo->iph->ttl) << " " << pinfo->tcph->window;
            if (pinfo->tcph->ack == 1) {
                cout << " " << pinfo->tcph->ack_seq;
            } else {
                cout << " -";
            }
            cout << endl;
        } else {
            continue;
        }
    }
}

void mode_c(int fd, pkt_info *pinfo) {
    map<pair<string, string>, pair<int, int>> all_packets;
    while (next_packet(fd, pinfo)) {
        if (pinfo->tcph) {
            pair<string, string> src_dst = {address_transfer(pinfo->iph->saddr), address_transfer(pinfo->iph->daddr)};
            if (all_packets.find(src_dst) != all_packets.end()) {
                all_packets[src_dst].first++;
                all_packets[src_dst].second += pinfo->iph->tot_len - pinfo->iph->ihl * 4 - pinfo->tcph->doff * 4;
            } else {
                pair<int, int> new_value = {1, pinfo->iph->tot_len - pinfo->iph->ihl * 4 - pinfo->tcph->doff * 4};
                all_packets[src_dst] = new_value;
            }
        } else {
            continue;
        }
    }
    for (const auto &it: all_packets) {
        cout << it.first.first << " " << it.first.second << " " << it.second.first << " " << it.second.second << endl;
    }
}