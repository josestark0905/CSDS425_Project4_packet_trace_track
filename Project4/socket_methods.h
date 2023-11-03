#ifndef PROJECT4_SOCKET_METHODS_H
#define PROJECT4_SOCKET_METHODS_H

#define REQUIRED_ARGC 4
#define ERROR 1
#define INITIAL_ARGV 1
#define PROJECT_POSITION 0
#define OPTION_END (-1)
#define MAX_PKT_SIZE 1600

#include <string>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* meta information, using same layout as trace file */
struct meta_info {
    unsigned int usecs;
    unsigned int secs;
    unsigned short ignored;
    unsigned short caplen;
};

/* record of information about the current packet */
struct pkt_info {
    unsigned short caplen;      /* from meta info */
    double now;                 /* from meta info */
    unsigned char pkt[MAX_PKT_SIZE];
    ether_header *ethh;  /* ptr to ethernet header */
    iphdr *iph;          /* ptr to IP header */
    tcphdr *tcph;        /* ptr to TCP header */
    udphdr *udph;        /* ptr to UDP header */
};


/*Structure containing the options get from command line.*/
struct Opts {
    bool r_flag;
    bool s_flag;
    bool l_flag;
    bool p_flag;
    bool c_flag;
    std::string trace_file;
};

void usage(char *program_name);

void err_exit(const std::string &format);

void err_exit(const std::string &format, const std::string &arg);

std::string address_transfer(uint32_t address);

void parseargs(Opts *opts, int argc, char *argv[]);

unsigned short next_packet(int fd, pkt_info *pinfo);

void mode_s(int fd, pkt_info *pinfo);

void mode_l(int fd, pkt_info *pinfo);

void mode_p(int fd, pkt_info *pinfo);

void mode_c(int fd, pkt_info *pinfo);

#endif //PROJECT4_SOCKET_METHODS_H
