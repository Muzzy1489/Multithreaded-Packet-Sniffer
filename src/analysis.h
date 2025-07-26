#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

extern const char *blacklisted_domains[];
extern int blacklist_count[];
extern int blackListed;
extern int arpResponses;
extern int syns;
extern int uniqueIps;

typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef unsigned int u_int;

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
