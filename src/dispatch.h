#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>

typedef struct Task{
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
} Task;

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void initThreadPool();
void cleanupThreadPool();

void* startThread(void* args);

extern pthread_mutex_t mutexQueue;
extern pthread_cond_t condQueue;
extern int terminate;
#endif
