#include "analysis.h"

#include <pthread.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



// Blacklisted domains
const char *blacklisted_domains[] = {"www.google.co.uk", "www.bbc.co.uk"};

int syns = 0;
int uniqueIps = 0;
int blackListed = 0;
int arpResponses = 0;

pthread_mutex_t mutexIps = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutexBlacklist = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutexArps = PTHREAD_MUTEX_INITIALIZER;

//----------------Dynamic array implementation----------------------------------------------
// Initally I was going to implement a hashmap for this question however due to the question eluding
// to a dynamic array, i decided to do this instead


char **ipArray = NULL; //pointer to the array of IPs
int ipCount = 0;       //num IPs stored in array
int ipCapacity = 0;    //curr capacity of the array

//loops through array to see if IP is unique
int isUniqueIP(const char *ip){
    for(int i = 0; i < ipCount; i++){
        if(strcmp(ipArray[i], ip) == 0){
            return 0; //not unique
        }
    }
    return 1; //unique
}

//Adds ip to array, if too small, resizes array
void addUniqueIP(const char *ip){
    if(ipCapacity == 0){
        ipCapacity = 500; // starting capacity
        ipArray = malloc(ipCapacity * sizeof(char *));
        if(!ipArray){
            exit(EXIT_FAILURE);
        }
    } else if(ipCount >= ipCapacity){
        ipCapacity += 500;// resizes but with this additional amount
        ipArray = realloc(ipArray, ipCapacity * sizeof(char *));
        if(!ipArray){
            exit(EXIT_FAILURE);
        }
    }

    //allocates memory for the new IP and add it to the array
    ipArray[ipCount] = malloc(16);
    if(!ipArray[ipCount]){
        exit(EXIT_FAILURE);
    }
    strcpy(ipArray[ipCount], ip); // puts ip string in array
    ipCount++;                    //ip count and uniqueIps, to show theres a new ip and a new unique one
    uniqueIps++;
}

//function to free all array spaces and free entire array space memory resource
void freeIPArray(){
    for(int i = 0; i < ipCount; i++){
        free(ipArray[i]);
    }
    free(ipArray);
}

//-----------------------------------------------------------------------------------------------------------------

void analyse(struct pcap_pkthdr *header,
             const u_char *packet,
             int verbose) {
    // Extract Ethernet header
    struct ether_header *ethHeader = (struct ether_header *)packet;

    //------ARP Cache Poisoning--------------------------------------------------------------------------------

    // check for ARP packet
    if(ntohs(ethHeader->ether_type) == ETH_P_ARP){
        //extracts the ARP header
        struct ether_arp *arpHeader = (struct ether_arp *)(packet + ETH_HLEN);

        //if ARP response
        if(ntohs(arpHeader->ea_hdr.ar_op) == ARPOP_REPLY){
            pthread_mutex_lock(&mutexArps);
            arpResponses++; //increment arp counter
            pthread_mutex_unlock(&mutexArps);
        }
        return; //processed ARP packet, no further checks needed
    }

    //-----------------------------------------------------------------------------------------------------

    // if not an ip packet
    if(ntohs(ethHeader->ether_type) != ETHERTYPE_IP){
        return;
    }
    //gets ip header
    struct ip *ipHeader = (struct ip *)(packet + ETH_HLEN);
    // if not a tcp packet
    if(ipHeader->ip_p != IPPROTO_TCP){
        return;
    }

    //----------SYN Flooding Detection-----------------------------------------------------------------------
    struct tcphdr *tcpHeader = (struct tcphdr *)((u_char *)ipHeader + (ipHeader->ip_hl * 4));

    //if the packet is a SYN packet (SYN flag set, all othersothers unset)
    if(tcpHeader->syn && !tcpHeader->ack && !tcpHeader->fin && !tcpHeader->rst){
        pthread_mutex_lock(&mutexIps);
        syns++; //incrememnt total syns

        //extracts the ip address to teh srcIP string
        char srcIP[16];
        //converts the ip address from binary to string and stores in srcIP
        snprintf(srcIP, sizeof(srcIP), "%s", inet_ntoa(ipHeader->ip_src));
        

        //if its a unique ip
        if(isUniqueIP(srcIP)){
            //adds to the array function
            addUniqueIP(srcIP);
        }
        pthread_mutex_unlock(&mutexIps);
        return; //processed SYN packet, no further checks needed

    }

    //-----------------------------------------------------------------------------------------------------

    
    //----------Blacklisted URLS-----------------------------------------------------------------------

    // if port is 80
    if(ntohs(tcpHeader->dest) == 80){
        //extract httppayload which comes after the tcp header
        const unsigned char *httpPayload = (u_char *)tcpHeader + (tcpHeader->doff * 4);
        // used to store the length of the payload
        // type of size_t is used here as is safe for 32 bit and 64 bit systems, unlike u_int
        size_t payloadLength = header->caplen - (httpPayload - packet);

        //if no payload
        if(payloadLength == 0){
            return;
        }

        //if there isn't a "Host: " in payload, meaning 
        const char *hostHeader = strstr((const char *)httpPayload, "Host: ");
        if(!hostHeader){
            return;
        }

        //extract the domain and then stores in host string
        char host[256];
        sscanf(hostHeader, "Host: %255s", host);

        //loop through black listed urls (upper limit calculated as such to future proof for more urls)
        for(int i = 0; i < sizeof(blacklisted_domains) / sizeof(blacklisted_domains[0]); i++){
            if(strstr(host, blacklisted_domains[i])){
                //increment counter and print out info of header
                pthread_mutex_lock(&mutexBlacklist);
                blackListed++;

                printf("==============================\n");
                printf("Blacklisted URL violation detected\n");
                printf("Source IP address: %s\n", inet_ntoa(ipHeader->ip_src));
                printf("Destination IP address: %s (%s)\n",
                       inet_ntoa(ipHeader->ip_dst), blacklisted_domains[i]);
                printf("==============================\n");
                pthread_mutex_unlock(&mutexBlacklist);
            }
        }
        return; //processed Blacklist, no further checks needed
    }

    //----------------------------------------------------------------------------------------
    
    return;
}
