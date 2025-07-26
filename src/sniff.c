#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "analysis.h"

#include "dispatch.h"
#include <pthread.h>

void freeIPArray(void);
void myDumper(int verbose, const struct pcap_pkthdr *header, const u_char *packet);

#define THREAD_NUM 20 // defines the amount of threads the program should create

pthread_t threads[THREAD_NUM]; // array to store threads declaration

// initialise the threadpool
void initThreadPool(){
  pthread_mutex_init(&mutexQueue, NULL); //initialise the mutex and condition variable
  pthread_cond_init(&condQueue, NULL);

  for (int i = 0; i < THREAD_NUM; i++){ // creates all the threads
    if (pthread_create(&threads[i], NULL, &startThread, NULL) != 0){
      exit(EXIT_FAILURE); // if issue creating, then exit
    }
  }
}

// closes down the thread pool
void cleanupThreadPool(){
  for (int i = 0; i < THREAD_NUM; i++){
    pthread_join(threads[i], NULL); //join the threads together
  }

  pthread_mutex_destroy(&mutexQueue); //destroys the mutex abd condition variable
  pthread_cond_destroy(&condQueue);
}


pcap_t *pcap_handle;


// packet handler, used when SIGINT is received
void handler(int sigint){
  printf("\nSIGINT received. Stopping packet capture...\n");
  if (pcap_handle){
    pcap_breakloop(pcap_handle);  // stops pcap_loop safely
  }

  //set the terminate flag and wake up all the worker threads
  pthread_mutex_lock(&mutexQueue);

  terminate = 1;

  pthread_cond_broadcast(&condQueue);
  pthread_mutex_unlock(&mutexQueue);

  //print output
  printf("\n=== Intrusion Detection Summary ===\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n", syns, uniqueIps);
  printf("%d ARP responses (cache poisoning)\n", arpResponses);
  printf("URL Blacklist Violations: %d\n", blackListed);
  printf("==================================\n");


  // free ipArray
  freeIPArray();
}



// runs dispatch in the future with the aurguments needed and maybe prints packet details
void packet_handler(u_char *verb, const struct pcap_pkthdr *header, const u_char *packet){
  int verbose = *(int *)verb;  // get verbose mode
  if (verbose){
    myDumper(verbose, header, packet);  // Dump packet if verbose
  }
  // Additional processing can go here
  dispatch((struct pcap_pkthdr*)header, packet, verbose);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  
  struct pcap_pkthdr header;
  const unsigned char *packet;
  initThreadPool();

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().

  //register signal handler for SIGINT
  signal(SIGINT, handler);

  //use pcap_loop for packet capture
  printf("Starting packet capture...\n");
  
  pcap_loop(pcap_handle, -1, packet_handler, (u_char *)&verbose);

  //close the pcap handle
  pcap_close(pcap_handle);

  printf("Packet capture stopped.\n");

  cleanupThreadPool();




  /*while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // If verbose is set to 1, dump raw packet to terminal
      if (verbose) {
        dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose);
    }
  }*/
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}

//function to format MAC addreses
void formatMacs(const u_char *mac, char *buffer){
  sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

//function to format IP addresses
void formatIps(uint32_t ip, char *buffer){
  u_char *bytes = (u_char *)&ip; //casts them to bytes for simple formatting
  sprintf(buffer, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]); //stores in string format to the string
}

// myDumper function, operates outside of multithreading, with future time i would implement this into the multithreading
void myDumper(int verbose, const struct pcap_pkthdr *header, const u_char *packet){
  struct ether_header *eth;
  struct ether_arp *arp;
  struct iphdr *ip;
  struct tcphdr *tcp;
  static unsigned long pcount = 0;
  char srcMac[18];
  char dstMac[18];
  char srcIp[16];
  char dstIp[16];

  pcount++;
  printf("\n\n=== PACKET %lu HEADER ===", pcount);

  //parses the eth header
  eth = (struct ether_header *)packet;
  formatMacs(eth->ether_shost, srcMac); // use helper functions to store the mac address of the source and destinations in their various strings
  formatMacs(eth->ether_dhost, dstMac);


  printf("\nSource MAC: %s", srcMac); //prints the strings of the mac address's 
  printf("\nDestination MAC: %s", dstMac);


  u_short eth_type = ntohs(eth->ether_type);
  printf("\nEtherType: 0x%04x", eth_type);      //prints the eth type

  // if its an ARP
  if(eth_type == ETHERTYPE_ARP){
    arp = (struct ether_arp *)(packet + ETH_HLEN);

    formatMacs(arp->arp_sha, srcMac);   
    formatMacs(arp->arp_tha, dstMac);
    formatIps(*(uint32_t *)arp->arp_spa, srcIp); // cast pointer to 32 bit integer pointer and then dereference it. This can then allow us to get the bianry form
    formatIps(*(uint32_t *)arp->arp_tpa, dstIp);

    printf("\nARP Packet:");
    printf("\n  Sender MAC: %s", srcMac);
    printf("\n  Target MAC: %s", dstMac);
    printf("\n  Sender IP: %s", srcIp);
    printf("\n  Target IP: %s", dstIp);
    return; //processed arp, no further processing required
  }
  // Parse IP header
  if(eth_type == ETHERTYPE_IP){
    ip = (struct iphdr *)(packet + ETH_HLEN);
    int ip_header_len = ip->ihl * 4;

    if(ip_header_len < 20){
      printf("\nInvalid IP header length: %d bytes\n", ip_header_len);
      return;

    }

    formatIps(ip->saddr, srcIp);
    formatIps(ip->daddr, dstIp);


    printf("\nSource IP: %s", srcIp);
    printf("\nDestination IP: %s", dstIp);
    printf("\nProtocol: ");


    if (ip->protocol == IPPROTO_TCP) {
      printf("TCP");
    } 
    else{
      printf("Non-TCP Protocol");
      return; //exit for non-TCP protocols
    }
    //parse through TCP header
    tcp = (struct tcphdr *)(packet + ETH_HLEN + ip_header_len);
    int tcp_header_len = tcp->doff * 4;
    if(tcp_header_len < 20){
      printf("\nInvalid TCP header length: %d bytes\n", tcp_header_len);
      return;
    }
    
    printf("\nSource Port: %d", ntohs(tcp->source));
    printf("\nDestination Port: %d", ntohs(tcp->dest));

    // if from port 80, then its http traffic
    if(ntohs(tcp->dest) == 80){
      printf("\nHTTP (port 80) detected");
    }
    // print the tcp flags
    printf("\nTCP Flags:");
    if(tcp->syn) printf(" SYN ");
    if(tcp->ack) printf(" ACK ");
    if(tcp->fin) printf(" FIN ");
    if(tcp->rst) printf(" RST ");
    if(tcp->psh) printf(" PSH ");
    if(tcp->urg) printf(" URG ");
    printf("\nEnd of packet processing\n");
    return;
  }
}

