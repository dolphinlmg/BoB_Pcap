#include <pcap.h>
#include <stdio.h>
#include "packet.h"

#define _DEBUG

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
#ifdef DEBUG
  char dev[] = "dum0";
#else
    if (argc != 2) {
      usage();
      return -1;
    }
    char* dev = argv[1];
#endif
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    Packet pk = Packet(packet);

    // Print Ethernet Header Information
    printf("========== Ethernet ==========\n");
    printf("SRC MAC: ");
    pk.printMACAddr(Flags::SRC);
    printf("DES MAC: ");
    pk.printMACAddr(Flags::DES);

    // If the packet has IP header
    if(pk.isHasIP()){
        printf("============= IP =============\n");
        printf("SRC IP: ");
        pk.printIPAddr(Flags::SRC);
        printf("DES IP: ");
        pk.printIPAddr(Flags::DES);

        // If the packet has TCP header
        if(pk.isHasTCP()){
            printf("============= TCP ============\n");
            printf("SRC Port: %d\nDES Port: %d\n",
                   pk.getTCPPort(Flags::SRC), pk.getTCPPort(Flags::DES));
            printf("TCP Data: \n");

            // Print TCP data upto 10 Bytes.
            for(uint8_t i = 0; i < 10; i++){
                if(pk.getSizeOfTCPData() <= i){
                    break;
                }
                printf("%02x ", *(pk.getTCPData() + i));
            }
            if(pk.getSizeOfTCPData() == 0){
                printf("There is no TCP Data\n");
            }
            printf("\n");
        }
    }
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
