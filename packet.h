#pragma once
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdio>
#include <arpa/inet.h>

enum Flags {
    IP = 0x0800,
    TCP = 0x06,
    NONE = 0x00,
    DES = 0x01,
    SRC = 0x02
};

class Packet {
public:
    Packet(){}
    Packet(const u_char* packet);
    void setEtherType();
    enum Flags getEtherType();
    void setIPProtocolID();
    enum Flags getIPProtocolID();
    bool isHasIP();
    bool isHasTCP();
    const u_char* getMACAddr(enum Flags type);
    void printMACAddr(enum Flags type);
    const u_char* getIPAddr(enum Flags type);
    void printIPAddr(enum Flags type);
    const u_char* getTCPData();
    uint16_t getSizeOfTCPData();
    uint16_t getTCPPort(enum Flags type);

private:
    const u_char* data;
    enum Flags etherType {Flags::NONE};
    enum Flags ipProtocolID {Flags::NONE};
    struct ether_header *etherHdr;
    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
};
