#include "packet.h"

Packet::Packet(const u_char* packet){
    this->data = packet;
    this->etherHdr = (struct ether_header *) packet;
    setEtherType();
    if(isHasIP()){
        this->ipHdr = (struct iphdr *)(packet + 14);
        setIPProtocolID();
    }
    if(isHasTCP())
        this->tcpHdr = (struct tcphdr *)(packet + 14 + ipHdr->ihl*4);
}

void Packet::setEtherType(){
    if(ntohs(etherHdr->ether_type) == Flags::IP)
        this->etherType = Flags::IP;
    else
        this->etherType = Flags::NONE;
}

enum Flags Packet::getEtherType(){
    if(isHasIP()) return this->etherType;
    else return Flags::NONE;
}

void Packet::setIPProtocolID(){
    if(this->ipHdr->protocol == Flags::TCP)
        this->ipProtocolID = Flags::TCP;
}

enum Flags Packet::getIPProtocolID(){
    if(isHasTCP())  return this->ipProtocolID;
    else return Flags::NONE;
}

bool Packet::isHasIP(){
    if(this->etherType == Flags::IP) return true;
    return false;
}

bool Packet::isHasTCP(){
    if(this->ipProtocolID == Flags::TCP)   return true;
    return false;
}

const u_char* Packet::getMACAddr(enum Flags type){
    if(type == Flags::SRC){
        return this->etherHdr->ether_shost;
    }else if(type == Flags::DES){
        return this->etherHdr->ether_dhost;
    }else{
        return nullptr;
    }
}

void Packet::printMACAddr(enum Flags type){
    const u_char* addr = getMACAddr(type);
    if(addr == nullptr) return;
    for(int i = 0; i < 6; i++){
        printf("%02x:", *(addr + i));
    }
    printf("\b \n");
}

const u_char* Packet::getIPAddr(enum Flags type){
    if(type == Flags::SRC){
        return ((const u_char*)this->ipHdr + 12);
    }else if(type == Flags::DES){
        return ((const u_char*)this->ipHdr + 16);
    }else{
        return nullptr;
    }
}

void Packet::printIPAddr(enum Flags type){
    const u_char* addr = getIPAddr(type);
    if(addr == nullptr) return;
    for(int i = 0; i < 4; i++)
        printf("%d.", *(addr + i));
    printf("\b \n");
}

const u_char* Packet::getTCPData(){
    if(!isHasTCP()) return nullptr;
    return data + 14 + (ipHdr->ihl*4) + (tcpHdr->th_off*4);
}

uint16_t Packet::getSizeOfTCPData(){
    return ntohs(this->ipHdr->tot_len) - this->ipHdr->ihl*4 - this->tcpHdr->th_off*4;
}

uint16_t Packet::getTCPPort(enum Flags type){
    if(type == Flags::SRC){
        return ntohs(this->tcpHdr->th_sport);
    }else if (type == Flags::DES){
        return ntohs(this->tcpHdr->th_dport);
    }else
        return 0;
}
