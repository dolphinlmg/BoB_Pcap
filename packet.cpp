#include "packet.h"

Packet::Packet(const u_char* packet){
    this->data = packet;
    this->etherHdr = (struct ether_header *) packet;
    setEtherType();
    setIPProtocolID();
    if(isHasIP())
        this->ipHdr = (struct iphdr *)(packet + 14);
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
    if(ipHdr->protocol == Flags::TCP)
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
        return etherHdr->ether_shost;
    }else if(type == Flags::DES){
        return etherHdr->ether_dhost;
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

int Packet::getSizeOfTCPData(){
    return this->ipHdr->tot_len - this->ipHdr->ihl*4 - this->tcpHdr->th_off*4;
}
