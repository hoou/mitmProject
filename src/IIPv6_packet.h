#ifndef PROJEKT_NEW_IPV6_PACKET_H
#define PROJEKT_NEW_IPV6_PACKET_H

#include <netinet/ip6.h>

class IIPv6_packet {
protected:
    static struct ip6_hdr constructIPv6Header(uint16_t payloadLength, uint8_t nextHeader, in6_addr srcAddr, in6_addr destAddr);
};

#endif //PROJEKT_NEW_IPV6_PACKET_H
