#ifndef PROJEKT_NEW_IPV6_PACKET_H
#define PROJEKT_NEW_IPV6_PACKET_H

#include <netinet/ip6.h>
#include <vector>

using namespace std;

class IIPv6_packet {
protected:
    struct ip6_hdr ipv6Header;

    static struct ip6_hdr constructIPv6Header(uint16_t payloadLength, uint8_t nextHeader, in6_addr srcAddr, in6_addr destAddr);
    static vector<uint8_t> constructDestinationOptionsHeader(uint8_t nextHeader, uint8_t length,
                                                             vector<uint8_t> options);
public:
    in6_addr getSourceAddress();

    in6_addr getDestinationAddress();
};

#endif //PROJEKT_NEW_IPV6_PACKET_H
