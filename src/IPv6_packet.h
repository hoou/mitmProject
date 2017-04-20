#ifndef PROJEKT_NEW_IPV6_PACKET_H
#define PROJEKT_NEW_IPV6_PACKET_H

#include <netinet/ip6.h>
#include <vector>
#include "Packet.h"

#define IP6_HDRLEN 40  // IPv6 header length
#define IP6_HOPBYHOPOPTS_HDRLEN 8 // IPv6 Hop-by-Hop Options header length

using namespace std;

class IPv6_packet : public Packet {
private:
    void setupHeader();

protected:

    struct ip6_hdr ipv6Header;

    static struct ip6_hdr constructIPv6Header(
            uint16_t payloadLength,
            uint8_t nextHeader,
            in6_addr srcAddr,
            in6_addr destAddr
    );

    static vector<uint8_t> constructDestinationOptionsHeader(
            uint8_t nextHeader,
            uint8_t length,
            vector<uint8_t> options
    );

    static vector<uint8_t> constructHopByHopOptions(uint8_t nextHeader, uint8_t length, vector<uint8_t> options);

public:

    IPv6_packet(const uint8_t *data, size_t length);

    in6_addr getSourceAddress();

    in6_addr getDestinationAddress();
};

#endif //PROJEKT_NEW_IPV6_PACKET_H
