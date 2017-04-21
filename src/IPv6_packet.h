#ifndef PDS_MITM_IPV6_PACKET_H
#define PDS_MITM_IPV6_PACKET_H

#include <netinet/ip6.h>
#include <vector>
#include "Packet.h"

#define IP6_HDRLEN 40  // IPv6 header length
#define IP6_HOPBYHOPOPTS_HDRLEN 8 // IPv6 Hop-by-Hop Options header length

using namespace std;

/**
 * IPv6 packet
 */
class IPv6_packet : public Packet {
private:
    /**
     * Setup header structure private member field
     */
    void setupHeader();

protected:

    struct ip6_hdr ipv6Header;

    /**
     * Construct structure for IPv6 header
     *
     * inspired by:
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     * @param payloadLength
     * @param nextHeader
     * @param srcAddr source IPv6 address
     * @param destAddr destination IPv6 address
     * @return IPv6 header structure
     */
    static struct ip6_hdr constructIPv6Header(
            uint16_t payloadLength,
            uint8_t nextHeader,
            in6_addr srcAddr,
            in6_addr destAddr
    );

    /**
     * Construct vector of bytes for destination options header
     * @param nextHeader
     * @param length
     * @param options
     * @return vector of bytes for destination options header
     */
    static vector<uint8_t> constructDestinationOptionsHeader(
            uint8_t nextHeader,
            uint8_t length,
            vector<uint8_t> options
    );

    /**
     * Construct vector of bytes for hop-by-hop options
     * @param nextHeader
     * @param length
     * @param options
     * @return vector of bytes for hop-by-hop options
     */
    static vector<uint8_t> constructHopByHopOptions(uint8_t nextHeader, uint8_t length, vector<uint8_t> options);

public:

    /**
     * Construct IPv6 packet
     * @param data packet raw data
     * @param length length of packet
     */
    IPv6_packet(const uint8_t *data, size_t length);

    in6_addr getSourceAddress();

    in6_addr getDestinationAddress();
};

#endif //PDS_MITM_IPV6_PACKET_H
