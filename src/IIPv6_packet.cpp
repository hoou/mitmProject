#include "IIPv6_packet.h"

struct ip6_hdr IIPv6_packet::constructIPv6Header(
        uint16_t payloadLength,
        uint8_t nextHeader,
        in6_addr srcAddr,
        in6_addr destAddr
) {
    struct ip6_hdr header;

    /*
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     */

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    header.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Payload length (16 bits): ICMP header + ICMP data
    header.ip6_plen = htons(payloadLength);

    // Next header (8 bits): 58 for ICMP
    header.ip6_nxt = nextHeader;

    // Hop limit (8 bits): default to maximum value
    header.ip6_hops = 255;

    /* Source */
    header.ip6_src = srcAddr;

    /* Destination */
    header.ip6_dst = destAddr;

    return header;
}

in6_addr IIPv6_packet::getSourceAddress() {
    return ipv6Header.ip6_src;
}

in6_addr IIPv6_packet::getDestinationAddress() {
    return ipv6Header.ip6_dst;
}
