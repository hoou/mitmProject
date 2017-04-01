#ifndef PROJEKT_NEW_ICMPV6_PACKET_H
#define PROJEKT_NEW_ICMPV6_PACKET_H


#include "Packet.h"
#include "IIPv6_packet.h"
#include <netinet/icmp6.h>

/*
 * http://www.pdbuchan.com/rawsock/rawsock.html
 * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
 * icmp6_ll.c
 *
 */
#define ICMP_ECHO_REQUEST_HDRLEN 8  // ICMP header length for echo request, excludes data
#define ICMP_NEIGH_ADV_HDRLEN 32 // ICMP header length for neighbor advertisement
#define IP6_HDRLEN 40  // IPv6 header length

class ICMPv6_packet : public Packet, public IIPv6_packet {
private:
    struct icmp6_hdr icmp6Header;

    static icmp6_hdr constructICMP6header(uint8_t type, uint8_t code);

    static nd_neighbor_advert constructNeighborAdvertisementHeader(const in6_addr &targetAddress);

    static nd_opt_hdr constructTargetLinkAddressOptionHeader(uint8_t targetLinkAddressOptionLength);

    /**
     * Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
     *
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     * @param iphdr
     * @param icmp6hdr
     * @param payload
     * @param payloadlen
     * @return
     */
    static uint16_t icmp6_checksum(ip6_hdr iphdr, icmp6_hdr icmp6hdr, uint8_t *payload, size_t payloadlen);

    /**
     * Computing the internet checksum (RFC 1071).
     * Note that the internet checksum does not preclude collisions.
     *
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     * @param addr
     * @param len
     * @return
     */
    static uint16_t checksum(uint16_t *addr, int len);

protected:

    void setupHeaders();

public:

    ICMPv6_packet(const uint8_t *data, size_t length);

    static ICMPv6_packet *createEchoRequest(
            mac_addr senderHardwareAddress,
            mac_addr targetHardwareAddress,
            in6_addr sourceAddress,
            in6_addr destinationAddress
    );

    static ICMPv6_packet *createMalformedEchoRequest(
            mac_addr senderHardwareAddress,
            mac_addr targetHardwareAddress,
            in6_addr sourceAddress,
            in6_addr destinationAddress
    );

    static ICMPv6_packet *createNeighborAdvertisement(
            mac_addr senderHardwareAddress,
            in6_addr sourceAddress,
            mac_addr targetHardwareAddress,
            in6_addr destinationAddress
    );
};


#endif //PROJEKT_NEW_ICMPV6_PACKET_H
