#ifndef PDS_MITM_ICMPV6_PACKET_H
#define PDS_MITM_ICMPV6_PACKET_H

#include "Packet.h"
#include "IPv6_packet.h"
#include <netinet/icmp6.h>

#define ICMP_ECHO_REQUEST_HDRLEN 8  // ICMP header length for echo request, excludes data
#define ICMP_NEIGH_ADV_HDRLEN 32 // ICMP header length for neighbor advertisement
#define ICMP_MCAST_LISTEN_QUERY_HDRLEN 24 // ICMP header length for multicast listener query

/**
 * ICMPv6 packet
 *
 * Inspired by:
 * http://www.pdbuchan.com/rawsock/rawsock.html
 * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
 * icmp6_ll.c
 */
class ICMPv6_packet : public IPv6_packet {
private:
    struct icmp6_hdr icmp6Header;

    /**
     * Construct structure for ICMPv6 header with given type and code
     * @param type
     * @param code
     * @return ICMPv6 header structure
     */
    static icmp6_hdr constructICMP6header(uint8_t type, uint8_t code);

    /**
     * Construct structure for ICMPv6 echo request header
     * @return ICMPv6 echo request header structure
     */
    static icmp6_hdr constructICMP6echoRequestHeader();

    /**
     * Construct structure for Neighbor advertisement header
     * @param targetAddress
     * @return Neighbor advertisement header structure
     */
    static nd_neighbor_advert constructNeighborAdvertisementHeader(const in6_addr &targetAddress);

    /**
     * Construct structure for Target link address option header
     * @param targetLinkAddressOptionLength
     * @return Target link address option header structure
     */
    static nd_opt_hdr constructTargetLinkAddressOptionHeader(uint8_t targetLinkAddressOptionLength);

    /**
     * Construct structure for Multicast listener query header
     * @param maximumResponseDelay
     * @param multicastAddress
     * @return Multicast listener query header structure
     */
    static mld_hdr constructMulticastListenerQueryHeader(uint16_t maximumResponseDelay, in6_addr multicastAddress);

    /**
     * Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
     *
     * NOT MY CODE!!!! - just slightly modified
     *
     * source:
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
     * NOT MY CODE!!!!
     *
     * source:
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     * @param addr
     * @param len
     * @return
     */
    static uint16_t checksum(uint16_t *addr, int len);

    /**
     * Setup header structure private member field
     */
    void setupHeader();

public:

    /**
     * Construct ICMPv6 packet
     * @param data packet raw data
     * @param length length of packet
     */
    ICMPv6_packet(const uint8_t *data, size_t length);

    /**
     * Construct ICMPv6 echo request packet
     * @param senderHardwareAddress
     * @param targetHardwareAddress
     * @param sourceAddress
     * @param destinationAddress
     * @return ICMPv6 echo request packet
     */
    static ICMPv6_packet *createEchoRequest(
            mac_addr senderHardwareAddress,
            mac_addr targetHardwareAddress,
            in6_addr sourceAddress,
            in6_addr destinationAddress
    );

    /**
     * Construct malformed ICMPv6 echo request packet. Malformed means that packet contains invalid IPv6 extension header.
     * This type of packet is used for IPv6 scanning purposes.
     *
     * @param senderHardwareAddress
     * @param targetHardwareAddress
     * @param sourceAddress
     * @param destinationAddress
     * @return malformed ICMPv6 echo request packet
     */
    static ICMPv6_packet *createMalformedEchoRequest(
            mac_addr senderHardwareAddress,
            mac_addr targetHardwareAddress,
            in6_addr sourceAddress,
            in6_addr destinationAddress
    );

    /**
     * Construct Neighbor advertisement packet
     * @param senderHardwareAddress
     * @param sourceAddress
     * @param targetHardwareAddress
     * @param destinationAddress
     * @return Neighbor advertisement packet
     */
    static ICMPv6_packet *createNeighborAdvertisement(
            mac_addr senderHardwareAddress,
            in6_addr sourceAddress,
            mac_addr targetHardwareAddress,
            in6_addr destinationAddress
    );

    /**
     * Construct Multicast listener query packet
     * @param senderHardwareAddress
     * @param sourceAddress
     * @param targetHardwareAddress
     * @param destinationAddress
     * @param multicastAddress
     * @return Multicast listener query packet
     */
    static ICMPv6_packet *createMulticastListenerQuery(
            mac_addr senderHardwareAddress,
            in6_addr sourceAddress,
            mac_addr targetHardwareAddress,
            in6_addr destinationAddress,
            in6_addr multicastAddress
    );
};


#endif //PDS_MITM_ICMPV6_PACKET_H
