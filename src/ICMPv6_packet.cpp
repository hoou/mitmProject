#include "ICMPv6_packet.h"
#include <netinet/ip.h>

ICMPv6_packet::ICMPv6_packet(const uint8_t *data, size_t length) : IPv6_packet(data, length) {
    setupHeader();
}

struct nd_neighbor_advert ICMPv6_packet::constructNeighborAdvertisementHeader(const in6_addr &targetAddress) {
    struct nd_neighbor_advert neighborAdvertisementHeader;
    neighborAdvertisementHeader.nd_na_hdr = constructICMP6header(ND_NEIGHBOR_ADVERT, 0);
    neighborAdvertisementHeader.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
    neighborAdvertisementHeader.nd_na_target = targetAddress;
    return neighborAdvertisementHeader;
}

void ICMPv6_packet::setupHeader() {
    memcpy(&icmp6Header, rawData + ETH_HLEN + IP6_HDRLEN, sizeof(icmp6Header) * sizeof(uint8_t));
}

struct nd_opt_hdr ICMPv6_packet::constructTargetLinkAddressOptionHeader(uint8_t targetLinkAddressOptionLength) {
    struct nd_opt_hdr targetLinkAddressOptionHeader;
    targetLinkAddressOptionHeader.nd_opt_len = targetLinkAddressOptionLength;
    targetLinkAddressOptionHeader.nd_opt_type = ND_OPT_TARGET_LINKADDR;
    return targetLinkAddressOptionHeader;
}

ICMPv6_packet *ICMPv6_packet::createEchoRequest(
        mac_addr senderHardwareAddress,
        mac_addr targetHardwareAddress,
        in6_addr sourceAddress,
        in6_addr destinationAddress
) {
    uint8_t *data;
    size_t length;
    ICMPv6_packet *icmPv6Packet;

    struct ether_header etherHeader = constructEthernetHeader(ETH_P_IPV6, senderHardwareAddress, targetHardwareAddress);
    struct ip6_hdr ipv6header = constructIPv6Header(
            ICMP_ECHO_REQUEST_HDRLEN,
            IPPROTO_ICMPV6,
            sourceAddress,
            destinationAddress
    );
    struct icmp6_hdr icmp6Header = constructICMP6header(ICMP6_ECHO_REQUEST, 0);

    /* Checksum */
    icmp6Header.icmp6_cksum = icmp6_checksum(ipv6header, icmp6Header, NULL, 0);

    length = ETH_HLEN + IP6_HDRLEN + ICMP_ECHO_REQUEST_HDRLEN;

    data = (uint8_t *) malloc(length * sizeof(uint8_t));
    memcpy(data, &etherHeader, ETH_HLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN, &ipv6header, IP6_HDRLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN + IP6_HDRLEN, &icmp6Header, ICMP_ECHO_REQUEST_HDRLEN * sizeof(uint8_t));

    icmPv6Packet = new ICMPv6_packet(data, length);

    free(data);

    return icmPv6Packet;
}

ICMPv6_packet *ICMPv6_packet::createMalformedEchoRequest(
        mac_addr senderHardwareAddress,
        mac_addr targetHardwareAddress,
        in6_addr sourceAddress,
        in6_addr destinationAddress
) {
    uint8_t *data;
    size_t length;
    ICMPv6_packet *icmPv6Packet;

    struct ether_header etherHeader = constructEthernetHeader(ETH_P_IPV6, senderHardwareAddress, targetHardwareAddress);

    vector<uint8_t> destinationOptionsHeader = constructDestinationOptionsHeader(
            IPPROTO_ICMPV6,
            0,
            vector<uint8_t>{0x80, 0x01, 0x00, 0x00, 0x00, 0x00}
    );

    struct ip6_hdr ipv6header = constructIPv6Header(
            (uint16_t) (ICMP_ECHO_REQUEST_HDRLEN + destinationOptionsHeader.size()),
            IPPROTO_DSTOPTS,
            sourceAddress,
            destinationAddress
    );

    struct icmp6_hdr icmp6Header = constructICMP6header(ICMP6_ECHO_REQUEST, 0);

    /* Checksum */
    icmp6Header.icmp6_cksum = icmp6_checksum(ipv6header, icmp6Header, NULL, 0);

    length = ETH_HLEN + IP6_HDRLEN + ICMP_ECHO_REQUEST_HDRLEN + destinationOptionsHeader.size();

    data = (uint8_t *) malloc(length * sizeof(uint8_t));
    memcpy(data, &etherHeader, ETH_HLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN, &ipv6header, IP6_HDRLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN + IP6_HDRLEN,
           destinationOptionsHeader.data(),
           destinationOptionsHeader.size() * sizeof(uint8_t)
    );
    memcpy(data + ETH_HLEN + IP6_HDRLEN + destinationOptionsHeader.size(),
           &icmp6Header,
           ICMP_ECHO_REQUEST_HDRLEN * sizeof(uint8_t)
    );

    icmPv6Packet = new ICMPv6_packet(data, length);

    free(data);

    return icmPv6Packet;
}

ICMPv6_packet *ICMPv6_packet::createNeighborAdvertisement(
        mac_addr senderHardwareAddress,
        in6_addr sourceAddress,
        mac_addr targetHardwareAddress,
        in6_addr destinationAddress
) {
    uint8_t *data;
    size_t length;
    ICMPv6_packet *icmPv6Packet;

    struct ether_header etherHeader = constructEthernetHeader(ETH_P_IPV6, senderHardwareAddress, targetHardwareAddress);
    struct ip6_hdr ipv6header = constructIPv6Header(
            ICMP_NEIGH_ADV_HDRLEN,
            IPPROTO_ICMPV6,
            sourceAddress,
            destinationAddress
    );
    struct nd_neighbor_advert neighborAdvertisementHeader = constructNeighborAdvertisementHeader(sourceAddress);
    struct nd_opt_hdr targetLinkAddressOptionHeader = constructTargetLinkAddressOptionHeader(1);
    mac_addr targetLinkAddress = senderHardwareAddress;

    size_t icmpPayloadLength = sizeof(struct in6_addr) + sizeof(struct nd_opt_hdr) + ETH_ALEN;
    uint8_t *icmpPayload = (uint8_t *) malloc(sizeof(uint8_t) * icmpPayloadLength);
    memcpy(icmpPayload, &neighborAdvertisementHeader.nd_na_target, sizeof(struct in6_addr));
    memcpy(icmpPayload + sizeof(struct in6_addr), &targetLinkAddressOptionHeader, sizeof(struct nd_opt_hdr));
    memcpy(icmpPayload + sizeof(struct in6_addr) + sizeof(struct nd_opt_hdr), targetLinkAddress.data(), ETH_ALEN);

    /* Checksum */
    neighborAdvertisementHeader.nd_na_hdr.icmp6_cksum = icmp6_checksum(
            ipv6header,
            neighborAdvertisementHeader.nd_na_hdr,
            icmpPayload,
            icmpPayloadLength
    );

    free(icmpPayload);

    length = ETH_HLEN + IP6_HDRLEN + ICMP_NEIGH_ADV_HDRLEN;

    data = (uint8_t *) malloc(length * sizeof(uint8_t));
    memcpy(data, &etherHeader, ETH_HLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN, &ipv6header, IP6_HDRLEN * sizeof(uint8_t));
    memcpy(data + ETH_HLEN + IP6_HDRLEN, &neighborAdvertisementHeader,
           sizeof(struct nd_neighbor_advert) * sizeof(uint8_t));
    memcpy(data + ETH_HLEN + IP6_HDRLEN + sizeof(struct nd_neighbor_advert), &targetLinkAddressOptionHeader,
           sizeof(struct nd_opt_hdr) * sizeof(uint8_t));
    memcpy(data + ETH_HLEN + IP6_HDRLEN + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr),
           &targetLinkAddress, ETH_ALEN);

    icmPv6Packet = new ICMPv6_packet(data, length);

    free(data);

    return icmPv6Packet;
}

icmp6_hdr ICMPv6_packet::constructICMP6header(uint8_t type, uint8_t code) {
    struct icmp6_hdr header;

    /*
     * http://www.pdbuchan.com/rawsock/rawsock.html
     * Table 9:	sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
     * icmp6_ll.c
     *
     */

    // Message Type (8 bits)
    header.icmp6_type = type;

    // Message Code (8 bits)
    header.icmp6_code = code;

    // Identifier (16 bits): usually pid of sending process - pick a number
    header.icmp6_id = htons(0x4B1D);

    // Sequence Number (16 bits): starts at 0
    header.icmp6_seq = htons(0);

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    header.icmp6_cksum = 0;

    return header;
}

uint16_t ICMPv6_packet::icmp6_checksum(
        struct ip6_hdr iphdr,
        struct icmp6_hdr icmp6hdr,
        uint8_t *payload,
        size_t payloadlen
) {
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    size_t i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
    ptr += sizeof(iphdr.ip6_src);
    chksumlen += sizeof(iphdr.ip6_src);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
    ptr += sizeof(iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

    // Copy Upper Layer Packet length into buf (32 bits).
    // Should not be greater than 65535 (i.e., 2 bytes).
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = (char) ((ICMP_ECHO_REQUEST_HDRLEN + payloadlen) / 256);
    ptr++;
    *ptr = (char) ((ICMP_ECHO_REQUEST_HDRLEN + payloadlen) % 256);
    ptr++;
    chksumlen += 4;

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
    ptr += sizeof(iphdr.ip6_nxt);
    chksumlen += sizeof(iphdr.ip6_nxt);

    // Copy ICMPv6 type to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_type, sizeof(icmp6hdr.icmp6_type));
    ptr += sizeof(icmp6hdr.icmp6_type);
    chksumlen += sizeof(icmp6hdr.icmp6_type);

    // Copy ICMPv6 code to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_code, sizeof(icmp6hdr.icmp6_code));
    ptr += sizeof(icmp6hdr.icmp6_code);
    chksumlen += sizeof(icmp6hdr.icmp6_code);

    // Copy ICMPv6 ID to buf (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_id, sizeof(icmp6hdr.icmp6_id));
    ptr += sizeof(icmp6hdr.icmp6_id);
    chksumlen += sizeof(icmp6hdr.icmp6_id);

    // Copy ICMPv6 sequence number to buff (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_seq, sizeof(icmp6hdr.icmp6_seq));
    ptr += sizeof(icmp6hdr.icmp6_seq);
    chksumlen += sizeof(icmp6hdr.icmp6_seq);

    // Copy ICMPv6 checksum to buf (16 bits)
    // Zero, since we don't know it yet.
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy ICMPv6 payload to buf
    memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr += 1;
        chksumlen += 1;
    }

    return checksum((uint16_t *) buf, chksumlen);
}

uint16_t ICMPv6_packet::checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = (uint16_t) ~sum;

    return (answer);
}

