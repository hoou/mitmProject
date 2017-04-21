#ifndef PDS_MITM_IPV4_PACKET_H
#define PDS_MITM_IPV4_PACKET_H

#include <netinet/ip.h>
#include "Packet.h"

/**
 * IPv4 packet
 */
class IPv4_packet : Packet {
private:
    struct ip ipv4Header;

    void setupHeader();

public:
    /**
     * Construt IPv4 packet
     * @param data packet raw data
     * @param length length of packet
     */
    IPv4_packet(const uint8_t *data, size_t length);

    in_addr getSourceAddress();

    in_addr getDestinationAddress();
};


#endif //PDS_MITM_IPV4_PACKET_H
