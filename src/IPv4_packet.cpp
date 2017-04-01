#include <cstring>
#include "IPv4_packet.h"

IPv4_packet::IPv4_packet(const uint8_t *data, size_t length) : Packet(data, length) {
    setupHeader();
}

void IPv4_packet::setupHeader() {
    memcpy(&ipv4Header, rawData + ETH_HLEN, sizeof(ipv4Header));
}

in_addr IPv4_packet::getSourceAddress() {
    return ipv4Header.ip_src;
}

in_addr IPv4_packet::getDestinationAddress() {
    return ipv4Header.ip_dst;
}
