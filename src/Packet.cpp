#include <cstring>
#include <iostream>
#include "Packet.h"

Packet::Packet(const uint8_t *data, size_t length) : length(length) {
    rawData = (uint8_t *) malloc(sizeof(uint8_t) * length);
    memcpy(rawData, data, length);
    memcpy(&ethernetHeader, data, ETH_HLEN);
}

Packet::~Packet() {
    free(rawData);
}

struct ether_header Packet::constructEthernetHeader(uint16_t type, mac_addr source, mac_addr destination) {
    struct ether_header header;

    header.ether_type = htons(type);

    memcpy(header.ether_shost, source.data(), ETH_ALEN);
    memcpy(header.ether_dhost, destination.data(), ETH_ALEN);

    return header;
}

uint8_t *Packet::getRawData() const {
    return rawData;
}

size_t Packet::getLength() const {
    return length;
}

mac_addr Packet::getEthernetSourceAddress() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ethernetHeader.ether_shost);
}

mac_addr Packet::getEthernetDestinationAddress() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ethernetHeader.ether_dhost);
}
