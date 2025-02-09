#include <cstring>
#include <iostream>
#include "Packet.h"

Packet::Packet(const uint8_t *data, size_t length) : length(length) {
    rawData = (uint8_t *) malloc(sizeof(uint8_t) * length);
    memcpy(rawData, data, length);

    /* Setup ethernet header */
    memcpy(&ethernetHeader, rawData, ETH_HLEN);
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

uint16_t Packet::getType() const {
    return (uint16_t) ethernetHeader.ether_type;
}

mac_addr Packet::getEthernetSourceAddress() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ethernetHeader.ether_shost);
}

mac_addr Packet::getEthernetDestinationAddress() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ethernetHeader.ether_dhost);
}

void Packet::setEthernetSourceAddress(mac_addr address) {
    memcpy(ethernetHeader.ether_shost, address.data(), ETH_ALEN);
    memcpy(rawData + ETH_ALEN, address.data(), ETH_ALEN);
}

void Packet::setEthernetDestinationAddress(mac_addr address) {
    memcpy(ethernetHeader.ether_dhost, address.data(), ETH_ALEN);
    memcpy(rawData, address.data(), ETH_ALEN);
}

ostream &operator<<(ostream &os, const Packet &packet) {
    os << "length: " << packet.length << endl;
    os << "type: " << packet.ethernetHeader.ether_type << endl;
    os << "src: " << Utils::formatMacAddress(
            Utils::constructMacAddressFromRawData((const uint8_t *) packet.ethernetHeader.ether_shost),
            six_groups_of_two_hexa_digits_sep_colon) << endl;
    os << "dst: " << Utils::formatMacAddress(
            Utils::constructMacAddressFromRawData((const uint8_t *) packet.ethernetHeader.ether_dhost),
            six_groups_of_two_hexa_digits_sep_colon);
    return os;
}
