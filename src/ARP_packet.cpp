#include "ARP_packet.h"
#include <cstring>

ARP_packet::ARP_packet(const uint8_t *data, size_t length) : Packet(data, length) {
    setupHeaders();
}

void ARP_packet::setupHeaders() {
    memcpy(&ARP_struct, rawData + ETH_HLEN, sizeof(struct ether_arp));
}

/* http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap/send_arp.c */
ARP_packet *ARP_packet::createRequest(
        mac_addr senderHardwareAddr,
        in_addr senderProtocolAddr,
        in_addr targetProtocolAddr
) {
    uint8_t *data;
    size_t length;
    size_t arpLength = sizeof(struct ether_arp);

    struct ether_header etherHeader = constructEthernetHeader(ETH_P_ARP, senderHardwareAddr, Utils::constructEthernetBroadcastAddress());
    struct ether_arp arpStruct = constructArpRequest(senderHardwareAddr, senderProtocolAddr, targetProtocolAddr);

    length = ETH_HLEN + arpLength;

    data = (uint8_t *) malloc(sizeof(uint8_t) * length);

    memcpy(data, &etherHeader, ETH_HLEN);
    memcpy(data + ETH_HLEN, &arpStruct, arpLength);

    ARP_packet *arpPacket = new ARP_packet(data, length);
    arpPacket->ARP_struct = arpStruct;

    free(data);

    return arpPacket;
}

struct ether_arp ARP_packet::constructArpRequest(
        mac_addr senderHardwareAddr, in_addr senderProtocolAddr, in_addr targetProtocolAddr
) {
    struct ether_arp arpStruct;

    /* APR header */
    arpStruct.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arpStruct.ea_hdr.ar_pro = htons(ETH_P_IP);
    arpStruct.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arpStruct.ea_hdr.ar_pln = sizeof(in_addr_t);
    arpStruct.ea_hdr.ar_op = htons(ARPOP_REQUEST);

    /* Sender hardware address */
    memcpy(&arpStruct.arp_sha, senderHardwareAddr.data(), sizeof(arpStruct.arp_sha));

    /* Sender protocol address */
    memcpy(&arpStruct.arp_spa, &senderProtocolAddr.s_addr, sizeof(arpStruct.arp_spa));

    /* Target hardware address */
    memset(&arpStruct.arp_tha, 0, sizeof(arpStruct.arp_tha)); // always 0 when requesting, we are trying to find it

    /* Target protocol address */
    memcpy(&arpStruct.arp_tpa, &targetProtocolAddr.s_addr, sizeof(arpStruct.arp_tpa));

    return arpStruct;
}

mac_addr ARP_packet::getSenderHardwareAddr() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ARP_struct.arp_sha);
}

in_addr ARP_packet::getSenderProtocolAddr() {
    return Utils::constructIpv4addressFromRawData((const uint8_t *) ARP_struct.arp_spa);
}

mac_addr ARP_packet::getTargetHardwareAddr() {
    return Utils::constructMacAddressFromRawData((const uint8_t *) ARP_struct.arp_tha);
}

in_addr ARP_packet::getTargetProtocolAddr() {
    return Utils::constructIpv4addressFromRawData((const uint8_t *) ARP_struct.arp_tpa);
}

unsigned short ARP_packet::getArpType() {
    return ntohs(ARP_struct.ea_hdr.ar_op);
}
