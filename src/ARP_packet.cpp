#include "ARP_packet.h"
#include <cstring>

ARP_packet::ARP_packet(const uint8_t *data, size_t length) : Packet(data, length) {
    setupHeader();
}

void ARP_packet::setupHeader() {
    memcpy(&ARP_struct, rawData + ETH_HLEN, sizeof(struct ether_arp));
}

ARP_packet *ARP_packet::create(
        uint16_t type,
        mac_addr ethernetDestination,
        mac_addr ethernetSource,
        mac_addr senderHardwareAddress,
        in_addr senderProtocolAddress,
        mac_addr targetHardwareAddress,
        in_addr targetProtocolAddress
) {
    uint8_t *data;
    size_t length;

    struct ether_header etherHeader = constructEthernetHeader(
            ETH_P_ARP,
            ethernetSource,
            ethernetDestination
    );
    struct ether_arp arpHeader = constructArpHeader(
            type,
            senderHardwareAddress,
            senderProtocolAddress,
            targetHardwareAddress,
            targetProtocolAddress
    );

    length = ETH_HLEN + ARP_HLEN;

    data = (uint8_t *) malloc(sizeof(uint8_t) * length);

    memcpy(data, &etherHeader, ETH_HLEN);
    memcpy(data + ETH_HLEN, &arpHeader, ARP_HLEN);

    ARP_packet *arpPacket = new ARP_packet(data, length);

    free(data);

    return arpPacket;
}

/* http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap/send_arp.c */
ARP_packet *ARP_packet::createRequest(
        mac_addr senderHardwareAddress,
        in_addr senderProtocolAddress,
        in_addr targetProtocolAddress
) {
    return create(
            ARPOP_REQUEST,
            Utils::constructEthernetBroadcastAddress(), // send broadcast(to all nodes)
            senderHardwareAddress,
            senderHardwareAddress,
            senderProtocolAddress,
            Utils::constructZeroMacAddress(), // when requesting, we are trying to find out target hardware address, set this to all zeros
            targetProtocolAddress
    );
}

ARP_packet *ARP_packet::createReply(
        mac_addr senderHardwareAddress,
        in_addr senderProtocolAddress,
        mac_addr targetHardwareAddress,
        in_addr targetProtocolAddress
) {
    return create(
            ARPOP_REPLY,
            targetHardwareAddress,
            senderHardwareAddress,
            senderHardwareAddress,
            senderProtocolAddress,
            targetHardwareAddress,
            targetProtocolAddress
    );
}

ether_arp ARP_packet::constructArpHeader(
        uint16_t type,
        mac_addr senderHardwareAddress,
        in_addr senderProtocolAddress,
        mac_addr targetHardwareAddress,
        in_addr targetProtocolAddress
) {
    struct ether_arp arpStruct;

    /* APR header */
    arpStruct.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arpStruct.ea_hdr.ar_pro = htons(ETH_P_IP);
    arpStruct.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arpStruct.ea_hdr.ar_pln = sizeof(in_addr_t);
    arpStruct.ea_hdr.ar_op = htons(type);

    /* Sender hardware address */
    memcpy(&arpStruct.arp_sha, senderHardwareAddress.data(), sizeof(arpStruct.arp_sha));

    /* Sender protocol address */
    memcpy(&arpStruct.arp_spa, &senderProtocolAddress.s_addr, sizeof(arpStruct.arp_spa));

    /* Target hardware address */
    memcpy(&arpStruct.arp_tha, targetHardwareAddress.data(), sizeof(arpStruct.arp_tha));

    /* Target protocol address */
    memcpy(&arpStruct.arp_tpa, &targetProtocolAddress.s_addr, sizeof(arpStruct.arp_tpa));

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
