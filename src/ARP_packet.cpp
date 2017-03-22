#include "ARP_packet.h"
#include "Utils.h"
#include <cstring>

ARP_packet::ARP_packet() {}

ARP_packet
ARP_packet::request(
        array<u_int8_t, ETH_ALEN> senderHardwareAddr,
        in_addr senderProtocolAddr,
        in_addr targetProtocolAddr
) {
    /* http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap/send_arp.c */
    ARP_packet arpPacket;
    arpPacket.constructEthernetHeader(senderHardwareAddr);
    arpPacket.constructArpRequest(senderHardwareAddr, senderProtocolAddr, targetProtocolAddr);
    arpPacket.constructContiguousFrame();
    return arpPacket;
}

ARP_packet ARP_packet::constructFromRawData(const u_char *data) {
    ARP_packet arpPacket;
    memcpy(&arpPacket.ethernetHeader, data, ETH_HLEN);
    memcpy(&arpPacket.ARP_struct, data + ETH_HLEN, sizeof(struct ether_arp));
    memcpy(&arpPacket.frame, data, getFrameSize());
    return arpPacket;
}

void
ARP_packet::constructArpRequest(array<u_int8_t, ETH_ALEN> senderHardwareAddr, in_addr senderProtocolAddr,
                                in_addr targetProtocolAddr) {
    /* APR header */
    ARP_struct.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    ARP_struct.ea_hdr.ar_pro = htons(ETH_P_IP);
    ARP_struct.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    ARP_struct.ea_hdr.ar_pln = sizeof(in_addr_t);
    ARP_struct.ea_hdr.ar_op = htons(ARPOP_REQUEST);

    /* Sender hardware address */
    memcpy(&ARP_struct.arp_sha, senderHardwareAddr.data(), sizeof(ARP_struct.arp_sha));

    /* Sender protocol address */
    memcpy(&ARP_struct.arp_spa, &senderProtocolAddr.s_addr, sizeof(ARP_struct.arp_spa));

    /* Target hardware address */
    memset(&ARP_struct.arp_tha, 0, sizeof(ARP_struct.arp_tha)); // always 0 when requesting, we are trying to find it

    /* Target protocol address */
    memcpy(&ARP_struct.arp_tpa, &targetProtocolAddr.s_addr, sizeof(ARP_struct.arp_tpa));
}

void ARP_packet::constructEthernetHeader(array<u_int8_t, ETH_ALEN> source, array<u_int8_t, ETH_ALEN> destination) {
    ethernetHeader.ether_type = htons(ETH_P_ARP);
    memcpy(ethernetHeader.ether_shost, source.data(), ETH_ALEN);

    /* If destination address not set, send broadcast */
    if (Utils::isZeroMacAddress(destination)) {
        memset(ethernetHeader.ether_dhost, 0xff, ETH_ALEN);
    } else {
        memcpy(ethernetHeader.ether_dhost, destination.data(), ETH_ALEN);
    }
}

void ARP_packet::constructContiguousFrame() {
    memcpy(frame, &ethernetHeader, sizeof(struct ether_header));
    memcpy(frame + sizeof(struct ether_header), &ARP_struct, sizeof(struct ether_arp));
}

const unsigned char *ARP_packet::getFrame() const {
    return frame;
}

const size_t ARP_packet::getFrameSize() {
    return frameSize;
}

array<u_int8_t, ETH_ALEN> ARP_packet::getSenderHardwareAddr() {
    return Utils::constructMacAddressFromRawData(ARP_struct.arp_sha);
}

in_addr ARP_packet::getSenderProtocolAddr() {
    return Utils::constructIpv4addressFromRawData(ARP_struct.arp_spa);
}

array<u_int8_t, ETH_ALEN> ARP_packet::getTargetHardwareAddr() {
    return Utils::constructMacAddressFromRawData(ARP_struct.arp_tha);
}

in_addr ARP_packet::getTargetProtocolAddr() {
    return Utils::constructIpv4addressFromRawData(ARP_struct.arp_tpa);
}

unsigned short ARP_packet::getArpType() {
    return ntohs(ARP_struct.ea_hdr.ar_op);
}
