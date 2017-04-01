#ifndef PROJEKT_NEW_ARPPACKET_H
#define PROJEKT_NEW_ARPPACKET_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <array>
#include "Utils.h"
#include "Packet.h"

#define ARP_HLEN sizeof(struct ether_arp)

using namespace std;

class ARP_packet : public Packet {
private:
    struct ether_arp ARP_struct;

    static ether_arp constructArpHeader(
            uint16_t type,
            mac_addr senderHardwareAddress,
            in_addr senderProtocolAddress,
            mac_addr targetHardwareAddress,
            in_addr targetProtocolAddress
    );

protected:
    void setupHeaders();

public:
    ARP_packet(const uint8_t *data, size_t length);

    static ARP_packet *create(
            uint16_t type,
            mac_addr ethernetDestination,
            mac_addr ethernetSource,
            mac_addr senderHardwareAddress,
            in_addr senderProtocolAddress,
            mac_addr targetHardwareAddress,
            in_addr targetProtocolAddress
    );

    static ARP_packet *createRequest(
            mac_addr senderHardwareAddress,
            in_addr senderProtocolAddress,
            in_addr targetProtocolAddress
    );

    static ARP_packet *createReply(
            mac_addr senderHardwareAddress,
            in_addr senderProtocolAddress,
            mac_addr targetHardwareAddress,
            in_addr targetProtocolAddress
    );

    mac_addr getSenderHardwareAddr();

    in_addr getSenderProtocolAddr();

    mac_addr getTargetHardwareAddr();

    in_addr getTargetProtocolAddr();

    unsigned short getArpType();
};


#endif //PROJEKT_NEW_ARPPACKET_H
