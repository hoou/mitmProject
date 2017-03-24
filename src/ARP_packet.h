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

using namespace std;

class ARP_packet : public Packet {
private:
    struct ether_arp ARP_struct;

    static struct ether_arp constructArpRequest(
            mac_addr senderHardwareAddr,
            in_addr senderProtocolAddr,
            in_addr targetProtocolAddr
    );

public:
    ARP_packet(uint8_t *data, size_t length);

    static ARP_packet * createRequest(
            mac_addr senderHardwareAddr,
            in_addr senderProtocolAddr,
            in_addr targetProtocolAddr
    );

    mac_addr getSenderHardwareAddr();

    in_addr getSenderProtocolAddr();

    mac_addr getTargetHardwareAddr();

    in_addr getTargetProtocolAddr();

    unsigned short getArpType();
};


#endif //PROJEKT_NEW_ARPPACKET_H
