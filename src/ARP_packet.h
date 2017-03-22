#ifndef PROJEKT_NEW_ARPPACKET_H
#define PROJEKT_NEW_ARPPACKET_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <array>
#include "Utils.h"

using namespace std;

class ARP_packet {
private:
    struct ether_header ethernetHeader;
    struct ether_arp ARP_struct;
    static const size_t frameSize = sizeof(struct ether_header) + sizeof(struct ether_arp);
    unsigned char frame[frameSize];

    ARP_packet();

    void constructEthernetHeader(mac_addr source, mac_addr destination = mac_addr());

    void constructArpRequest(mac_addr senderHardwareAddr, in_addr senderProtocolAddr, in_addr targetProtocolAddr);

    void constructContiguousFrame();

public:
    static ARP_packet constructFromRawData(const u_char *data);

    static ARP_packet request(mac_addr senderHardwareAddr, in_addr senderProtocolAddr, in_addr targetProtocolAddr);

    const unsigned char *getFrame() const;

    static const size_t getFrameSize();

    mac_addr getSenderHardwareAddr();

    in_addr getSenderProtocolAddr();

    mac_addr getTargetHardwareAddr();

    in_addr getTargetProtocolAddr();

    unsigned short getArpType();
};


#endif //PROJEKT_NEW_ARPPACKET_H
