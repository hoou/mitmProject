#ifndef PROJEKT_NEW_ARPPACKET_H
#define PROJEKT_NEW_ARPPACKET_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <array>

using namespace std;

class ARP_packet {
private:
    struct ether_header ethernetHeader;
    struct ether_arp ARP_struct;
    static const size_t frameSize = sizeof(struct ether_header) + sizeof(struct ether_arp);
    unsigned char frame[frameSize];

    ARP_packet();

    void constructEthernetHeader(
            array<u_int8_t, ETH_ALEN> source,
            array<u_int8_t, ETH_ALEN> destination = array<u_int8_t, ETH_ALEN>()
    );

    void constructArpRequest(
            array<u_int8_t, ETH_ALEN> senderHardwareAddr,
            in_addr senderProtocolAddr,
            in_addr targetProtocolAddr
    );

    void constructContiguousFrame();

public:
    static ARP_packet constructFromRawData(const u_char *data);

    static ARP_packet request(
            array<u_int8_t, ETH_ALEN> senderHardwareAddr,
            in_addr senderProtocolAddr,
            in_addr targetProtocolAddr
    );

    const unsigned char *getFrame() const;

    static const size_t getFrameSize();

    array<u_int8_t, ETH_ALEN> getSenderHardwareAddr();

    in_addr getSenderProtocolAddr();

    array<u_int8_t, ETH_ALEN> getTargetHardwareAddr();

    in_addr getTargetProtocolAddr();

    unsigned short getArpType();
};


#endif //PROJEKT_NEW_ARPPACKET_H
