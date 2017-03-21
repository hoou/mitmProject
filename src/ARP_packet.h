#ifndef PROJEKT_NEW_ARPPACKET_H
#define PROJEKT_NEW_ARPPACKET_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cstdint>
#include <netinet/in.h>
#include <string>

using namespace std;

class ARP_packet {
private:
    struct ether_header ethernetHeader;
    struct ether_arp ARP_struct;
    static const size_t frameSize = sizeof(struct ether_header) + sizeof(struct ether_arp);
    unsigned char frame[frameSize];

    void constructEthernetHeader(const u_int8_t *source, const u_int8_t *destination = nullptr);

    void
    constructArpRequest(const u_int8_t *senderHardwareAddr, in_addr senderProtocolAddr, in_addr targetProtocolAddr);

    void constructContiguousFrame();

    ARP_packet();

public:
    static ARP_packet constructFromRawData(const u_char *data);

    static ARP_packet request(const u_int8_t *senderHardwareAddr,in_addr senderProtocolAddr, in_addr targetProtocolAddr);

    const unsigned char *getFrame() const;

    static const size_t getFrameSize();

    const u_int8_t *getSenderHardwareAddr();

    const u_int8_t *getSenderProtocolAddr();

    const u_int8_t *getTargetHardwareAddr();

    const u_int8_t *getTargetProtocolAddr();

    unsigned short getArpType();
};


#endif //PROJEKT_NEW_ARPPACKET_H
