#ifndef PROJEKT_NEW_PACKET_H
#define PROJEKT_NEW_PACKET_H

#include <vector>
#include <netinet/if_ether.h>
#include "Utils.h"

using namespace std;

class Packet {
protected:
    uint8_t *rawData;
    size_t length;
    struct ether_header ethernetHeader;

    virtual void setupHeaders();

    static struct ether_header constructEthernetHeader(
            uint16_t type,
            mac_addr source,
            mac_addr destination
    );

public:
    Packet(const uint8_t *data, size_t length);

    virtual ~Packet();

    uint8_t *getRawData() const;

    size_t getLength() const;

    mac_addr getEthernetSourceAddress();

    mac_addr getEthernetDestinationAddress();
};


#endif //PROJEKT_NEW_PACKET_H
