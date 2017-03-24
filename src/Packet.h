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

    static struct ether_header constructEthernetHeader(
            uint16_t type,
            mac_addr source,
            mac_addr destination = mac_addr()
    );

    Packet(const uint8_t *data, size_t length);

public:
    virtual ~Packet();

    uint8_t *getRawData() const;

    size_t getLength() const;
};


#endif //PROJEKT_NEW_PACKET_H
