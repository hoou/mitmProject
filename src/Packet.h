#ifndef PDS_MITM_PACKET_H
#define PDS_MITM_PACKET_H

#include <vector>
#include <netinet/if_ether.h>
#include <ostream>
#include "Utils.h"

using namespace std;

/**
 * Packet containing raw data, length and structure for ethernet header
 */
class Packet {
protected:
    uint8_t *rawData;
    size_t length;
    struct ether_header ethernetHeader;

    /**
     * Construct structure for ethernet header
     * @param type
     * @param source sender MAC address
     * @param destination target MAC address
     * @return ethernet header structure
     */
    static struct ether_header constructEthernetHeader(
            uint16_t type,
            mac_addr source,
            mac_addr destination
    );

public:
    /**
     * Construct packet
     * @param data packet raw data
     * @param length length of packet
     */
    Packet(const uint8_t *data, size_t length);

    /**
     * Destructor. Delete raw data
     */
    virtual ~Packet();

    uint8_t *getRawData() const;

    size_t getLength() const;

    uint16_t getType() const;

    mac_addr getEthernetSourceAddress();

    mac_addr getEthernetDestinationAddress();

    void setEthernetSourceAddress(mac_addr address);

    void setEthernetDestinationAddress(mac_addr address);

    friend ostream &operator<<(ostream &os, const Packet &packet);
};


#endif //PDS_MITM_PACKET_H
