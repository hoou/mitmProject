#ifndef PDS_MITM_INTERCEPTPACKETMANAGER_H
#define PDS_MITM_INTERCEPTPACKETMANAGER_H


#include "PacketManager.h"
#include "Host.h"

class InterceptPacketManager : public PacketManager<Packet> {
private:
    Host from;
    Host to;

    void initFilters();

protected:
    void processPacket(u_char *payload, size_t length) override;

public:
    InterceptPacketManager(NetworkInterface &networkInterface, Host from, Host to);
};


#endif //PDS_MITM_INTERCEPTPACKETMANAGER_H
