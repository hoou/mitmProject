#ifndef PROJEKT_NEW_PACKETMANAGER_H
#define PROJEKT_NEW_PACKETMANAGER_H


#include <mutex>
#include "NetworkInterface.h"
#include "Packet.h"
#include <thread>

class PacketManager {
private:
    NetworkInterface *networkInterface;
    pcap_t *sendPCAP_handle;

    mutex mtx;
    thread listenThread;
    string listenFilterExpression;

    void listenTask();

    void setupFilters();

    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

protected:

    pcap_t *listenPCAP_handle;

    void setListenFilterExpression(const string &listenFilterExpression);

    virtual void processPacket(u_char *payload, size_t length)=0;

public:

    void init(NetworkInterface *networkInterface);

    void listen();

    void stopListen();

    virtual void send(Packet *packet);

    void wait();

    virtual void clean();
};


#endif //PROJEKT_NEW_PACKETMANAGER_H
