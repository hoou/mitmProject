#ifndef PROJEKT_NEW_PACKETMANAGER_H
#define PROJEKT_NEW_PACKETMANAGER_H


#include <mutex>
#include "NetworkInterface.h"
#include "Packet.h"
#include <thread>
#include <vector>

using namespace std;

template<typename T>
class PacketManager {
private:
    static vector<PacketManager *> instances;
    NetworkInterface &networkInterface;
    pcap_t *sendPCAP_handle;

    mutex mtx;
    thread listenThread;
    string listenFilterExpression;

    T *lastCaughtPacket;
    vector<Packet *> caughtPackets;

    void listenTask();

    void setupFilters();

    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

    pcap_t *listenPCAP_handle;

    void processPacket(u_char *payload, size_t length);

    void clean();

public:

    PacketManager(NetworkInterface &networkInterface);

    PacketManager(NetworkInterface &networkInterface, string listenFilterExpression);

    virtual ~PacketManager();

    void setListenFilterExpression(const string &listenFilterExpression);

    void listen();

    void stopListen();

    void send(Packet *packet);

    void wait();

    const vector<Packet *> &getCaughtPackets();

    static const vector<PacketManager *> &getInstances();
};


#endif //PROJEKT_NEW_PACKETMANAGER_H
