#include <thread>
#include <sstream>
#include "PacketManager.h"
#include "ARP_packet.h"
#include "ICMPv6_packet.h"

template<typename T>
vector<PacketManager<T> *> PacketManager<T>::instances;

template<typename T>
PacketManager<T>::PacketManager(NetworkInterface &networkInterface) : networkInterface(networkInterface) {
    instances.push_back(this);

    /* Initialize pcap handle for sending packets */
    char errorBuffer[PCAP_ERRBUF_SIZE];
    sendPCAP_handle = pcap_open_live(networkInterface.getName().c_str(), 96, 1, 0, errorBuffer);
    if (sendPCAP_handle == NULL)
        throw runtime_error(errorBuffer);
}

template<typename T>
PacketManager<T>::PacketManager(
        NetworkInterface &networkInterface,
        string listenFilterExpression
) : PacketManager(networkInterface) {
    setListenFilterExpression(listenFilterExpression);
}

template<typename T>
PacketManager<T>::~PacketManager() {
    clean();
}

template<typename T>
void PacketManager<T>::clean() {
    if (sendPCAP_handle != nullptr && sendPCAP_handle != NULL) {
        pcap_close(sendPCAP_handle);
    }

    for (auto &packet : caughtPackets) {
        delete (packet);
    }
}

template<typename T>
void PacketManager<T>::listen() {
    mtx.lock();
    listenThread = thread(&PacketManager::listenTask, this);
}

template<typename T>
void PacketManager<T>::listenTask() {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    listenPCAP_handle = pcap_open_live(networkInterface.getName().c_str(), 1024, 0, 1000, errorBuffer);
    if (listenPCAP_handle == NULL) {
        throw runtime_error(errorBuffer);
    }

    setupFilters();

    /* Allow to send packets */
    mtx.unlock();

    pcap_loop(listenPCAP_handle, 0, packetHandler, reinterpret_cast<u_char *>(this));
    pcap_close(listenPCAP_handle);
}

template<typename T>
void PacketManager<T>::packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload) {
    PacketManager *packetManager = reinterpret_cast<PacketManager *>(args);
    packetManager->processPacket((u_char *) payload, header->caplen);
}

template<typename T>
void PacketManager<T>::stopListen() {
    pcap_breakloop(listenPCAP_handle);
}

template<typename T>
void PacketManager<T>::wait() {
    listenThread.join();
}

template<typename T>
void PacketManager<T>::send(Packet *packet) {
    int status;

    /* Wait for beginning of pcap_loop */
    mtx.lock();

    status = pcap_inject(sendPCAP_handle, packet->getRawData(), packet->getLength());

    if (status == -1)
        throw runtime_error(pcap_geterr(sendPCAP_handle));

    mtx.unlock();

}

template<typename T>
void PacketManager<T>::setupFilters() {
    int status;
    struct bpf_program filter;

    /* no filter */
    if (listenFilterExpression.empty())
        return;

    status = pcap_compile(listenPCAP_handle, &filter, listenFilterExpression.c_str(), 0, 0);
    if (status == -1) {
        throw runtime_error(pcap_geterr(listenPCAP_handle));
    }

    status = pcap_setfilter(listenPCAP_handle, &filter);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    pcap_freecode(&filter);
}

template<typename T>
void PacketManager<T>::setListenFilterExpression(const string &listenFilterExpression) {
    PacketManager::listenFilterExpression = listenFilterExpression;
}

template<typename T>
void PacketManager<T>::processPacket(u_char *payload, size_t length) {
    lastCaughtPacket = new T(payload, length);
    caughtPackets.push_back(lastCaughtPacket);
}

template<typename T>
const vector<Packet *> &PacketManager<T>::getCaughtPackets() {
    return caughtPackets;
}

template<typename T>
const vector<PacketManager<T> *> &PacketManager<T>::getInstances() {
    return instances;
}

template<typename T>
string PacketManager<T>::createHostFilter(string target, string separator, set<in_addr> addresses) {
    stringstream res;

    for (set<in_addr>::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (it != addresses.begin()) {
            res << " " << separator << " ";
        }

        res << target << " " << Utils::ipv4ToString((*it));
    }

    return res.str();
}

template<typename T>
string PacketManager<T>::createHostFilter(string target, string separator, set<in6_addr> addresses) {
    stringstream res;

    for (set<in6_addr>::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (it != addresses.begin()) {
            res << " " << separator << " ";
        }

        res << target << " " << Utils::ipv6ToString((*it));
    }

    return res.str();
}

template<typename T>
string PacketManager<T>::createSrcFilter(set<in_addr> addresses) {
    return PacketManager<T>::createHostFilter("src", "or", addresses);
}

template<typename T>
string PacketManager<T>::createSrcFilter(set<in6_addr> addresses) {
    return PacketManager<T>::createHostFilter("src", "or", addresses);
}

template<typename T>
string PacketManager<T>::createDstFilter(set<in_addr> addresses) {
    return PacketManager<T>::createHostFilter("dst", "or", addresses);
}

template<typename T>
string PacketManager<T>::createDstFilter(set<in6_addr> addresses) {
    return PacketManager<T>::createHostFilter("dst", "or", addresses);
}

template
class PacketManager<ARP_packet>;

template
class PacketManager<ICMPv6_packet>;

template
class PacketManager<Packet>;