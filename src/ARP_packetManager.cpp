#include <pcap.h>
#include <stdexcept>
#include <thread>
#include "ARP_packetManager.h"

mutex ARP_packetManager::mtx;
NetworkInterface *ARP_packetManager::networkInterface;
thread ARP_packetManager::listenThread;
pcap_t *ARP_packetManager::listenPCAP_handle = nullptr;
pcap_t *ARP_packetManager::sendPCAP_handle = nullptr;
vector<ARP_packet> ARP_packetManager::caughtARPpackets;

ARP_packetManager::ARP_packetManager() {}

/* http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap/send_arp.c */
void ARP_packetManager::sendRequest(ARP_packet arpPacket) {
    int status;

    /* Wait for beginning of pcap_loop */
    mtx.lock();

    status = pcap_inject(sendPCAP_handle, arpPacket.getFrame(), arpPacket.getFrameSize());

    if (status == -1)
        throw runtime_error(pcap_geterr(sendPCAP_handle));

    mtx.unlock();
}

void ARP_packetManager::listen() {
    mtx.lock();
    listenThread = thread(ARP_packetManager::listenTask);
}

void ARP_packetManager::stopListen() {
    pcap_breakloop(listenPCAP_handle);
}

void ARP_packetManager::listenTask() {
    int status;
    char errorBuffer[PCAP_ERRBUF_SIZE];
//    string filterExpression = "arp and dst net " + string(inet_ntoa(networkInterface->getAddress()));
    string filterExpression = "arp";
    struct bpf_program filter;

    listenPCAP_handle = pcap_open_live(networkInterface->getName().c_str(), 1024, 0, 1000, errorBuffer);
    if (listenPCAP_handle == NULL)
        throw runtime_error(errorBuffer);

    status = pcap_compile(listenPCAP_handle, &filter, filterExpression.c_str(), 0, 0);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    status = pcap_setfilter(listenPCAP_handle, &filter);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    pcap_freecode(&filter);

    mtx.unlock(); // Allow to send ARP packets
    pcap_loop(listenPCAP_handle, 0, packetHandler, NULL);

    pcap_close(listenPCAP_handle);
}

void ARP_packetManager::packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    caughtARPpackets.push_back(ARP_packet::constructFromRawData(packet));
}

void ARP_packetManager::wait() {
    listenThread.join();
}

void ARP_packetManager::init(NetworkInterface *networkInterface) {
    ARP_packetManager::networkInterface = networkInterface;

    /* Initialize pcap handle for sending packets */
    char errorBuffer[PCAP_ERRBUF_SIZE];
    sendPCAP_handle = pcap_open_live(networkInterface->getName().c_str(), 96, 1, 0, errorBuffer);
    if (sendPCAP_handle == NULL)
        throw runtime_error(errorBuffer);
}

const vector<ARP_packet> &ARP_packetManager::getCaughtARP_packets() {
    return caughtARPpackets;
}

void ARP_packetManager::clean() {
    if (sendPCAP_handle != nullptr && sendPCAP_handle != NULL) {
        pcap_close(sendPCAP_handle);
    }
}
