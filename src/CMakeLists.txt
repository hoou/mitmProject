include_directories(.)

set(SCANNER_SOURCE_FILES
        scanner.cpp
        ScannerArguments.cpp
        NetworkInterface.cpp
        Subnet.cpp
        Utils.cpp
        ARP_packet.cpp
        HostsList.cpp
        PacketManager.cpp
        Packet.cpp
        ICMPv6_packet.cpp
        IIPv6_packet.cpp
        )

set(SPOOF_SOURCE_FILES
        spoof.cpp
        SpoofArguments.cpp
        Utils.cpp
        NetworkInterface.cpp
        ARP_packet.cpp
        PacketManager.cpp
        Packet.cpp
        Subnet.cpp
        ICMPv6_packet.cpp
        IIPv6_packet.cpp
        )

add_executable(pds-scanner ${SCANNER_SOURCE_FILES})

add_executable(pds-spoof ${SPOOF_SOURCE_FILES})

target_link_libraries(pds-scanner ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})

target_link_libraries(pds-spoof ${PCAP_LIBRARIES})
