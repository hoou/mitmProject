include_directories(..)

set(SOURCE_FILES
        main.cpp
        ScannerArguments.cpp
        ../ARP_packetManager.cpp
        ../NetworkInterface.cpp
        ../Subnet.cpp
        ../Utils.cpp
        ../ARP_packet.cpp
        HostsList.cpp
        ../ICMPv6_packetManager.cpp
        ../PacketManager.cpp
        ../Packet.cpp
        ../ICMPv6_packet.cpp
        ../IIPv6_packet.cpp
        )

add_executable(pds-scanner ${SOURCE_FILES})

target_link_libraries(pds-scanner ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})
