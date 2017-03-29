cmake_minimum_required(VERSION 3.6)
project(pds-mitm)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(Pcap)
find_package(LibXml2)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")

include_directories(${PCAP_INCLUDE_DIR} ${LIBXML2_INCLUDE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../build)

add_definitions(${LIBXML2_DEFINITIONS})

add_subdirectory(src)
