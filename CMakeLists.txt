cmake_minimum_required(VERSION 3.12.3)
project(RechnernetzPraxis)

include(FindPCAP.cmake)

add_executable(RawEthernet RawEthernet.cpp)
target_link_libraries(RawEthernet)


# target_link_libraries(RawEthernet ${PCAP_LIBRARY})
