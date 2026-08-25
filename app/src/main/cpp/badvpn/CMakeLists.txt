# badvpn tun2socks for Android — CMake port of Psiphon's Android.mk
#
# Source: Psiphon-Inc/psiphon-android, app/src/main/jni/badvpn
# License: BSD 3-clause (see COPYING). Copyright (c) 2009 Ambroz Bizjak.
#
# This produces libtun2socks.so, exposing three JNI methods that are registered
# from JNI_OnLoad against ca/psiphon/Tun2SocksJniLoader:
#   runTun2Socks(int fd, int mtu, String ip4, String mask, String ip6,
#                String socksAddr, String udpgwAddr, int transparentDns,
#                int udpgwDnsOnly)
#   terminateTun2Socks()
#   initTun2socksLogger(String className, String methodName)
#
# The TCP/IP stack is lwIP. Do not add a hand-written TCP implementation
# alongside it — that was the mistake this port replaces.

cmake_minimum_required(VERSION 3.22.1)
project(tun2socks C)

set(BADVPN_DIR ${CMAKE_CURRENT_LIST_DIR})

add_library(tun2socks SHARED
    base/BLog_syslog.c
    system/BReactor_badvpn.c
    system/BSignal.c
    system/BConnection_unix.c
    system/BTime.c
    system/BUnixSignal.c
    system/BNetwork.c
    flow/StreamRecvInterface.c
    flow/PacketRecvInterface.c
    flow/PacketPassInterface.c
    flow/StreamPassInterface.c
    flow/SinglePacketBuffer.c
    flow/BufferWriter.c
    flow/PacketBuffer.c
    flow/PacketStreamSender.c
    flow/PacketPassConnector.c
    flow/PacketProtoFlow.c
    flow/PacketPassFairQueue.c
    flow/PacketProtoEncoder.c
    flow/PacketProtoDecoder.c
    socksclient/BSocksClient.c
    tuntap/BTap.c
    lwip/src/core/timers.c
    lwip/src/core/udp.c
    lwip/src/core/memp.c
    lwip/src/core/init.c
    lwip/src/core/pbuf.c
    lwip/src/core/tcp.c
    lwip/src/core/tcp_out.c
    lwip/src/core/netif.c
    lwip/src/core/def.c
    lwip/src/core/mem.c
    lwip/src/core/tcp_in.c
    lwip/src/core/stats.c
    lwip/src/core/inet_chksum.c
    lwip/src/core/ipv4/icmp.c
    lwip/src/core/ipv4/ip4.c
    lwip/src/core/ipv4/ip4_addr.c
    lwip/src/core/ipv4/ip_frag.c
    lwip/src/core/ipv6/ip6.c
    lwip/src/core/ipv6/nd6.c
    lwip/src/core/ipv6/icmp6.c
    lwip/src/core/ipv6/ip6_addr.c
    lwip/src/core/ipv6/ip6_frag.c
    lwip/custom/sys.c
    tun2socks/tun2socks.c
    base/DebugObject.c
    base/BLog.c
    base/BPending.c
    flowextra/PacketPassInactivityMonitor.c
    tun2socks/SocksUdpGwClient.c
    udpgw_client/UdpGwClient.c
)

target_include_directories(tun2socks PRIVATE
    ${BADVPN_DIR}
    ${BADVPN_DIR}/lwip/src/include/ipv4
    ${BADVPN_DIR}/lwip/src/include/ipv6
    ${BADVPN_DIR}/lwip/src/include
    ${BADVPN_DIR}/lwip/custom
)

target_compile_definitions(tun2socks PRIVATE
    BADVPN_THREAD_SAFE=0
    BADVPN_LINUX
    BADVPN_BREACTOR_BADVPN
    _GNU_SOURCE
    BADVPN_USE_SELFPIPE
    BADVPN_USE_EPOLL
    BADVPN_LITTLE_ENDIAN
    PSIPHON
)

target_compile_options(tun2socks PRIVATE
    -std=gnu99
    # badvpn is a 2009-era codebase; these warnings are noise under a modern
    # clang and -Werror is not used upstream either.
    -Wno-pointer-sign
    -Wno-unused-variable
    -Wno-unused-function
    -Wno-implicit-function-declaration
)

# 16KB page size — required for Android 15+ / Google Play.
target_link_options(tun2socks PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)

find_library(log-lib log)
target_link_libraries(tun2socks ${log-lib})
