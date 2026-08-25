/*
 * Copyright (c) 2024, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package ca.psiphon;

/**
 * JNI bridge to libtun2socks.so (badvpn + lwIP).
 *
 * The package and class name MUST stay exactly ca.psiphon.Tun2SocksJniLoader:
 * the native JNI_OnLoad in tun2socks.c does
 * FindClass("ca/psiphon/Tun2SocksJniLoader") and registers the three natives
 * below by signature. Renaming or moving this class makes System.loadLibrary
 * fail with JNI_ERR.
 */
public class Tun2SocksJniLoader {
    static {
        System.loadLibrary("tun2socks");
    }

    public static void initializeLogger(String className, String methodName) {
        // Replace '.' with '/' in the class name
        String formattedClassName = className.replace('.', '/');
        initTun2socksLogger(formattedClassName, methodName);
    }

    private native static void initTun2socksLogger(String className, String logMethodName);

    // Starts tun2socks. Blocks on the calling thread until terminateTun2Socks().
    public native static void runTun2Socks(
            int vpnInterfaceFileDescriptor,
            int vpnInterfaceMTU,
            String vpnIpv4Address,
            String vpnIpv4NetMask,
            // If vpnIpv6Address is null, IPv6 routing is disabled
            String vpnIpv6Address,
            String socksServerAddress,
            String udpgwServerAddress,
            int udpgwTransparentDNS,
            // MSN-GUARD: when 1, udpgw accepts only DNS (UDP port 53); all other
            // UDP is dropped before it can consume a connection slot. Tor sets
            // this because its SOCKS front cannot carry non-DNS UDP anyway.
            int udpgwDnsOnly);

    // Stops tun2socks
    public native static void terminateTun2Socks();
}
