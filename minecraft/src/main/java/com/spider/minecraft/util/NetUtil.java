package com.spider.minecraft.util;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

/**
 * 网络工具类：获取本机 LAN 地址、生成短 ID 等。
 */
public final class NetUtil {

    private NetUtil() {}

    public static List<Inet4Address> getLocalIPv4Addresses() {
        List<Inet4Address> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) {
                    continue;
                }
                Enumeration<InetAddress> addrs = iface.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address ipv4 && !addr.isLoopbackAddress()) {
                        result.add(ipv4);
                    }
                }
            }
        } catch (SocketException e) {
            // 忽略
        }
        return result;
    }

    public static String getPrimaryLocalIPv4() {
        List<Inet4Address> addrs = getLocalIPv4Addresses();
        if (addrs.isEmpty()) {
            return "127.0.0.1";
        }
        return addrs.get(0).getHostAddress();
    }

    public static String generateShortId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    public static boolean isValidIPv4(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            for (String part : parts) {
                int val = Integer.parseInt(part);
                if (val < 0 || val > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }
}
