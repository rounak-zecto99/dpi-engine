package model;

import java.util.Objects;

/** Identifies a network flow using source/destination IPs, ports and protocol. */
public class FiveTuple {
    public final long srcIp;
    public final long dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol;

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp & 0xFFFF_FFFFL;
        this.dstIp = dstIp & 0xFFFF_FFFFL;
        this.srcPort = srcPort & 0xFFFF;
        this.dstPort = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /** Packs an IPv4 address in the same low-byte-first form used by the parser. */
    public static long parseIPv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        long result = 0;
        for (int i = 0; i < 4; i++) {
            int value = Integer.parseInt(parts[i]);
            if (value < 0 || value > 255) throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            result |= ((long) value) << (i * 8);
        }
        return result;
    }

    public static String formatIPv4(long ip) {
        return (ip & 255) + "." + ((ip >>> 8) & 255) + "."
                + ((ip >>> 16) & 255) + "." + ((ip >>> 24) & 255);
    }

    /** Same hash for both directions of a connection, so both use the same worker. */
    public long flowHash() {
        long source = endpointHash(srcIp, srcPort);
        long destination = endpointHash(dstIp, dstPort);
        long first = Math.min(source, destination);
        long second = Math.max(source, destination);
        long hash = first * 31 + second;
        hash = hash * 31 + protocol;
        hash ^= (hash >>> 33);
        hash *= 0xff51afd7ed558ccdL;
        hash ^= (hash >>> 33);
        return hash;
    }

    private long endpointHash(long ip, int port) {
        return (ip << 16) ^ port;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof FiveTuple)) return false;
        FiveTuple tuple = (FiveTuple) other;
        return srcIp == tuple.srcIp && dstIp == tuple.dstIp
                && srcPort == tuple.srcPort && dstPort == tuple.dstPort
                && protocol == tuple.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        String name = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "IP";
        return formatIPv4(srcIp) + ":" + srcPort + " -> "
                + formatIPv4(dstIp) + ":" + dstPort + " (" + name + ")";
    }
}
