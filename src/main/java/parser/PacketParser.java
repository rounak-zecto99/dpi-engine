package parser;

import model.FiveTuple;
import java.util.Locale;

/** Reads Ethernet, IPv4, TCP and UDP headers from raw packet bytes. */
public class PacketParser {
    public static final int TCP = 6;
    public static final int UDP = 17;
    public static final int SYN = 0x02;
    public static final int ACK = 0x10;
    public static final int FIN = 0x01;
    public static final int RST = 0x04;

    public static class ParsedPacket {
        public boolean hasIp;
        public boolean hasTcp;
        public boolean hasUdp;
        public String sourceIp = "";
        public String destinationIp = "";
        public int sourcePort;
        public int destinationPort;
        public int protocol;
        public int tcpFlags;
        public int ipHeaderLength;
        public int transportOffset;
        public int payloadOffset;
        public int payloadLength;
    }

    /** Returns null for packets with unsupported or malformed headers. */
    public ParsedPacket parse(byte[] data) {
        if (data == null || data.length < 14) return null;

        int etherType = readUnsignedShort(data, 12);
        if (etherType != 0x0800) return null; // This project currently supports IPv4 only.
        if (data.length < 14 + 20) return null;

        int ipOffset = 14;
        int versionAndLength = data[ipOffset] & 255;
        int version = versionAndLength >>> 4;
        int ipHeaderLength = (versionAndLength & 15) * 4;
        if (version != 4 || ipHeaderLength < 20 || data.length < ipOffset + ipHeaderLength) return null;

        ParsedPacket packet = new ParsedPacket();
        packet.hasIp = true;
        packet.protocol = data[ipOffset + 9] & 255;
        packet.sourceIp = FiveTuple.formatIPv4(readIpv4(data, ipOffset + 12));
        packet.destinationIp = FiveTuple.formatIPv4(readIpv4(data, ipOffset + 16));
        packet.ipHeaderLength = ipHeaderLength;

        int transportOffset = ipOffset + ipHeaderLength;
        packet.transportOffset = transportOffset;

        if (packet.protocol == TCP) {
            if (data.length < transportOffset + 20) return null;
            packet.sourcePort = readUnsignedShort(data, transportOffset);
            packet.destinationPort = readUnsignedShort(data, transportOffset + 2);
            int tcpHeaderLength = ((data[transportOffset + 12] & 255) >>> 4) * 4;
            packet.tcpFlags = data[transportOffset + 13] & 255;
            if (tcpHeaderLength < 20 || data.length < transportOffset + tcpHeaderLength) return null;
            packet.hasTcp = true;
            packet.payloadOffset = transportOffset + tcpHeaderLength;
        } else if (packet.protocol == UDP) {
            if (data.length < transportOffset + 8) return null;
            packet.sourcePort = readUnsignedShort(data, transportOffset);
            packet.destinationPort = readUnsignedShort(data, transportOffset + 2);
            packet.hasUdp = true;
            packet.payloadOffset = transportOffset + 8;
        } else {
            return null;
        }

        packet.payloadLength = Math.max(0, data.length - packet.payloadOffset);
        return packet;
    }

    public static int readUnsignedShort(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }

    private static long readIpv4(byte[] data, int offset) {
        return (data[offset] & 255L)
                | ((data[offset + 1] & 255L) << 8)
                | ((data[offset + 2] & 255L) << 16)
                | ((data[offset + 3] & 255L) << 24);
    }

    public static String macToString(byte[] data, int offset) {
        return String.format(Locale.ROOT, "%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset] & 255, data[offset + 1] & 255, data[offset + 2] & 255,
                data[offset + 3] & 255, data[offset + 4] & 255, data[offset + 5] & 255);
    }
}
