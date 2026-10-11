package pcap;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Reads classic PCAP files, including little- and big-endian captures. */
public class PcapReader implements Closeable {
    public static class GlobalHeader {
        public int versionMajor;
        public int versionMinor;
        public long snapLength;
        public long linkType;
        public boolean littleEndian;
        public boolean nanoTimestamps;
        public byte[] originalBytes;
    }

    public static class PacketHeader {
        public long seconds;
        public long fraction;
        public long capturedLength;
        public long originalLength;
    }

    public static class RawPacket {
        public PacketHeader header;
        public byte[] data;
    }

    private InputStream input;
    private GlobalHeader globalHeader;

    public boolean open(String fileName) {
        close();
        try {
            input = Files.newInputStream(Path.of(fileName));
            byte[] bytes = readExact(input, 24);
            if (bytes == null) throw new EOFException("PCAP header is missing");

            int a = bytes[0] & 255;
            int b = bytes[1] & 255;
            int c = bytes[2] & 255;
            int d = bytes[3] & 255;
            boolean little;
            boolean nano;

            if (a == 0xd4 && b == 0xc3 && c == 0xb2 && d == 0xa1) {
                little = true; nano = false;
            } else if (a == 0xa1 && b == 0xb2 && c == 0xc3 && d == 0xd4) {
                little = false; nano = false;
            } else if (a == 0x4d && b == 0x3c && c == 0xb2 && d == 0xa1) {
                little = true; nano = true;
            } else if (a == 0xa1 && b == 0xb2 && c == 0x3c && d == 0x4d) {
                little = false; nano = true;
            } else {
                throw new IOException("Unrecognized PCAP magic number");
            }

            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            buffer.order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            buffer.getInt(); // Magic number is already checked above.
            GlobalHeader header = new GlobalHeader();
            header.versionMajor = Short.toUnsignedInt(buffer.getShort());
            header.versionMinor = Short.toUnsignedInt(buffer.getShort());
            buffer.getInt(); // timezone
            buffer.getInt(); // timestamp accuracy
            header.snapLength = Integer.toUnsignedLong(buffer.getInt());
            header.linkType = Integer.toUnsignedLong(buffer.getInt());
            header.littleEndian = little;
            header.nanoTimestamps = nano;
            header.originalBytes = bytes;
            globalHeader = header;

            System.out.println("Opened PCAP: " + fileName);
            System.out.println("  Version: " + header.versionMajor + "." + header.versionMinor);
            System.out.println("  Link type: " + header.linkType);
            return true;
        } catch (IOException e) {
            System.err.println("Could not open PCAP: " + e.getMessage());
            close();
            return false;
        }
    }

    public RawPacket readNextPacket() {
        if (input == null) return null;
        try {
            byte[] headerBytes = readExact(input, 16);
            if (headerBytes == null) return null;

            ByteBuffer buffer = ByteBuffer.wrap(headerBytes);
            buffer.order(globalHeader.littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            PacketHeader header = new PacketHeader();
            header.seconds = Integer.toUnsignedLong(buffer.getInt());
            header.fraction = Integer.toUnsignedLong(buffer.getInt());
            header.capturedLength = Integer.toUnsignedLong(buffer.getInt());
            header.originalLength = Integer.toUnsignedLong(buffer.getInt());

            if (header.capturedLength > globalHeader.snapLength || header.capturedLength > 65_535) {
                throw new IOException("Invalid packet length: " + header.capturedLength);
            }
            byte[] data = readExact(input, (int) header.capturedLength);
            if (data == null) throw new EOFException("Packet data is incomplete");

            RawPacket packet = new RawPacket();
            packet.header = header;
            packet.data = data;
            return packet;
        } catch (IOException e) {
            System.err.println("Stopping PCAP read: " + e.getMessage());
            close();
            return null;
        }
    }

    public GlobalHeader getGlobalHeader() { return globalHeader; }

    @Override
    public void close() {
        if (input != null) {
            try { input.close(); } catch (IOException ignored) { }
        }
        input = null;
    }

    private static byte[] readExact(InputStream input, int length) throws IOException {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(bytes, offset, length - offset);
            if (count < 0) {
                if (offset == 0) return null;
                throw new EOFException("Unexpected end of file");
            }
            offset += count;
        }
        return bytes;
    }
}
