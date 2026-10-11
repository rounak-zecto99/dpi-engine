package pcap;

import model.PacketJob;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Writes forwarded packets into a new PCAP file. */
public class PcapWriter implements AutoCloseable {
    private OutputStream output;
    private boolean littleEndian = true;

    public boolean open(String fileName, PcapReader.GlobalHeader header) {
        close();
        try {
            output = new BufferedOutputStream(Files.newOutputStream(Path.of(fileName),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE));
            littleEndian = header.littleEndian;
            // Keep the exact global header from the input file.
            output.write(header.originalBytes);
            return true;
        } catch (IOException e) {
            System.err.println("Could not open PCAP output: " + e.getMessage());
            close();
            return false;
        }
    }

    public void writePacket(PacketJob packet) {
        if (output == null || packet == null || packet.data == null) return;
        try {
            ByteBuffer header = ByteBuffer.allocate(16);
            header.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            header.putInt((int) packet.timestampSeconds);
            header.putInt((int) packet.timestampFraction);
            header.putInt(packet.data.length);
            header.putInt(packet.data.length);
            output.write(header.array());
            output.write(packet.data);
        } catch (IOException e) {
            System.err.println("Could not write packet: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        if (output != null) {
            try { output.close(); } catch (IOException ignored) { }
        }
        output = null;
    }
}
