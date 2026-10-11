package model;

import java.util.Arrays;

/** A packet plus the information found while parsing its headers. */
public class PacketJob {
    public long packetId;
    public long timestampSeconds;
    public long timestampFraction;
    public FiveTuple tuple;
    public byte[] data = new byte[0];
    public int tcpFlags;
    public int ipOffset;
    public int transportOffset;
    public int payloadOffset;
    public int payloadLength;

    public byte[] getPayload() {
        if (data == null || payloadOffset < 0 || payloadLength <= 0 || payloadOffset >= data.length) {
            return new byte[0];
        }
        int end = Math.min(data.length, payloadOffset + payloadLength);
        return Arrays.copyOfRange(data, payloadOffset, end);
    }
}
