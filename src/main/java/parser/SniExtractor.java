package parser;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

/** Extracts hostnames from TLS SNI, HTTP Host headers and DNS questions. */
public class SniExtractor {
    public Optional<String> extractTlsSni(byte[] data) {
        if (data == null || data.length < 9 || (data[0] & 255) != 0x16) return Optional.empty();
        int recordLength = u16(data, 3);
        if (recordLength > data.length - 5 || (data[5] & 255) != 1) return Optional.empty();

        int limit = Math.min(data.length, 5 + recordLength);
        int offset = 9; // TLS record header (5 bytes) + handshake header (4 bytes).
        int handshakeLength = u24(data, 6);
        limit = Math.min(limit, offset + handshakeLength);
        if (!hasBytes(offset, 34, limit)) return Optional.empty();
        offset += 34; // Client version and random value.

        if (!hasBytes(offset, 1, limit)) return Optional.empty();
        int sessionLength = data[offset++] & 255;
        if (!hasBytes(offset, sessionLength + 2, limit)) return Optional.empty();
        offset += sessionLength;

        int cipherLength = u16(data, offset);
        offset += 2;
        if (!hasBytes(offset, cipherLength + 1, limit)) return Optional.empty();
        offset += cipherLength;

        int compressionLength = data[offset++] & 255;
        if (!hasBytes(offset, compressionLength + 2, limit)) return Optional.empty();
        offset += compressionLength;
        int extensionsLength = u16(data, offset);
        offset += 2;
        int extensionsEnd = Math.min(limit, offset + extensionsLength);

        while (hasBytes(offset, 4, extensionsEnd)) {
            int type = u16(data, offset);
            int length = u16(data, offset + 2);
            offset += 4;
            if (!hasBytes(offset, length, extensionsEnd)) return Optional.empty();
            if (type == 0 && length >= 5) { // Extension 0 is Server Name Indication (SNI).
                int nameType = data[offset + 2] & 255;
                int nameLength = u16(data, offset + 3);
                if (nameType == 0 && nameLength <= length - 5 && hasBytes(offset + 5, nameLength, offset + length)) {
                    return Optional.of(new String(data, offset + 5, nameLength, StandardCharsets.US_ASCII));
                }
            }
            offset += length;
        }
        return Optional.empty();
    }

    public Optional<String> extractHttpHost(byte[] data) {
        if (data == null || data.length < 4) return Optional.empty();
        String request = new String(data, StandardCharsets.ISO_8859_1);
        if (!(request.startsWith("GET ") || request.startsWith("POST ") || request.startsWith("HEAD ")
                || request.startsWith("PUT ") || request.startsWith("DELETE ") || request.startsWith("PATCH ")
                || request.startsWith("OPTIONS "))) return Optional.empty();

        for (String line : request.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Host")) {
                String host = line.substring(colon + 1).trim();
                int colonInHost = host.lastIndexOf(':');
                if (colonInHost > 0 && host.indexOf(':') == colonInHost) host = host.substring(0, colonInHost);
                if (!host.isEmpty()) return Optional.of(host);
            }
        }
        return Optional.empty();
    }

    public Optional<String> extractDnsQuery(byte[] data) {
        if (data == null || data.length < 12 || (data[2] & 0x80) != 0 || u16(data, 4) == 0) {
            return Optional.empty();
        }
        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < data.length) {
            int length = data[offset++] & 255;
            if (length == 0) break;
            if (length > 63 || offset + length > data.length) return Optional.empty();
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, offset, length, StandardCharsets.US_ASCII));
            offset += length;
        }
        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }

    /** Maps a hostname to a recognizable application label. */
    public String classifyHost(String host) {
        if (host == null || host.isBlank()) return "Unknown";
        String value = host.toLowerCase(Locale.ROOT);
        if (value.contains("youtube") || value.contains("ytimg")) return "YouTube";
        if (value.contains("google") || value.contains("gstatic") || value.contains("googleapis")) return "Google";
        if (value.contains("facebook") || value.contains("fbcdn") || value.contains("meta.com")) return "Facebook";
        if (value.contains("instagram")) return "Instagram";
        if (value.contains("whatsapp") || value.contains("wa.me")) return "WhatsApp";
        if (value.contains("twitter") || value.contains("x.com") || value.contains("twimg")) return "Twitter/X";
        if (value.contains("netflix") || value.contains("nflx")) return "Netflix";
        if (value.contains("amazon") || value.contains("cloudfront") || value.contains("amazonaws")) return "Amazon";
        if (value.contains("microsoft") || value.contains("office.com") || value.contains("outlook")) return "Microsoft";
        if (value.contains("apple") || value.contains("icloud")) return "Apple";
        if (value.contains("telegram") || value.contains("t.me")) return "Telegram";
        if (value.contains("tiktok")) return "TikTok";
        if (value.contains("spotify")) return "Spotify";
        if (value.contains("discord")) return "Discord";
        if (value.contains("github")) return "GitHub";
        if (value.contains("cloudflare")) return "Cloudflare";
        return "HTTPS";
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }

    private static int u24(byte[] data, int offset) {
        return ((data[offset] & 255) << 16) | ((data[offset + 1] & 255) << 8) | (data[offset + 2] & 255);
    }

    private static boolean hasBytes(int offset, int length, int limit) {
        return offset >= 0 && length >= 0 && offset <= limit && length <= limit - offset;
    }
}
