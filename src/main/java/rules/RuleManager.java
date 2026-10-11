package rules;

import model.FiveTuple;
import model.PacketJob;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Stores IP, application, domain and port blocking rules. */
public class RuleManager {
    private final Set<Long> blockedIps = new LinkedHashSet<>();
    private final Set<String> blockedApplications = new LinkedHashSet<>();
    private final Set<String> blockedDomains = new LinkedHashSet<>();
    private final Set<Integer> blockedPorts = new LinkedHashSet<>();

    public synchronized void blockIP(String ip) { blockedIps.add(FiveTuple.parseIPv4(ip)); }
    public synchronized void unblockIP(String ip) { blockedIps.remove(FiveTuple.parseIPv4(ip)); }

    public synchronized void blockApp(String application) {
        if (application != null && !application.isBlank()) {
            blockedApplications.add(application.trim().toLowerCase(Locale.ROOT));
        }
    }

    public synchronized void unblockApp(String application) {
        if (application != null) blockedApplications.remove(application.trim().toLowerCase(Locale.ROOT));
    }

    public synchronized void blockDomain(String domain) {
        if (domain != null && !domain.isBlank()) {
            String normalized = domain.trim().toLowerCase(Locale.ROOT);
            if (normalized.startsWith("*.")) normalized = normalized.substring(2);
            blockedDomains.add(normalized);
        }
    }

    public synchronized void unblockDomain(String domain) {
        if (domain != null) {
            String normalized = domain.trim().toLowerCase(Locale.ROOT);
            if (normalized.startsWith("*.")) normalized = normalized.substring(2);
            blockedDomains.remove(normalized);
        }
    }

    public synchronized void blockPort(int port) {
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Port must be between 0 and 65535");
        blockedPorts.add(port);
    }

    public synchronized void unblockPort(int port) { blockedPorts.remove(port); }

    /** Returns a reason when any rule matches, or an empty string when it does not. */
    public synchronized String findBlockReason(PacketJob packet, String application, String domain) {
        if (blockedIps.contains(packet.tuple.srcIp)) return "source IP " + FiveTuple.formatIPv4(packet.tuple.srcIp);
        if (blockedIps.contains(packet.tuple.dstIp)) return "destination IP " + FiveTuple.formatIPv4(packet.tuple.dstIp);
        if (blockedPorts.contains(packet.tuple.srcPort)) return "source port " + packet.tuple.srcPort;
        if (blockedPorts.contains(packet.tuple.dstPort)) return "destination port " + packet.tuple.dstPort;

        if (application != null && blockedApplications.contains(application.toLowerCase(Locale.ROOT))) {
            return "application " + application;
        }
        if (domain != null && !domain.isBlank()) {
            String host = domain.toLowerCase(Locale.ROOT);
            for (String blocked : blockedDomains) {
                // A rule for example.com also matches www.example.com.
                if (host.equals(blocked) || host.endsWith("." + blocked)) return "domain " + domain;
            }
        }
        return "";
    }

    public synchronized int getBlockedIpCount() { return blockedIps.size(); }
    public synchronized int getBlockedAppCount() { return blockedApplications.size(); }
    public synchronized int getBlockedDomainCount() { return blockedDomains.size(); }
    public synchronized int getBlockedPortCount() { return blockedPorts.size(); }

    /** Loads the original section-based C++ format and the simpler key=value format. */
    public boolean loadRules(String fileName) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(fileName), StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("Could not load rules: " + e.getMessage());
            return false;
        }

        String section = "";
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.toUpperCase(Locale.ROOT);
                continue;
            }

            int equals = line.indexOf('=');
            String type;
            String value;
            if (equals > 0) {
                type = line.substring(0, equals).trim().toLowerCase(Locale.ROOT);
                value = line.substring(equals + 1).trim();
            } else {
                value = line;
                if ("[BLOCKED_IPS]".equals(section)) type = "block-ip";
                else if ("[BLOCKED_APPS]".equals(section)) type = "block-app";
                else if ("[BLOCKED_DOMAINS]".equals(section)) type = "block-domain";
                else if ("[BLOCKED_PORTS]".equals(section)) type = "block-port";
                else continue;
            }

            try {
                switch (type) {
                    case "block-ip" -> blockIP(value);
                    case "block-app" -> blockApp(value);
                    case "block-domain" -> blockDomain(value);
                    case "block-port" -> blockPort(Integer.parseInt(value));
                    default -> System.err.println("Unknown rule type: " + type);
                }
            } catch (RuntimeException e) {
                System.err.println("Ignoring invalid rule: " + line);
            }
        }
        return true;
    }

    /** Saves rules in the same section-based format as the original C++ project. */
    public synchronized boolean saveRules(String fileName) {
        List<String> lines = new ArrayList<>();
        lines.add("[BLOCKED_IPS]");
        for (long ip : blockedIps) lines.add(FiveTuple.formatIPv4(ip));
        lines.add("");
        lines.add("[BLOCKED_APPS]");
        for (String app : blockedApplications) lines.add(app);
        lines.add("");
        lines.add("[BLOCKED_DOMAINS]");
        for (String domain : blockedDomains) lines.add(domain);
        lines.add("");
        lines.add("[BLOCKED_PORTS]");
        for (int port : blockedPorts) lines.add(Integer.toString(port));
        try {
            Files.write(Path.of(fileName), lines, StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            System.err.println("Could not save rules: " + e.getMessage());
            return false;
        }
    }
}
