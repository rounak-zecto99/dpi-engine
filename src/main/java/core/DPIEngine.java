package core;

import connection.ConnectionTracker;
import connection.GlobalConnectionTable;
import model.Config;
import model.FiveTuple;
import model.PacketAction;
import model.PacketJob;
import parser.PacketParser;
import pcap.PcapReader;
import pcap.PcapWriter;
import pipeline.BlockingPacketQueue;
import pipeline.FastPath;
import pipeline.LoadBalancer;
import rules.RuleManager;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Coordinates PCAP reading, load balancers, workers, filtering and PCAP output. */
public class DPIEngine implements AutoCloseable {
    private final Config config;
    private final DPIStats stats = new DPIStats();
    private final BlockingPacketQueue<PacketResult> outputQueue;
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final RuleManager ruleManager = new RuleManager();
    private final GlobalConnectionTable connectionTable = new GlobalConnectionTable();
    private final PacketParser packetParser = new PacketParser();

    private Thread outputThread;

    /** A worker result must be kept until earlier packet IDs have finished. */
    private static class PacketResult {
        PacketJob packet;
        PacketAction action;

        PacketResult(PacketJob packet, PacketAction action) {
            this.packet = packet;
            this.action = action;
        }
    }
    private PcapWriter pcapWriter;
    private boolean initialized;
    private boolean started;

    public DPIEngine(Config config) {
        this.config = config;
        this.outputQueue = new BlockingPacketQueue<>(config.queueSize);
    }

    /** Create load balancers and fast-path workers. */
    public boolean initialize() {
        if (initialized) return true;
        if (config.numLoadBalancers < 1 || config.workersPerLoadBalancer < 1) {
            System.err.println("Need at least one load balancer and one worker per load balancer");
            return false;
        }

        if (config.rulesFile != null && !config.rulesFile.isBlank()) {
            if (!ruleManager.loadRules(config.rulesFile)) return false;
        }

        int nextWorkerId = 0;
        for (int i = 0; i < config.numLoadBalancers; i++) {
            final LoadBalancer loadBalancer = new LoadBalancer(
                    i,
                    nextWorkerId,
                    config.workersPerLoadBalancer,
                    ruleManager,
                    this::handleWorkerResult,
                    config.queueSize
            );
            loadBalancers.add(loadBalancer);
            for (FastPath worker : loadBalancer.getWorkers()) {
                connectionTable.registerTracker(worker.getWorkerId(), worker.getConnectionTracker());
            }
            nextWorkerId += config.workersPerLoadBalancer;
        }

        initialized = true;
        System.out.println("[DPIEngine] Initialized " + config.numLoadBalancers + " load balancers and "
                + nextWorkerId + " fast-path workers");
        return true;
    }

    /** Process one input capture and write packets that were not blocked. */
    public boolean processFile(String inputFile, String outputFile) {
        if (!initialize()) return false;

        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) return false;

        pcapWriter = new PcapWriter();
        if (!pcapWriter.open(outputFile, reader.getGlobalHeader())) {
            reader.close();
            return false;
        }

        startWorkers();
        long packetId = 0;
        PcapReader.RawPacket rawPacket;

        while ((rawPacket = reader.readNextPacket()) != null) {
            PacketParser.ParsedPacket parsed = packetParser.parse(rawPacket.data);
            if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                continue;
            }

            PacketJob packet = createPacketJob(rawPacket, parsed, packetId++);
            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(packet.data.length);
            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            int loadBalancerIndex = (int) Math.floorMod(packet.tuple.flowHash(), (long) loadBalancers.size());
            if (!loadBalancers.get(loadBalancerIndex).enqueue(packet)) {
                System.err.println("[DPIEngine] A load-balancer queue was closed early");
            }
        }

        reader.close();
        stopWorkersAndWriteRemainingPackets();
        pcapWriter.close();
        pcapWriter = null;

        System.out.println(generateReport());
        System.out.println(generateClassificationReport());
        return true;
    }

    private void startWorkers() {
        if (started) throw new IllegalStateException("This engine instance has already processed a file");
        started = true;
        outputThread = new Thread(this::writeOutputQueue, "dpi-output-writer");
        outputThread.start();
        for (LoadBalancer loadBalancer : loadBalancers) loadBalancer.start();
    }

    /** Called by workers after a packet has been inspected. */
    private void handleWorkerResult(PacketJob packet, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
        } else {
            stats.forwardedPackets.incrementAndGet();
        }
        // Queue both FORWARD and DROP results so the writer can preserve packet order.
        if (!outputQueue.push(new PacketResult(packet, action))) {
            System.err.println("[DPIEngine] Output queue was closed before packet result was written");
        }
    }

    private void writeOutputQueue() {
        Map<Long, PacketResult> waitingForEarlierPackets = new TreeMap<>();
        long nextPacketId = 0;

        while (true) {
            PacketResult result = outputQueue.popWithTimeout(Duration.ofMillis(100));
            if (result != null) {
                waitingForEarlierPackets.put(result.packet.packetId, result);
            }

            // Other workers may finish sooner. Only write the next original packet ID.
            while (waitingForEarlierPackets.containsKey(nextPacketId)) {
                PacketResult ready = waitingForEarlierPackets.remove(nextPacketId);
                if (ready.action == PacketAction.FORWARD) {
                    pcapWriter.writePacket(ready.packet);
                }
                nextPacketId++;
            }

            if (outputQueue.isShutdown() && outputQueue.isEmpty()) break;
        }

        if (!waitingForEarlierPackets.isEmpty()) {
            System.err.println("[DPIEngine] Warning: some packet results were missing; output may be incomplete");
        }
    }

    private void stopWorkersAndWriteRemainingPackets() {
        // A load balancer first drains its own queue, then drains each worker queue.
        for (LoadBalancer loadBalancer : loadBalancers) loadBalancer.stopAndDrain();
        // All workers have finished, so no new packet will be added to this queue.
        outputQueue.shutdown();
        join(outputThread);
    }

    private PacketJob createPacketJob(PcapReader.RawPacket raw,
                                      PacketParser.ParsedPacket parsed,
                                      long packetId) {
        PacketJob packet = new PacketJob();
        packet.packetId = packetId;
        packet.timestampSeconds = raw.header.seconds;
        packet.timestampFraction = raw.header.fraction;
        packet.tuple = new FiveTuple(
                FiveTuple.parseIPv4(parsed.sourceIp),
                FiveTuple.parseIPv4(parsed.destinationIp),
                parsed.sourcePort,
                parsed.destinationPort,
                parsed.protocol
        );
        packet.data = raw.data.clone();
        packet.tcpFlags = parsed.tcpFlags;
        packet.ipOffset = 14;
        packet.transportOffset = parsed.transportOffset;
        packet.payloadOffset = parsed.payloadOffset;
        packet.payloadLength = parsed.payloadLength;
        return packet;
    }

    // Methods used to configure blocking rules before processing starts.
    public void blockIP(String ip) { ruleManager.blockIP(ip); }
    public void unblockIP(String ip) { ruleManager.unblockIP(ip); }
    public void blockApp(String application) { ruleManager.blockApp(application); }
    public void unblockApp(String application) { ruleManager.unblockApp(application); }
    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain) { ruleManager.unblockDomain(domain); }
    public void blockPort(int port) { ruleManager.blockPort(port); }
    public void unblockPort(int port) { ruleManager.unblockPort(port); }
    public boolean loadRules(String fileName) { return ruleManager.loadRules(fileName); }
    public boolean saveRules(String fileName) { return ruleManager.saveRules(fileName); }
    public RuleManager getRuleManager() { return ruleManager; }
    public DPIStats getStats() { return stats; }
    public GlobalConnectionTable getGlobalConnectionTable() { return connectionTable; }

    public String generateReport() {
        StringBuilder report = new StringBuilder();
        report.append("================ DPI ENGINE REPORT ================\n");
        addLine(report, "Packets inspected", stats.totalPackets.get());
        addLine(report, "Bytes inspected", stats.totalBytes.get());
        addLine(report, "TCP packets", stats.tcpPackets.get());
        addLine(report, "UDP packets", stats.udpPackets.get());
        addLine(report, "Forwarded packets", stats.forwardedPackets.get());
        addLine(report, "Dropped packets", stats.droppedPackets.get());
        long total = stats.totalPackets.get();
        double dropRate = total == 0 ? 0.0 : 100.0 * stats.droppedPackets.get() / total;
        report.append(String.format(java.util.Locale.ROOT, "Drop rate: %.2f%%\n", dropRate));
        report.append("Active connections: ").append(connectionTable.getActiveConnectionCount()).append('\n');
        report.append("Blocked IP rules: ").append(ruleManager.getBlockedIpCount()).append('\n');
        report.append("Blocked app rules: ").append(ruleManager.getBlockedAppCount()).append('\n');
        report.append("Blocked domain rules: ").append(ruleManager.getBlockedDomainCount()).append('\n');
        report.append("Blocked port rules: ").append(ruleManager.getBlockedPortCount()).append('\n');
        return report.toString();
    }

    public String generateClassificationReport() {
        java.util.Map<String, Integer> apps = new java.util.TreeMap<>();
        java.util.Map<String, Integer> domains = new java.util.TreeMap<>();
        for (ConnectionTracker tracker : connectionTable.getTrackers()) {
            for (ConnectionTracker.ConnectionInfo connection : tracker.getAllConnections()) {
                apps.put(connection.application, apps.getOrDefault(connection.application, 0) + 1);
                if (!connection.domain.isBlank()) {
                    domains.put(connection.domain, domains.getOrDefault(connection.domain, 0) + 1);
                }
            }
        }

        StringBuilder report = new StringBuilder("APPLICATION CLASSIFICATION\n");
        for (String app : apps.keySet()) {
            report.append(String.format(java.util.Locale.ROOT, "%-16s %d%n", app, apps.get(app)));
        }
        if (!domains.isEmpty()) {
            report.append("\nObserved domains\n");
            for (String domain : domains.keySet()) report.append(domain).append(" : ").append(domains.get(domain)).append('\n');
        }
        return report.toString();
    }

    public void printStatus() {
        System.out.println("Packets: " + stats.totalPackets.get()
                + " | Forwarded: " + stats.forwardedPackets.get()
                + " | Dropped: " + stats.droppedPackets.get());
    }

    @Override
    public void close() {
        if (pcapWriter != null) pcapWriter.close();
    }

    private static void addLine(StringBuilder report, String label, long value) {
        report.append(String.format(java.util.Locale.ROOT, "%-22s %d%n", label + ":", value));
    }

    private static void join(Thread thread) {
        if (thread == null) return;
        try {
            thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
