package pipeline;

import connection.ConnectionTracker;
import model.PacketAction;
import model.PacketJob;
import parser.PacketParser;
import parser.SniExtractor;
import rules.RuleManager;

import java.time.Duration;
import java.util.Optional;

/** One worker thread that classifies packets and applies blocking rules. */
public class FastPath {
    public interface PacketHandler {
        void onPacket(PacketJob packet, PacketAction action);
    }

    private final int workerId;
    private final BlockingPacketQueue<PacketJob> inputQueue;
    private final ConnectionTracker tracker;
    private final RuleManager rules;
    private final PacketHandler outputHandler;
    private final SniExtractor extractor = new SniExtractor();
    private Thread workerThread;
    private long processedPackets;
    private long forwardedPackets;
    private long droppedPackets;

    public FastPath(int workerId, RuleManager rules, PacketHandler outputHandler, int queueSize) {
        this.workerId = workerId;
        this.rules = rules;
        this.outputHandler = outputHandler;
        this.inputQueue = new BlockingPacketQueue<>(queueSize);
        this.tracker = new ConnectionTracker(workerId);
    }

    public void start() {
        if (workerThread != null) return;
        workerThread = new Thread(this::run, "dpi-fast-path-" + workerId);
        workerThread.start();
    }

    public boolean enqueue(PacketJob packet) {
        return inputQueue.push(packet);
    }

    public void stopAndDrain() {
        inputQueue.shutdown();
        join(workerThread);
    }

    private void run() {
        while (true) {
            PacketJob packet = inputQueue.popWithTimeout(Duration.ofMillis(100));
            if (packet == null) {
                tracker.removeStale(Duration.ofMinutes(5));
                if (inputQueue.isShutdown() && inputQueue.isEmpty()) break;
                continue;
            }

            processedPackets++;
            PacketAction action;
            try {
                action = inspectPacket(packet);
            } catch (RuntimeException e) {
                // A malformed or unexpected payload should not crash the worker.
                System.err.println("[FastPath " + workerId + "] Could not inspect packet: " + e.getMessage());
                action = PacketAction.FORWARD;
            }

            if (action == PacketAction.DROP) droppedPackets++;
            else forwardedPackets++;
            outputHandler.onPacket(packet, action);
        }
    }

    private PacketAction inspectPacket(PacketJob packet) {
        ConnectionTracker.ConnectionInfo connection = tracker.getOrCreate(packet.tuple);
        tracker.update(connection, packet.data.length);

        if (connection.blocked) return PacketAction.DROP;

        if (connection.domain.isEmpty()) inspectPayload(packet, connection);

        String reason = rules.findBlockReason(packet, connection.application, connection.domain);
        if (!reason.isEmpty()) {
            tracker.block(connection);
            System.out.println("[FastPath " + workerId + "] Dropped packet: " + reason);
            return PacketAction.DROP;
        }

        if (packet.tuple.protocol == PacketParser.TCP && (packet.tcpFlags & PacketParser.FIN) != 0) {
            tracker.markClosed(packet.tuple);
        }
        return PacketAction.FORWARD;
    }

    private void inspectPayload(PacketJob packet, ConnectionTracker.ConnectionInfo connection) {
        byte[] payload = packet.getPayload();
        if (payload.length == 0) {
            setApplicationFromPorts(packet, connection);
            return;
        }

        Optional<String> sni = extractor.extractTlsSni(payload);
        if (sni.isPresent()) {
            String host = sni.get();
            tracker.classify(connection, extractor.classifyHost(host), host);
            return;
        }

        Optional<String> host = extractor.extractHttpHost(payload);
        if (host.isPresent()) {
            String application = extractor.classifyHost(host.get());
            if ("HTTPS".equals(application)) application = "HTTP";
            tracker.classify(connection, application, host.get());
            return;
        }

        if (packet.tuple.srcPort == 53 || packet.tuple.dstPort == 53) {
            Optional<String> query = extractor.extractDnsQuery(payload);
            if (query.isPresent()) {
                tracker.classify(connection, "DNS", query.get());
                return;
            }
        }
        setApplicationFromPorts(packet, connection);
    }

    private void setApplicationFromPorts(PacketJob packet, ConnectionTracker.ConnectionInfo connection) {
        int sourcePort = packet.tuple.srcPort;
        int destinationPort = packet.tuple.dstPort;
        if (sourcePort == 53 || destinationPort == 53) {
            tracker.classify(connection, "DNS", "");
        } else if (packet.tuple.protocol == PacketParser.UDP && (sourcePort == 443 || destinationPort == 443)) {
            tracker.classify(connection, "QUIC", "");
        } else if (sourcePort == 80 || destinationPort == 80) {
            tracker.classify(connection, "HTTP", "");
        } else if (sourcePort == 443 || destinationPort == 443) {
            tracker.classify(connection, "HTTPS", "");
        }
    }

    public ConnectionTracker getConnectionTracker() { return tracker; }
    public int getWorkerId() { return workerId; }
    public synchronized long getProcessedPackets() { return processedPackets; }
    public synchronized long getForwardedPackets() { return forwardedPackets; }
    public synchronized long getDroppedPackets() { return droppedPackets; }

    private static void join(Thread thread) {
        if (thread == null) return;
        try {
            thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
