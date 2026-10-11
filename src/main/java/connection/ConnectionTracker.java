package connection;

import model.FiveTuple;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Stores basic state for flows handled by one fast-path worker. */
public class ConnectionTracker {
    public static class ConnectionInfo {
        public final FiveTuple tuple;
        public String application = "Unknown";
        public String domain = "";
        public long packets;
        public long bytes;
        public Instant lastSeen = Instant.now();
        public boolean blocked;
        public boolean closed;

        public ConnectionInfo(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }

    private final int workerId;
    private final int maximumConnections;
    private final Map<FiveTuple, ConnectionInfo> connections = new HashMap<>();

    public ConnectionTracker(int workerId) {
        this(workerId, 100_000);
    }

    public ConnectionTracker(int workerId, int maximumConnections) {
        this.workerId = workerId;
        this.maximumConnections = Math.max(1, maximumConnections);
    }

    /** Finds a connection in either direction, or creates it if this is the first packet. */
    public synchronized ConnectionInfo getOrCreate(FiveTuple tuple) {
        ConnectionInfo connection = connections.get(tuple);
        if (connection == null) connection = connections.get(tuple.reverse());
        if (connection != null) return connection;

        if (connections.size() >= maximumConnections) removeOldestConnection();
        connection = new ConnectionInfo(tuple);
        connections.put(tuple, connection);
        return connection;
    }

    public synchronized void update(ConnectionInfo connection, int packetLength) {
        connection.packets++;
        connection.bytes += packetLength;
        connection.lastSeen = Instant.now();
    }

    public synchronized void classify(ConnectionInfo connection, String application, String domain) {
        if (connection == null || connection.blocked) return;
        if (application != null && !application.isBlank()) connection.application = application;
        if (domain != null && !domain.isBlank()) connection.domain = domain;
        connection.lastSeen = Instant.now();
    }

    public synchronized void block(ConnectionInfo connection) {
        if (connection != null) connection.blocked = true;
    }

    public synchronized void markClosed(FiveTuple tuple) {
        ConnectionInfo connection = connections.get(tuple);
        if (connection == null) connection = connections.get(tuple.reverse());
        if (connection != null) connection.closed = true;
    }

    public synchronized int removeStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int before = connections.size();
        connections.entrySet().removeIf(entry -> entry.getValue().lastSeen.isBefore(cutoff)
                || entry.getValue().closed);
        return before - connections.size();
    }

    public synchronized List<ConnectionInfo> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public synchronized int getActiveCount() {
        return connections.size();
    }

    public synchronized long getClassifiedCount() {
        long count = 0;
        for (ConnectionInfo connection : connections.values()) {
            if (!"Unknown".equals(connection.application)) count++;
        }
        return count;
    }

    public synchronized long getBlockedCount() {
        long count = 0;
        for (ConnectionInfo connection : connections.values()) if (connection.blocked) count++;
        return count;
    }

    public int getWorkerId() { return workerId; }

    private void removeOldestConnection() {
        Map.Entry<FiveTuple, ConnectionInfo> oldest = null;
        for (Map.Entry<FiveTuple, ConnectionInfo> entry : connections.entrySet()) {
            if (oldest == null || entry.getValue().lastSeen.isBefore(oldest.getValue().lastSeen)) {
                oldest = entry;
            }
        }
        if (oldest != null) connections.remove(oldest.getKey());
    }
}
