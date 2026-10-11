package connection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Gives the engine one place to find all workers' connection trackers. */
public class GlobalConnectionTable {
    private final Map<Integer, ConnectionTracker> trackers = new HashMap<>();

    public synchronized void registerTracker(int workerId, ConnectionTracker tracker) {
        trackers.put(workerId, tracker);
    }

    public synchronized List<ConnectionTracker> getTrackers() {
        return new ArrayList<>(trackers.values());
    }

    public synchronized int getActiveConnectionCount() {
        int total = 0;
        for (ConnectionTracker tracker : trackers.values()) total += tracker.getActiveCount();
        return total;
    }

    public synchronized long getClassifiedConnectionCount() {
        long total = 0;
        for (ConnectionTracker tracker : trackers.values()) total += tracker.getClassifiedCount();
        return total;
    }

    public synchronized long getBlockedConnectionCount() {
        long total = 0;
        for (ConnectionTracker tracker : trackers.values()) total += tracker.getBlockedCount();
        return total;
    }
}
