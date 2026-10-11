package pipeline;

import model.PacketJob;
import rules.RuleManager;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Distributes incoming packets among fast-path workers. */
public class LoadBalancer {
    private final int id;
    private final BlockingPacketQueue<PacketJob> inputQueue;
    private final List<FastPath> workers = new ArrayList<>();
    private Thread dispatchThread;
    private long receivedPackets;
    private long dispatchedPackets;

    public LoadBalancer(int id, int firstWorkerId, int workerCount, RuleManager rules,
                        FastPath.PacketHandler outputHandler, int queueSize) {
        this.id = id;
        this.inputQueue = new BlockingPacketQueue<>(queueSize);
        for (int i = 0; i < workerCount; i++) {
            workers.add(new FastPath(firstWorkerId + i, rules, outputHandler, queueSize));
        }
    }

    public void start() {
        for (FastPath worker : workers) worker.start();
        dispatchThread = new Thread(this::dispatchPackets, "dpi-load-balancer-" + id);
        dispatchThread.start();
    }

    public boolean enqueue(PacketJob packet) {
        return inputQueue.push(packet);
    }

    /** Stop accepting packets, drain the queue, and then stop all workers. */
    public void stopAndDrain() {
        inputQueue.shutdown();
        join(dispatchThread);
    }

    private void dispatchPackets() {
        while (true) {
            PacketJob packet = inputQueue.popWithTimeout(Duration.ofMillis(100));
            if (packet == null) {
                if (inputQueue.isShutdown() && inputQueue.isEmpty()) break;
                continue;
            }

            receivedPackets++;
            // Mix in the LB id to avoid sending every packet to the same worker
            // when the LB count and worker count happen to be equal.
            long hash = packet.tuple.flowHash() ^ (0x9E3779B97F4A7C15L * (id + 1));
            int workerIndex = Math.floorMod(hash, workers.size());
            if (workers.get(workerIndex).enqueue(packet)) dispatchedPackets++;
        }

        for (FastPath worker : workers) worker.stopAndDrain();
    }

    public int getId() { return id; }
    public List<FastPath> getWorkers() { return new ArrayList<>(workers); }
    public synchronized long getReceivedPackets() { return receivedPackets; }
    public synchronized long getDispatchedPackets() { return dispatchedPackets; }

    private static void join(Thread thread) {
        if (thread == null) return;
        try {
            thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
