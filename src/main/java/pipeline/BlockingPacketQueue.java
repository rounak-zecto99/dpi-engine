package pipeline;

import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/** A bounded queue that lets one thread pass packets to another thread. */
public class BlockingPacketQueue<T> {
    private final ArrayBlockingQueue<T> queue;
    private volatile boolean shutdown = false;

    public BlockingPacketQueue(int capacity) {
        queue = new ArrayBlockingQueue<>(Math.max(1, capacity));
    }

    /** Waits for free space rather than silently losing a packet. */
    public boolean push(T item) {
        while (!shutdown) {
            try {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    public T popWithTimeout(Duration timeout) {
        try {
            return queue.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public void shutdown() { shutdown = true; }
    public boolean isShutdown() { return shutdown; }
    public boolean isEmpty() { return queue.isEmpty(); }
    public int size() { return queue.size(); }
}
