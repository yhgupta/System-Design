import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

// ═══════════════════════════════════════════════════════════════════
//  Rate Limiter — All Four Strategies
//  Interface + Token Bucket + Sliding Window Log +
//  Fixed Window Counter + Leaky Bucket
// ═══════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────
// Common Interface
// ─────────────────────────────────────────────────────────────────
interface RateLimiter {
    /**
     * @return true if the request is allowed, false if throttled (429)
     */
    boolean allow();

    /**
     * @return approximate time in millis until a request will be accepted
     */
    long retryAfterMillis();
}


// ═══════════════════════════════════════════════════════════════════
//  1. TOKEN BUCKET
//  Complexity: O(1) time, O(1) space per user
//  Allows burst up to capacity, then throttles to refill rate.
// ═══════════════════════════════════════════════════════════════════
class TokenBucketRateLimiter implements RateLimiter {

    private final int    capacity;      // max tokens in bucket
    private final double refillRate;    // tokens added per second
    private final int    tokensPerReq;  // tokens consumed per request

    private double       tokens;        // current token count
    private long         lastRefillNs;  // last refill timestamp (nanos)

    private final ReentrantLock lock = new ReentrantLock();

    /**
     * @param capacity     max burst size (bucket depth)
     * @param refillRate   tokens per second to add
     * @param tokensPerReq cost in tokens per request
     */
    public TokenBucketRateLimiter(int capacity, double refillRate, int tokensPerReq) {
        this.capacity     = capacity;
        this.refillRate   = refillRate;
        this.tokensPerReq = tokensPerReq;
        this.tokens       = capacity;           // start full
        this.lastRefillNs = System.nanoTime();
    }

    /** Convenience constructor: 1 token per request */
    public TokenBucketRateLimiter(int capacity, double refillRate) {
        this(capacity, refillRate, 1);
    }

    // Recompute tokens based on elapsed time — called under lock
    private void refill() {
        long now       = System.nanoTime();
        double elapsed = (now - lastRefillNs) / 1_000_000_000.0; // seconds
        tokens         = Math.min(capacity, tokens + elapsed * refillRate);
        lastRefillNs   = now;
    }

    @Override
    public boolean allow() {
        lock.lock();
        try {
            refill();
            if (tokens >= tokensPerReq) {
                tokens -= tokensPerReq;
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long retryAfterMillis() {
        lock.lock();
        try {
            refill();
            double deficit = tokensPerReq - tokens;
            if (deficit <= 0) return 0;
            return (long) Math.ceil((deficit / refillRate) * 1000);
        } finally {
            lock.unlock();
        }
    }

    public double getTokens() {
        lock.lock();
        try { refill(); return tokens; }
        finally { lock.unlock(); }
    }
}


// ═══════════════════════════════════════════════════════════════════
//  2. SLIDING WINDOW LOG
//  Complexity: O(log n) time (sorted set), O(n) space per user
//  Most accurate — no boundary burst problem.
// ═══════════════════════════════════════════════════════════════════
class SlidingWindowLogRateLimiter implements RateLimiter {

    private final int  limit;       // max requests per window
    private final long windowMs;    // window size in milliseconds

    // Sorted queue of request timestamps (oldest first)
    private final ArrayDeque<Long> timestamps = new ArrayDeque<>();
    private final ReentrantLock    lock        = new ReentrantLock();

    public SlidingWindowLogRateLimiter(int limit, long windowMs) {
        this.limit    = limit;
        this.windowMs = windowMs;
    }

    // Remove timestamps that have fallen outside the current window
    private void evictExpired(long now) {
        long cutoff = now - windowMs;
        while (!timestamps.isEmpty() && timestamps.peekFirst() <= cutoff) {
            timestamps.pollFirst();
        }
    }

    @Override
    public boolean allow() {
        lock.lock();
        try {
            long now = System.currentTimeMillis();
            evictExpired(now);
            if (timestamps.size() < limit) {
                timestamps.addLast(now);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long retryAfterMillis() {
        lock.lock();
        try {
            long now = System.currentTimeMillis();
            evictExpired(now);
            if (timestamps.size() < limit) return 0;
            // Oldest timestamp + window = when the next slot opens
            long oldestExpiry = timestamps.peekFirst() + windowMs;
            return Math.max(0, oldestExpiry - now);
        } finally {
            lock.unlock();
        }
    }

    public int getActiveCount() {
        lock.lock();
        try {
            evictExpired(System.currentTimeMillis());
            return timestamps.size();
        } finally {
            lock.unlock();
        }
    }
}


// ═══════════════════════════════════════════════════════════════════
//  3. FIXED WINDOW COUNTER
//  Complexity: O(1) time, O(1) space per user
//  Simplest — but has boundary burst problem (2× limit possible).
// ═══════════════════════════════════════════════════════════════════
class FixedWindowRateLimiter implements RateLimiter {

    private final int  limit;       // max requests per window
    private final long windowMs;    // window duration in milliseconds

    private final AtomicInteger count        = new AtomicInteger(0);
    private volatile long        windowStart  = System.currentTimeMillis();

    private final ReentrantLock lock = new ReentrantLock();

    public FixedWindowRateLimiter(int limit, long windowMs) {
        this.limit    = limit;
        this.windowMs = windowMs;
    }

    // Roll over to a new window if the current one has expired
    private void maybeReset(long now) {
        if (now - windowStart >= windowMs) {
            count.set(0);
            windowStart = now;
        }
    }

    @Override
    public boolean allow() {
        lock.lock();
        try {
            long now = System.currentTimeMillis();
            maybeReset(now);
            if (count.get() < limit) {
                count.incrementAndGet();
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long retryAfterMillis() {
        long now = System.currentTimeMillis();
        if (count.get() < limit) return 0;
        return Math.max(0, (windowStart + windowMs) - now);
    }

    public int getCount()    { return count.get(); }
    public int getRemaining() { return Math.max(0, limit - count.get()); }
}


// ═══════════════════════════════════════════════════════════════════
//  4. LEAKY BUCKET
//  Complexity: O(1) enqueue, O(q) space (queue depth)
//  Produces perfectly smooth output — bursts are queued or dropped.
// ═══════════════════════════════════════════════════════════════════
class LeakyBucketRateLimiter implements RateLimiter {

    private final int      capacity;     // max queue depth
    private final long     leakIntervalMs; // ms between each processed request

    private final Queue<Runnable>    queue    = new LinkedList<>();
    private final ReentrantLock      lock     = new ReentrantLock();
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "leaky-bucket-drain");
                t.setDaemon(true);
                return t;
            });

    private final AtomicLong processedCount = new AtomicLong(0);
    private final AtomicLong droppedCount   = new AtomicLong(0);

    /**
     * @param capacity   max requests that can queue up
     * @param leakRateHz requests processed per second
     */
    public LeakyBucketRateLimiter(int capacity, double leakRateHz) {
        this.capacity      = capacity;
        this.leakIntervalMs = (long) (1000.0 / leakRateHz);

        scheduler.scheduleAtFixedRate(this::leak, 0, leakIntervalMs, TimeUnit.MILLISECONDS);
    }

    // Drain one item from the queue — called by the scheduler thread
    private void leak() {
        lock.lock();
        try {
            Runnable task = queue.poll();
            if (task != null) {
                processedCount.incrementAndGet();
                task.run();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Enqueue a request for processing.
     * @param task the work to execute when the request drains through
     * @return true if accepted into queue, false if dropped (queue full)
     */
    public boolean enqueue(Runnable task) {
        lock.lock();
        try {
            if (queue.size() < capacity) {
                queue.offer(task);
                return true;
            }
            droppedCount.incrementAndGet();
            return false;
        } finally {
            lock.unlock();
        }
    }

    /** allow() with no-op task — use enqueue(Runnable) for real work */
    @Override
    public boolean allow() {
        return enqueue(() -> {});
    }

    @Override
    public long retryAfterMillis() {
        lock.lock();
        try {
            int depth = queue.size();
            return depth >= capacity ? leakIntervalMs : 0;
        } finally {
            lock.unlock();
        }
    }

    public int  getQueueDepth()    { return queue.size(); }
    public long getProcessedCount(){ return processedCount.get(); }
    public long getDroppedCount()  { return droppedCount.get(); }

    public void shutdown() { scheduler.shutdown(); }
}


// ═══════════════════════════════════════════════════════════════════
//  Per-User / Per-Key Registry
//  Wraps any RateLimiter factory to provide per-client limiting.
// ═══════════════════════════════════════════════════════════════════
class RateLimiterRegistry<T extends RateLimiter> {

    private final ConcurrentHashMap<String, T> limiters = new ConcurrentHashMap<>();
    private final java.util.function.Supplier<T> factory;

    public RateLimiterRegistry(java.util.function.Supplier<T> factory) {
        this.factory = factory;
    }

    public T get(String clientId) {
        return limiters.computeIfAbsent(clientId, k -> factory.get());
    }

    public boolean allow(String clientId) {
        return get(clientId).allow();
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Demo / Main
// ═══════════════════════════════════════════════════════════════════
public class RateLimiter {

    static void printResult(String strategy, int req, boolean allowed, RateLimiter rl) {
        String status = allowed ? "✓ ALLOW" : "✗ DENY ";
        String retry  = allowed ? "" : "  (retry after " + rl.retryAfterMillis() + "ms)";
        System.out.printf("  [%s] req#%02d → %s%s%n", strategy, req, status, retry);
    }

    public static void main(String[] args) throws InterruptedException {

        System.out.println("\n══════════════════════════════════════════");
        System.out.println("  1. TOKEN BUCKET  (cap=5, refill=2/s)");
        System.out.println("══════════════════════════════════════════");
        {
            TokenBucketRateLimiter tb = new TokenBucketRateLimiter(5, 2.0);
            // Burst 7 requests immediately
            for (int i = 1; i <= 7; i++) {
                printResult("TokenBucket", i, tb.allow(), tb);
            }
            System.out.println("  ... waiting 1.5s for refill ...");
            Thread.sleep(1500);
            for (int i = 8; i <= 10; i++) {
                printResult("TokenBucket", i, tb.allow(), tb);
            }
        }

        System.out.println("\n══════════════════════════════════════════");
        System.out.println("  2. SLIDING WINDOW LOG  (limit=4, window=3s)");
        System.out.println("══════════════════════════════════════════");
        {
            SlidingWindowLogRateLimiter sw = new SlidingWindowLogRateLimiter(4, 3000);
            for (int i = 1; i <= 6; i++) {
                printResult("SlidingWindow", i, sw.allow(), sw);
            }
            System.out.println("  ... waiting 3s for window to slide ...");
            Thread.sleep(3100);
            for (int i = 7; i <= 9; i++) {
                printResult("SlidingWindow", i, sw.allow(), sw);
            }
        }

        System.out.println("\n══════════════════════════════════════════");
        System.out.println("  3. FIXED WINDOW COUNTER  (limit=4, window=3s)");
        System.out.println("══════════════════════════════════════════");
        {
            FixedWindowRateLimiter fw = new FixedWindowRateLimiter(4, 3000);
            for (int i = 1; i <= 6; i++) {
                printResult("FixedWindow", i, fw.allow(), fw);
            }
            System.out.println("  ... waiting 3s for window to reset ...");
            Thread.sleep(3100);
            for (int i = 7; i <= 9; i++) {
                printResult("FixedWindow", i, fw.allow(), fw);
            }
        }

        System.out.println("\n══════════════════════════════════════════");
        System.out.println("  4. LEAKY BUCKET  (capacity=3, rate=1/s)");
        System.out.println("══════════════════════════════════════════");
        {
            LeakyBucketRateLimiter lb = new LeakyBucketRateLimiter(3, 1.0);
            // Burst 6 requests — 3 queued, 3 dropped
            for (int i = 1; i <= 6; i++) {
                boolean ok = lb.enqueue(() -> System.out.println("  [LeakyBucket] → processing task"));
                printResult("LeakyBucket ", i, ok, lb);
            }
            System.out.println("  ... waiting 4s for queue to drain ...");
            Thread.sleep(4000);
            System.out.printf("  Processed: %d | Dropped: %d | Queue: %d%n",
                    lb.getProcessedCount(), lb.getDroppedCount(), lb.getQueueDepth());
            lb.shutdown();
        }

        System.out.println("\n══════════════════════════════════════════");
        System.out.println("  5. PER-USER REGISTRY  (TokenBucket)");
        System.out.println("══════════════════════════════════════════");
        {
            RateLimiterRegistry<TokenBucketRateLimiter> registry =
                new RateLimiterRegistry<>(() -> new TokenBucketRateLimiter(3, 1.0));

            String[] users = {"alice", "bob", "alice", "alice", "alice", "bob"};
            for (int i = 0; i < users.length; i++) {
                String user = users[i];
                boolean ok  = registry.allow(user);
                System.out.printf("  req#%d user=%-5s → %s%n",
                        i + 1, user, ok ? "✓ ALLOW" : "✗ DENY");
            }
        }

        System.out.println();
    }
}
