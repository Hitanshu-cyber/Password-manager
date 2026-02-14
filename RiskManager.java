import java.util.HashMap;
import java.util.Map;

/**
 * RiskManager: Monitors system activity and assigns risk scores.
 * Triggers autonomous defense mechanisms based on threat intensity.
 */
public class RiskManager {
    private static final int CRITICAL_RISK_THRESHOLD = 70;
    private static final int LOCKOUT_THRESHOLD = 5; // Failed attempts per user

    private Map<String, Integer> failedAttempts = new HashMap<>();
    private Map<String, Long> lastAccessTime = new HashMap<>();
    private int globalRiskScore = 0;

    public synchronized void recordFailedAttempt(String username) {
        failedAttempts.put(username, failedAttempts.getOrDefault(username, 0) + 1);
        globalRiskScore += 15; // Increase global risk for any failure
        System.out.println("[🛡️] Risk Escalated: Global Score " + globalRiskScore);
    }

    public synchronized void recordSuccessfulLogin(String username) {
        failedAttempts.put(username, 0); // Reset on success
        if (globalRiskScore > 0) {
            globalRiskScore -= 5; // Gradual decay
        }
    }

    public int getRiskScore() {
        return globalRiskScore;
    }

    public boolean isHighRisk() {
        return globalRiskScore >= CRITICAL_RISK_THRESHOLD;
    }

    public boolean shouldLockout(String username) {
        return failedAttempts.getOrDefault(username, 0) >= LOCKOUT_THRESHOLD;
    }

    public long calculateRateLimitDelay(String username) {
        int attempts = failedAttempts.getOrDefault(username, 0);
        if (attempts == 0)
            return 0;
        // Exponential backoff: 2^attempts * 500ms
        return (long) Math.pow(2, attempts) * 500;
    }

    public void decayRisk() {
        if (globalRiskScore > 0) {
            globalRiskScore -= 2; // Passive decay
        }
    }

    public synchronized void resetRisk() {
        globalRiskScore = 0;
        failedAttempts.clear();
        System.out.println("[🛡️] System Risk Level Reset.");
    }

    /**
     * Cisco-Grade Thread Watchdog:
     * Detects anomalous thread spikes which may indicate hidden attacker activity.
     */
    public boolean isThreadAnomaly() {
        int activeThreads = Thread.activeCount();
        // For an individual user session, > 10 threads is highly suspicious
        // given our lightweight non-GUI architecture.
        if (activeThreads > 15) {
            globalRiskScore += 50; // Massively spike risk
            return true;
        }
        return false;
    }
}
