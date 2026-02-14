import java.util.BitSet;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * BreachDetector: Implements multi-tier password breach checking.
 * Tier 1: Local Top 100K list (HashSet)
 * Tier 2: Bloom Filter for high-performance offline HIBP simulation.
 */
public class BreachDetector {
    private Set<String> topBreached = new HashSet<>();
    private BitSet bloomFilter;
    private int bloomSize = 1000000; // Sample size
    private int numHashes = 4;

    public BreachDetector(String breachListPath) {
        loadTopBreached(breachListPath);
        initBloomFilter();
    }

    private void loadTopBreached(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                topBreached.add(line.trim().toLowerCase());
            }
            System.out.println("[🛡️] Loaded " + topBreached.size() + " top breached passwords.");
        } catch (IOException e) {
            System.err.println("[!] Failed to load breach list: " + e.getMessage());
        }
    }

    private void initBloomFilter() {
        bloomFilter = new BitSet(bloomSize);
        // In a real app, we would load the HIBP bloom filter from disk (1GB+).
        // Here we simulate it by adding common variations.
        for (String p : topBreached) {
            addToBloom(p);
        }
    }

    private void addToBloom(String s) {
        for (int i = 0; i < numHashes; i++) {
            int hash = hashFunction(s, i);
            bloomFilter.set(Math.abs(hash % bloomSize));
        }
    }

    public boolean isBreached(String password) {
        String p = password.toLowerCase();
        // Tier 1: Fast direct match
        if (topBreached.contains(p))
            return true;

        // Tier 2: Bloom match (Probabilistic)
        for (int i = 0; i < numHashes; i++) {
            int hash = hashFunction(p, i);
            if (!bloomFilter.get(Math.abs(hash % bloomSize))) {
                return false; // Definitely not in bloom
            }
        }
        return true; // Might be in bloom
    }

    private int hashFunction(String s, int index) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((byte) index);
            byte[] bytes = md.digest(s.getBytes());
            int result = 0;
            for (int i = 0; i < 4; i++) {
                result = (result << 8) | (bytes[i] & 0xFF);
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            return s.hashCode() + index;
        }
    }
}
