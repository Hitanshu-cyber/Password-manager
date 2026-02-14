import java.io.*;
import java.util.BitSet;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BloomFilter implements Serializable {
    private static final long serialVersionUID = 1L;
    private BitSet bitSet;
    private int bitSetSize;
    private int numHashFunctions;
    private int count;

    public BloomFilter(int expectedElements, double falsePositiveRate) {
        this.bitSetSize = (int) (-expectedElements * Math.log(falsePositiveRate) / (Math.log(2) * Math.log(2)));
        this.numHashFunctions = (int) (Math.log(2) * bitSetSize / expectedElements);
        this.bitSet = new BitSet(bitSetSize);
        this.count = 0;
    }

    public void add(String data) {
        int[] hashes = createHashes(data, numHashFunctions);
        for (int hash : hashes) {
            bitSet.set(Math.abs(hash % bitSetSize));
        }
        count++;
    }

    public boolean mightContain(String data) {
        int[] hashes = createHashes(data, numHashFunctions);
        for (int hash : hashes) {
            if (!bitSet.get(Math.abs(hash % bitSetSize))) {
                return false;
            }
        }
        return true;
    }

    private int[] createHashes(String data, int numHashes) {
        int[] result = new int[numHashes];
        int k = 0;
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] bytes = digest.digest();

            // Generate multiple hash values from MD5 (simplified approach)
            // Properly, we might want MurmurHash3, but standard Java lib makes this easier
            // for zero-dep
            for (int i = 0; i < numHashes; i++) {
                int h = 0;
                // Use different parts of the byte array for each hash run
                // Re-hashing if we run out of bytes
                if (k > bytes.length - 4) {
                    digest.update(bytes); // Reseed
                    bytes = digest.digest();
                    k = 0;
                }

                h = ((bytes[k] & 0xFF) << 24) |
                        ((bytes[k + 1] & 0xFF) << 16) |
                        ((bytes[k + 2] & 0xFF) << 8) |
                        ((bytes[k + 3] & 0xFF));
                result[i] = h;
                k += 4;
            }
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple string hash code variants
            for (int i = 0; i < numHashes; i++) {
                result[i] = data.hashCode() + i * 31;
            }
        }
        return result;
    }

    public void save(String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(this);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static BloomFilter load(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            return (BloomFilter) ois.readObject();
        } catch (Exception e) {
            return null;
        }
    }
}
