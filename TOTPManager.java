import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TOTPManager: Handles Time-based One-Time Password (RFC 6238)
 */
public class TOTPManager {
    private static final int DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    private static final String HMAC_ALGO = "HmacSHA1";

    public String generateSecret() {
        byte[] buffer = new byte[10];
        new SecureRandom().nextBytes(buffer);
        return Base32.encode(buffer);
    }

    public boolean verifyCode(String secret, int code) {
        long currentInterval = System.currentTimeMillis() / 1000 / TIME_STEP_SECONDS;
        // Check current, previous, and next intervals for clock drift
        for (int i = -1; i <= 1; i++) {
            if (generateCode(secret, currentInterval + i) == code) {
                return true;
            }
        }
        return false;
    }

    private int generateCode(String secret, long interval) {
        try {
            byte[] key = Base32.decode(secret);
            byte[] data = ByteBuffer.allocate(8).putLong(interval).array();

            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);

            return binary % (int) Math.pow(10, DIGITS);
        } catch (GeneralSecurityException e) {
            return -1;
        }
    }

    /**
     * Minimal Base32 Implementation for Authenticator compatibility
     */
    private static class Base32 {
        private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static String encode(byte[] data) {
            StringBuilder sb = new StringBuilder();
            int bitBuffer = 0;
            int bitCount = 0;
            for (byte b : data) {
                bitBuffer = (bitBuffer << 8) | (b & 0xFF);
                bitCount += 8;
                while (bitCount >= 5) {
                    sb.append(ALPHABET.charAt((bitBuffer >> (bitCount - 5)) & 0x1F));
                    bitCount -= 5;
                }
            }
            if (bitCount > 0) {
                sb.append(ALPHABET.charAt((bitBuffer << (5 - bitCount)) & 0x1F));
            }
            return sb.toString();
        }

        public static byte[] decode(String base32) {
            base32 = base32.toUpperCase().replaceAll("[^A-Z2-7]", "");
            byte[] out = new byte[base32.length() * 5 / 8];
            int bitBuffer = 0;
            int bitCount = 0;
            int outIndex = 0;
            for (char c : base32.toCharArray()) {
                bitBuffer = (bitBuffer << 5) | ALPHABET.indexOf(c);
                bitCount += 5;
                if (bitCount >= 8) {
                    out[outIndex++] = (byte) ((bitBuffer >> (bitCount - 8)) & 0xFF);
                    bitCount -= 8;
                }
            }
            return out;
        }
    }
}
