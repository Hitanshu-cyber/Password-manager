import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Arrays;
import javax.crypto.Mac;
import java.security.Key;
import java.io.UnsupportedEncodingException;

public class CryptoManager {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH_BIT = 256;

    public static class EncryptedData {
        public byte[] encryptedBytes;
        public byte[] iv;
        public byte[] authTag; // GCM mode handles tag within the encrypted bytes usually, but we'll separate
                               // for clarity if needed or just store raw output.
                               // Java's GCM implementation appends the tag to the ciphertext.
                               // We'll store IV and Ciphertext (which includes tag).

        public EncryptedData(byte[] encryptedBytes, byte[] iv, byte[] authTag) {
            this.encryptedBytes = encryptedBytes;
            this.iv = iv;
            this.authTag = authTag;
        }

        // Helper for when tag is embedded (standard Java GCM)
        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.encryptedBytes = ciphertext;
            this.iv = iv;
            this.authTag = null; // Tag is part of ciphertext
        }
    }

    public SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH_BIT);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] secret = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(secret, "AES");
    }

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTE];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public byte[] hashMasterPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Just reusing deriveKey logic to get a hash for storage verification
        return deriveKey(password, salt).getEncoded();
    }

    public EncryptedData encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return new EncryptedData(ciphertext, iv);
    }

    public String decrypt(EncryptedData data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, data.iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plaintext = cipher.doFinal(data.encryptedBytes);
        return new String(plaintext, "UTF-8");
    }

    public boolean verifyMasterPassword(String input, byte[] storedHash, byte[] salt) {
        try {
            SecretKey key = deriveKey(input, salt);
            return Arrays.equals(key.getEncoded(), storedHash);
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public SecretKey generateRandomKey() {
        byte[] key = new byte[KEY_LENGTH_BIT / 8];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    public EncryptedData wrapKey(SecretKey keyToWrap, SecretKey kek) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = generateIV();
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.WRAP_MODE, kek, spec);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        return new EncryptedData(wrappedKey, iv);
    }

    public SecretKey unwrapKey(EncryptedData wrappedData, SecretKey kek) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, wrappedData.iv);
        cipher.init(Cipher.UNWRAP_MODE, kek, spec);
        return (SecretKey) cipher.unwrap(wrappedData.encryptedBytes, "AES", Cipher.SECRET_KEY);
    }

    public byte[] generateHMAC(byte[] data, SecretKey key) throws Exception {
        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        sha256HMAC.init(key);
        return sha256HMAC.doFinal(data);
    }

    public boolean verifyHMAC(byte[] data, byte[] hmac, SecretKey key) throws Exception {
        byte[] calculated = generateHMAC(data, key);
        return Arrays.equals(calculated, hmac);
    }
}
