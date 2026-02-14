import java.io.*;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

/**
 * SyncManager: Handles Zero-Knowledge synchronization logic.
 * Packages DB state into encrypted, HMAC-protected blobs.
 */
public class SyncManager {
    private CryptoManager crypto;
    private DatabaseManager db;
    private SimulatedHSM hsm;

    public SyncManager(CryptoManager crypto, DatabaseManager db, SimulatedHSM hsm) {
        this.crypto = crypto;
        this.db = db;
        this.hsm = hsm;
    }

    public static class SyncPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        public List<DatabaseManager.FullUserData> users;

        public SyncPayload(List<DatabaseManager.FullUserData> users) {
            this.users = users;
        }
    }

    public byte[] createSyncBlob() throws Exception {
        List<DatabaseManager.FullUserData> allData = db.getFullUserSet();
        SyncPayload payload = new SyncPayload(allData);

        // Serialize payload
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(payload);
        oos.close();
        byte[] serialized = baos.toByteArray();

        // Encrypt with HSM KEK (Zero-Knowledge: Storage provider can't read it)
        byte[] iv = crypto.generateIV();
        CryptoManager.EncryptedData encrypted = crypto.encrypt(new String(serialized, "ISO-8859-1"), hsm.getMasterKEK(),
                iv);

        // Sign with HMAC
        byte[] signature = crypto.generateHMAC(encrypted.encryptedBytes, hsm.getMasterKEK());

        // Package: [IV length (4)][IV][HMAC (32)][Ciphertext]
        ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + signature.length + encrypted.encryptedBytes.length);
        buffer.putInt(iv.length);
        buffer.put(iv);
        buffer.put(signature);
        buffer.put(encrypted.encryptedBytes);

        return buffer.array();
    }

    public boolean restoreFromSyncBlob(byte[] blob) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(blob);
        int ivLen = buffer.getInt();
        byte[] iv = new byte[ivLen];
        buffer.get(iv);
        byte[] signature = new byte[32]; // HMAC-SHA256 is 32 bytes
        buffer.get(signature);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        // Verify HMAC
        if (!crypto.verifyHMAC(ciphertext, signature, hsm.getMasterKEK())) {
            System.err.println("[!] Sync Blob Integrity Check FAILED. Tampering detected.");
            return false;
        }

        // Decrypt
        CryptoManager.EncryptedData encData = new CryptoManager.EncryptedData(ciphertext, iv);
        String decryptedStr = crypto.decrypt(encData, hsm.getMasterKEK());
        byte[] serialized = decryptedStr.getBytes("ISO-8859-1");

        // Deserialize
        ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
        ObjectInputStream ois = new ObjectInputStream(bais);
        SyncPayload payload = (SyncPayload) ois.readObject();

        // Restore to Database
        db.restoreFullUserSet(payload.users);
        return true;
    }
}
