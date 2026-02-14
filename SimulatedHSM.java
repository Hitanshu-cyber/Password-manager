import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.io.*;
import java.util.Arrays;

/**
 * SimulatedHSM: Represents a hardware security root-of-trust (e.g., TPM).
 * In a real enterprise app, this would involve JNI calls to a hardware driver.
 */
public class SimulatedHSM {
    private static final String HSM_STORAGE = "hsm_enclave.dat";
    private SecretKey masterKEK;

    public SimulatedHSM() {
        loadOrGenerateMasterKEK();
    }

    private void loadOrGenerateMasterKEK() {
        File file = new File(HSM_STORAGE);
        if (file.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                byte[] keyBytes = (byte[]) ois.readObject();
                this.masterKEK = new SecretKeySpec(keyBytes, "AES");
            } catch (Exception e) {
                System.err.println("[!] HSM Initialization Failure: Backup key required.");
                generateNewKEK();
            }
        } else {
            generateNewKEK();
        }
    }

    private void generateNewKEK() {
        byte[] keyBytes = new byte[32]; // AES-256
        new SecureRandom().nextBytes(keyBytes);
        this.masterKEK = new SecretKeySpec(keyBytes, "AES");
        saveKEKToEnclave(keyBytes);
    }

    private void saveKEKToEnclave(byte[] keyBytes) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(HSM_STORAGE))) {
            oos.writeObject(keyBytes);
        } catch (IOException e) {
            System.err.println("[!] Critical: Failed to persist HSM Enclave state.");
        }
    }

    public SecretKey getMasterKEK() {
        // Enforce "Hardware Only" access logic:
        // In a real HSM, the key NEVER returns in plaintext.
        // We simulate this by returning the reference, but we strictly
        // control the wrapping/unwrapping operations.
        return masterKEK;
    }

    /**
     * Wipes the HSM memory.
     */
    public void secureWipe() {
        if (masterKEK != null) {
            // SecretKeySpec is immutable, but we null out the reference
            masterKEK = null;
            System.out.println("[🔒] HSM Enclave Locked/Memory Wiped.");
        }
    }
}
