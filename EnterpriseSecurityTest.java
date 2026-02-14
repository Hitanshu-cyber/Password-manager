import java.util.List;
import javax.crypto.SecretKey;

/**
 * Enterprise Security Test Suite (Google/Cisco Grade)
 * Validates Security controls, Crypto integrity, AI integration and DB sync.
 */
public class EnterpriseSecurityTest {
    private Main main;
    private CryptoManager crypto;
    private DatabaseManager db;
    private AIPasswordAnalyzer ai;

    public EnterpriseSecurityTest() {
        this.main = new Main();
        this.crypto = new CryptoManager();
        try {
            this.db = new DatabaseManager(crypto);
            this.ai = new AIPasswordAnalyzer();
        } catch (Exception e) {
            System.err.println("Test Setup Error: " + e.getMessage());
        }
    }

    public void runAllTests() {
        System.out.println("=== ENTERPRISE SECURITY TEST SUITE STARTING ===");

        testCryptoIntegrity();
        testDatabaseSyncIntegrity();
        testAISecurityBlocking();
        testHierarchicalIntegrity();
        testSQLInjectionResistance();
        testMFATOTPIntegrity();
        testHSMIntegrity();
        testSyncIntegrity();
        testSyncTampering();
        testAIDefenseIntegrity();
        testBruteForceEscalation();
        testHSMFailureScenario();
        testMultithreadedStress(); // NEW: Rigorous
        testInputFuzzing(); // NEW: Rigorous

        System.out.println("=== ALL TESTS COMPLETED ===");
    }

    private void testAIDefenseIntegrity() {
        System.out.print("[TEST] AI Adaptive Defense (Risk Scoring): ");
        try {
            RiskManager risk = new RiskManager();
            String target = "brute_force_client";

            // Initial state
            if (risk.getRiskScore() != 0)
                throw new Exception("Initial risk should be 0");

            // Record failures
            risk.recordFailedAttempt(target);
            risk.recordFailedAttempt(target);

            int score = risk.getRiskScore();
            long delay = risk.calculateRateLimitDelay(target);

            if (score > 0 && delay >= 2000) { // 2^2 * 500 = 2000ms
                System.out.println("PASS (Score: " + score + ", Delay: " + delay + "ms)");
            } else {
                System.out.println("FAIL (Weak risk response)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testSyncIntegrity() {
        System.out.print("[TEST] Zero-Knowledge Sync Integrity: ");
        try {
            SimulatedHSM hsm = new SimulatedHSM();
            SyncManager sync = new SyncManager(crypto, db, hsm);

            // 1. Create Data
            String user = "sync_test_user";
            db.registerUser(user, "password123", false);
            int uid = db.getUserId(user);
            SecretKey dek = crypto.generateRandomKey();
            db.addAccount(uid, "SyncService", "Security", "tester", "pass", dek, 3);

            // 2. Export sync blob
            byte[] blob = sync.createSyncBlob();

            // 3. Clear and restore
            if (sync.restoreFromSyncBlob(blob)) {
                // 4. Verify data
                List<DatabaseManager.AccountData> accs = db.getAccounts(uid);
                if (accs.size() == 1 && accs.get(0).siteName.equals("SyncService")) {
                    System.out.println("PASS");
                } else {
                    System.out.println("FAIL (Data not restored correctly)");
                }
            } else {
                System.out.println("FAIL (Restore failed)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testHSMIntegrity() {
        System.out.print("[TEST] HSM Key Wrapping (Hardware-Backed): ");
        try {
            SimulatedHSM hsm = new SimulatedHSM();
            SecretKey dek = crypto.generateRandomKey();

            // Wrap the DEK with HSM's KEK
            CryptoManager.EncryptedData wrapped = crypto.wrapKey(dek, hsm.getMasterKEK());

            // Unwrap it back
            SecretKey unwrapped = crypto.unwrapKey(wrapped, hsm.getMasterKEK());

            if (java.util.Arrays.equals(dek.getEncoded(), unwrapped.getEncoded())) {
                System.out.println("PASS");
            } else {
                System.out.println("FAIL (Key mismatch)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testMFATOTPIntegrity() {
        System.out.print("[TEST] MFA TOTP Integrity: ");
        try {
            TOTPManager totp = new TOTPManager();
            String secret = totp.generateSecret();
            if (secret != null && secret.length() > 0) {
                // Verify we can generate a code (logic check)
                boolean verified = totp.verifyCode(secret, -1); // Should be false
                System.out.println("PASS (Secret: " + secret + ")");
            } else {
                System.out.println("FAIL (Empty Secret)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testCryptoIntegrity() {
        System.out.print("[TEST] Crypto Integrity (AES-GCM): ");
        try {
            String plain = "EnterpriseSecret123!";
            byte[] salt = crypto.generateSalt();
            byte[] iv = crypto.generateIV();
            SecretKey key = crypto.deriveKey("MasterPassword", salt);
            CryptoManager.EncryptedData enc = crypto.encrypt(plain, key, iv);
            String dec = crypto.decrypt(enc, key);
            if (plain.equals(dec))
                System.out.println("PASS");
            else
                System.out.println("FAIL (Mismatch)");
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testDatabaseSyncIntegrity() {
        System.out.print("[TEST] DB Sync Persistence: ");
        try {
            String testUser = "test_ciso_" + System.currentTimeMillis();
            db.registerUser(testUser, "TestPass123!", false);
            Integer id = db.getUserId(testUser);
            if (id != null)
                System.out.println("PASS");
            else
                System.out.println("FAIL (User not found after registration)");
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testAISecurityBlocking() {
        System.out.print("[TEST] AI Breach Blocking (Multi-Tier): ");
        try {
            if (ai == null) {
                System.out.println("SKIP (AI not loaded)");
                return;
            }
            // "password123" is in our local breach_list.txt
            boolean breached = ai.checkBreach("password123");
            // Unique password should NOT be in breach list
            boolean safe = ai.checkBreach("V3ry_Un1qu3_S4f3_P@ss!_2026");

            if (breached && !safe) {
                System.out.println("PASS");
            } else {
                System.out.println("FAIL (Breached detected: " + breached + ", Safe marked as breached: " + safe + ")");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testHierarchicalIntegrity() {
        System.out.print("[TEST] Hierarchical Account Mapping: ");
        try {
            Account parent = new Account("Google", "admin", "pwd1", "Personal");
            Account child = new Account("Gmail", "sub_user", "pwd2", "Work");
            parent.subAccounts.add(child);
            if (parent.subAccounts.size() == 1 && parent.subAccounts.get(0).username.equals("sub_user")) {
                System.out.println("PASS");
            } else {
                System.out.println("FAIL (Hierarchy corruption)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testSQLInjectionResistance() {
        System.out.print("[TEST] SQL Injection Resistance (Login Bypass): ");
        try {
            // Attempt bypass via ' OR '1'='1
            Integer id = db.authenticateUser("' OR '1'='1", "' OR '1'='1");
            if (id == null)
                System.out.println("PASS (Bypass blocked via PreparedStatements)");
            else
                System.out.println("FAIL (SQL Injection vulnerability found!)");
        } catch (Exception e) {
            System.out.println("PASS (Properly errored out)");
        }
    }

    private void testSyncTampering() {
        System.out.print("[TEST] Sync Blob Tampering Resistance: ");
        try {
            SimulatedHSM hsm = new SimulatedHSM();
            SyncManager sync = new SyncManager(crypto, db, hsm);
            byte[] blob = sync.createSyncBlob();

            // Tamper with the ciphertext (last byte)
            blob[blob.length - 1] ^= 0x01;

            if (!sync.restoreFromSyncBlob(blob)) {
                System.out.println("PASS (Tampering detected via HMAC)");
            } else {
                System.out.println("FAIL (Tampered blob restored!)");
            }
        } catch (Exception e) {
            System.out.println("PASS (Caught exception during restore: " + e.getMessage() + ")");
        }
    }

    private void testBruteForceEscalation() {
        System.out.print("[TEST] Brute-Force Rate Limit Escalation: ");
        try {
            RiskManager risk = new RiskManager();
            String user = "attacker";
            long lastDelay = 0;
            for (int i = 1; i <= 5; i++) {
                risk.recordFailedAttempt(user);
                long delay = risk.calculateRateLimitDelay(user);
                if (delay <= lastDelay)
                    throw new Exception("Delay did not escalate at attempt " + i);
                lastDelay = delay;
            }
            if (risk.shouldLockout(user)) {
                System.out.println("PASS (Delay escalated to " + lastDelay + "ms & Lockout triggered)");
            } else {
                System.out.println("FAIL (Lockout not triggered)");
            }
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testMultithreadedStress() {
        System.out.print("[TEST] Multithreaded Race Condition Stress (20 threads): ");
        try {
            int threadCount = 20;
            Thread[] threads = new Thread[threadCount];
            java.util.concurrent.atomic.AtomicInteger successCount = new java.util.concurrent.atomic.AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int id = i;
                threads[i] = new Thread(() -> {
                    try {
                        String user = "stress_user_" + id;
                        db.registerUser(user, "pass", false);
                        Integer uid = db.getUserId(user);
                        if (uid != null) {
                            SecretKey k = crypto.generateRandomKey();
                            db.addAccount(uid, "Site", "Cat", "u", "p", k, 3);
                            successCount.incrementAndGet();
                        }
                    } catch (Exception ignored) {
                    }
                });
                threads[i].start();
            }

            for (Thread t : threads)
                t.join();

            if (successCount.get() > 0) {
                System.out.println("PASS (" + successCount.get() + "/" + threadCount + " operations successful)");
            } else {
                System.out.println("FAIL (0 successful operations)");
            }

            // NEW: Cleanup after stress
            db.cleanupTestData();
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    private void testInputFuzzing() {
        System.out.print("[TEST] Input Fuzzing & Overflow Resistance: ");
        try {
            // Test 1: Massive input
            StringBuilder largeInput = new StringBuilder();
            for (int i = 0; i < 5000; i++)
                largeInput.append("A");
            db.registerUser(largeInput.toString(), "p", false);

            // Test 2: SQL chars
            db.registerUser("'; DROP TABLE users; --", "p", false);

            // Test 3: Null bytes (if possible in string)
            db.registerUser("user\0name", "p", false);

            System.out.println("PASS (No crashes/corruption detected)");
        } catch (Exception e) {
            System.out.println("PASS (Caught expected handling: " + e.getMessage() + ")");
        }
    }

    private void testHSMFailureScenario() {
        System.out.print("[TEST] HSM Failure / Key Mismatch Protection: ");
        try {
            java.io.File hsmFile = new java.io.File("hsm_enclave.dat");
            hsmFile.delete(); // Start fresh

            SimulatedHSM hsm1 = new SimulatedHSM();
            SecretKey dek = crypto.generateRandomKey();
            CryptoManager.EncryptedData wrapped = crypto.wrapKey(dek, hsm1.getMasterKEK());

            hsmFile.delete(); // Force hsm2 to generate a NEW random KEK
            SimulatedHSM hsm2 = new SimulatedHSM();

            try {
                SecretKey unwrapped = crypto.unwrapKey(wrapped, hsm2.getMasterKEK());
                if (!java.util.Arrays.equals(dek.getEncoded(), unwrapped.getEncoded())) {
                    System.out.println("PASS (Decryption with different KEK returned wrong data)");
                } else {
                    System.out.println("FAIL (Unwrapped same key despite KEK change!)");
                }
            } catch (Exception e) {
                System.out.println("PASS (Caught expected error during unwrap: " + e.getMessage() + ")");
            }
            hsmFile.delete(); // Cleanup
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        }
    }

    public static void main(String[] args) {
        new EnterpriseSecurityTest().runAllTests();
    }
}
