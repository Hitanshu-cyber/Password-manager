import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.IOException;

class Main {
    // Instance variables instead of static
    private Scanner scanner;
    private AdminUser admin;
    private DatabaseManager db;
    private CryptoManager crypto;
    private AIPasswordAnalyzer ai;
    private TOTPManager totp;
    private SimulatedHSM hsm = new SimulatedHSM(); // NEW: HSM hardware simulation
    private SyncManager sync; // NEW: Zero-Knowledge Sync Manager
    private RiskManager risk = new RiskManager(); // NEW: AI Risk Assessment Engine

    // Phase 9: Control Mode
    private boolean cyberResistanceMode = false;

    // Session management vars
    private long lastActivityTime = System.currentTimeMillis();
    private static final long SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

    // Constants can remain static
    public static final int MAX_LOGIN_ATTEMPTS = 3;

    // Constructor to initialize instance variables
    public Main() {
        this.scanner = new Scanner(System.in);
        this.admin = null;

        // NEW: Initialize crypto and database
        this.crypto = new CryptoManager();
        try {
            this.db = new DatabaseManager(crypto);
            System.out.println("[✓] Database initialized");
        } catch (Exception e) {
            System.out.println("[✗] Database initialization failed: " + e.getMessage());
            System.out.println("    App will run in memory-only mode");
            this.db = null;
        }

        // NEW: Initialize AI (optional - don't fail if unavailable)
        try {
            this.ai = new AIPasswordAnalyzer();
            System.out.println("[✓] AI features enabled");
        } catch (Exception e) {
            System.out.println("[ℹ] AI features disabled (model not found)");
            this.ai = null;
        }

        this.totp = new TOTPManager(); // Initialize TOTP
        if (this.db != null) {
            this.sync = new SyncManager(crypto, db, hsm);
        }
    }

    public static void main(String[] args) {
        Main mainInstance = new Main();
        mainInstance.run();
    }

    public void run() {
        System.out.println("=== PASSWORD MANAGEMENT SYSTEM (Enterprise Edition) ===");

        // --- PHASE 1: SYSTEM SETUP (ADMIN) ---
        System.out.println("\n--- SYSTEM INITIALIZATION ---");
        System.out.println("Register System Root (Master Admin).");
        // Strict Validation for Root
        String regUser = "";
        while (true) {
            regUser = getSecureInput("Set Root Username: ");
            if (isValidUsername(regUser))
                break;
            System.out.println("Invalid Username. No spaces allowed. Use alphanumerics, dots, underscores, hyphens.");
        }

        String regPass = "";
        while (true) {
            regPass = getSecureInput("Set Root Password: ");
            if (regPass.length() < 8) {
                System.out.println("Invalid Password. Minimum length 8 required for Root Admin.");
                continue;
            }
            if (containsSpace(regPass)) {
                System.out.println("Invalid Password. No spaces allowed.");
                continue;
            }

            // AI INTEGRATION: Breach Check and Markov Complexity
            if (ai != null) {
                if (ai.checkBreach(regPass)) {
                    System.out.println(
                            "[🛡️] CRITICAL: That password is found in breach databases! Choose something unique.");
                    showAISuggestions(regPass);
                    continue;
                }
                AIPasswordAnalyzer.AnalysisResult analysis = ai.analyzePassword(regPass);
                if (analysis.getStrengthLabel().equals("Weak")) {
                    System.out.println(
                            "[🛡️] REJECTED: AI Analysis indicates this password follows predictable patterns (Markov Check Failed).");
                    System.out.println("    Analysis: " + analysis.suggestion);
                    showAISuggestions(regPass);
                    continue;
                }
            }
            break;
        }

        admin = new AdminUser(regUser, regPass);

        // NEW: Register admin in database
        if (db != null) {
            try {
                // NEW: Generate and Wrap Key
                SecretKey dek = crypto.generateRandomKey();
                CryptoManager.EncryptedData wrapped = crypto.wrapKey(dek, hsm.getMasterKEK());

                if (db.registerUser(regUser, regPass, true, wrapped.encryptedBytes, wrapped.iv)) {
                    admin.userId = db.getUserId(regUser);
                    admin.mfaSecret = db.getMFASecret(admin.userId);
                    admin.salt = db.getUserSalt(regUser);
                    admin.encryptionKey = dek; // Key is now the unwrapped random DEK
                    System.out.println("[✓] Admin registered with HSM-Protected Key.");
                } else {
                    // User already exists (restart persistence), try to authenticate/load
                    System.out.println("[ℹ] Admin user already exists in DB. Authenticating...");
                    applyRateLimit(regUser); // NEW: Rate Limit
                    Integer uid = db.authenticateUser(regUser, regPass);
                    if (uid != null) {
                        risk.recordSuccessfulLogin(regUser);
                        admin.userId = uid;
                        admin.mfaSecret = db.getMFASecret(uid);
                        if (!checkMFAChallenge(admin)) {
                            System.out.println("Access Denied: MFA Failure.");
                            return;
                        }
                        // NEW: Unwrap Key
                        DatabaseManager.KeyInfo keyInfo = db.getUserKeyInfo(uid);
                        if (keyInfo != null && keyInfo.wrappedKey != null) {
                            admin.encryptionKey = crypto.unwrapKey(
                                    new CryptoManager.EncryptedData(keyInfo.wrappedKey, keyInfo.keyIv),
                                    hsm.getMasterKEK());
                            System.out.println("[✓] Admin authenticated. DEK unwrapped from HSM.");
                        } else {
                            // Fallback for legacy users
                            admin.salt = db.getUserSalt(regUser);
                            admin.encryptionKey = crypto.deriveKey(regPass, admin.salt);
                        }
                    } else {
                        risk.recordFailedAttempt(regUser);
                        System.out.println(
                                "[!] Admin password mismatch with DB record. System Risk: " + risk.getRiskScore());
                        evaluateAutonomousDefense();
                    }
                }

                // NEW: Load sub-users from database to fix persistence
                loadSubUsersFromDB();
            } catch (Exception e) {
                System.out.println("[!] Database initialization error: " + e.getMessage());
            }
        }

        // NEW: Security Audit on Login (Admin)
        if (ai != null && ai.checkBreach(regPass)) {
            System.out.println("\n⚠️  [SECURITY WARNING] Your Master Password is found in breach databases!");
            System.out.println("    It is highly recommended to change it immediately for safety.");
        }

        // INITIALIZE SESSION FOR ADMIN
        admin.sessionManager.currentUser = admin;
        admin.sessionManager.isLoggedIn = true;
        admin.sessionManager.isAdminSession = true;

        System.out.println("Root Admin Registered. Starting System...");

        // Phase 9: Control Mode Selection
        System.out.println("\n--- SYSTEM CONTROL MODE ---");
        System.out.println("1. Normal Control (Standard Security)");
        System.out.println("2. Cyber Resistance Control (AI-Enforced, Anti-Breach)");
        String modeChoice = getSecureInput("Select Mode: ");
        if (modeChoice.equals("2")) {
            this.cyberResistanceMode = true;
            System.out.println("[🛡️] Cyber Resistance Mode ENABLED.");
        } else {
            System.out.println("[ℹ] Normal Control Mode enabled.");
        }

        // Fix: Explicitly load sub-users before starting the loop if not already done
        loadSubUsersFromDB();

        // --- PHASE 2: ADMIN CONTROL LOOP ---
        boolean systemRunning = true;
        while (systemRunning) {
            checkThreadHealth(); // NEW: Verify process integrity
            System.out.println("\n=== ADMIN CONTROL PANEL [" + (cyberResistanceMode ? "CYBER" : "NORMAL") + "] ===");
            System.out.println("Current Access: " + admin.username);
            System.out.println("1. Register New User");
            System.out.println("2. Access User Vault (Login as User)");
            System.out.println("3. System Stats");
            System.out.println("4. SHUTDOWN SYSTEM");
            System.out.println("5. System Security Audit (All Users)");
            System.out.println("6. Train AI Model (Markov Chain)");
            System.out.println("7. Import Breach List (Bloom Filter)");
            System.out.println("9. EXPORT ALL DATA (CSV)");
            System.out.println("11. EXPORT CLOUD SYNC BLOB (Zero-Knowledge)");
            System.out.println("12. IMPORT CLOUD SYNC BLOB (Restore)");
            System.out.println("13. REVOKE ALL SESSIONS (Kill-Switch)");

            String choice = getSecureInput("Admin Command: ");

            if (choice.equals("1")) {
                manageUsersFlow();
            } else if (choice.equals("2")) {
                User u = selectUserInteractively();
                if (u != null) {
                    applyRateLimit(u.username); // NEW: Rate Limit
                    if (!checkMFAChallenge(u)) {
                        System.out.println("Access Denied: MFA Challenge Failed.");
                    } else {
                        // NEW: HSM Unwrap for Sub-User
                        if (db != null && u.userId != null) {
                            try {
                                DatabaseManager.KeyInfo kInfo = db.getUserKeyInfo(u.userId);
                                if (kInfo != null && kInfo.wrappedKey != null) {
                                    u.encryptionKey = crypto.unwrapKey(
                                            new CryptoManager.EncryptedData(kInfo.wrappedKey, kInfo.keyIv),
                                            hsm.getMasterKEK());
                                    System.out.println("[✓] DEK unwrapped from HSM for user: " + u.username);
                                    risk.recordSuccessfulLogin(u.username);
                                }
                            } catch (Exception e) {
                                System.out.println("[!] HSM key recovery failed: " + e.getMessage());
                                risk.recordFailedAttempt(u.username);
                                evaluateAutonomousDefense();
                            }
                        }
                        System.out.println("Switching to User Session...");
                        runUserSession(u);
                    }
                } else {
                    risk.recordFailedAttempt("unknown_user");
                    evaluateAutonomousDefense();
                }
            } else if (choice.equals("3")) {
                // Admin Stats
                admin.viewSystemStats(getTotalAccounts(admin));
            } else if (choice.equals("4")) {
                System.out.println("System Shutting Down...");
                // SECURE SHUTDOWN: Clear AI models and sensitive data
                if (ai != null)
                    ai = null;
                if (admin != null) {
                    admin.encryptionKey = null;
                    admin.sessionManager.logout();
                }
                hsm.secureWipe(); // NEW: HSM Wipe
                System.gc(); // Suggest garbage collection
                systemRunning = false;
            } else if (choice.equals("5")) {
                viewSystemAudit(admin);
            } else if (choice.equals("6")) {
                System.out.println("--- Train AI Model ---");
                String path = getSecureInput("Enter path to training text file (e.g. /usr/share/dict/words): ");
                if (ai != null)
                    ai.trainModel(path);
            } else if (choice.equals("7")) {
                System.out.println("--- Import Breach List ---");
                String path = getSecureInput("Enter path to breach list file (one password per line): ");
                if (ai != null)
                    ai.importBreachList(path);
            } else if (choice.equals("8")) {
                globalSearchFlow();
            } else if (choice.equals("9")) {
                exportAllToCSV();
            } else if (choice.equals("10")) {
                scanAllForBreaches();
            } else if (choice.equals("11")) {
                exportSyncBlobFlow();
            } else if (choice.equals("12")) {
                importSyncBlobFlow();
            } else if (choice.equals("13")) {
                risk.resetRisk();
                System.out.println("[🚨] KILL-SWITCH ENGAGED: Risk levels reset and sessions revoked.");
                System.exit(0);
            } else {
                System.out.println("Invalid Command.");
            }
        }
    }

    private void globalSearchFlow() {
        System.out.println("\n--- Global Search (All Users) ---");
        String query = getSecureInput("Search term (Site or Username): ");
        if (db == null) {
            System.out.println("[!] Database not available for global search.");
            return;
        }
        try {
            List<String> userList = db.getAllUsers();
            boolean found = false;
            for (String u : userList) {
                Integer uid = db.getUserId(u);
                if (uid == null)
                    continue;
                List<DatabaseManager.AccountData> accs = db.getAccounts(uid);
                for (DatabaseManager.AccountData a : accs) {
                    if (stringContains(a.siteName, query) || stringContains(a.username, query)) {
                        System.out.println("User: " + u + " | " + a.siteName + " (" + a.username + ")");
                        found = true;
                    }
                }
            }
            if (!found)
                System.out.println("No matching accounts found.");
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public void scanAllForBreaches() {
        System.out.println("\n--- Proactive Security: Global Breach Scan ---");
        if (ai == null) {
            System.out.println("[!] AI Engine not loaded. Cannot scan.");
            return;
        }

        try {
            List<String> userList = db.getAllUsers();
            int breachCount = 0;
            for (String u : userList) {
                Integer uid = db.getUserId(u);
                List<DatabaseManager.AccountData> accs = db.getAccounts(uid);
                for (DatabaseManager.AccountData a : accs) {
                    // We don't have the plain password here without decryption keys of each user
                    // In a real system, the user's client would do this.
                    // For this enterprise simulation, we scan the Site Names and Usernames
                    // against the Markov model for commonality.
                    if (ai.checkBreach(a.username)) {
                        System.out.println("[⚠️] Potential Breach: User '" + u + "' has identifier '" + a.username
                                + "' in breach list.");
                        breachCount++;
                    }
                }
            }
            System.out.println("Scan Complete. Breaches Found: " + breachCount);
        } catch (Exception e) {
            System.out.println("Scan Error: " + e.getMessage());
        }
    }

    private void exportAllToCSV() {
        System.out.println("\n--- Exporting System Data to CSV ---");
        try (FileWriter writer = new FileWriter("passwords_export.csv")) {
            writer.write("Owner,Site,Category,Username,Strength\n");

            // Add Admin
            List<DatabaseManager.AccountData> adminAccs = db.getAccounts(admin.userId);
            for (DatabaseManager.AccountData a : adminAccs) {
                writer.write(admin.username + "," + a.siteName + "," + a.category + "," + a.username + ","
                        + a.strengthScore + "\n");
            }

            // Add Sub-users
            List<String> users = db.getAllUsers();
            for (String u : users) {
                Integer uid = db.getUserId(u);
                List<DatabaseManager.AccountData> accs = db.getAccounts(uid);
                for (DatabaseManager.AccountData a : accs) {
                    writer.write(
                            u + "," + a.siteName + "," + a.category + "," + a.username + "," + a.strengthScore + "\n");
                }
            }
            System.out.println("[✓] Exported to passwords_export.csv");
        } catch (Exception e) {
            System.out.println("[✗] Export failed: " + e.getMessage());
        }
    }

    private void loadSubUsersFromDB() {
        if (db == null || admin == null)
            return;
        try {
            List<String> usernames = db.getAllUsers();
            int count = 0;
            for (String username : usernames) {
                if (admin.findSubUser(username) == null) {
                    admin.addSubUser(username, "[PROTECTED]");
                    User u = admin.findSubUser(username);
                    if (u != null) {
                        u.userId = db.getUserId(username);
                        u.mfaSecret = db.getMFASecret(u.userId);
                    }
                    count++;
                }
            }
            if (count > 0)
                System.out.println("[DB] Loaded " + count + " users into memory.");
        } catch (SQLException e) {
            System.out.println("[!] Failed to load users from DB: " + e.getMessage());
        }
    }

    private void exportSyncBlobFlow() {
        System.out.println("\n--- Export Cloud Sync Blob ---");
        if (sync == null) {
            System.out.println("[!] Sync services not available.");
            return;
        }
        try {
            byte[] blob = sync.createSyncBlob();
            String path = "vault_sync_" + System.currentTimeMillis() + ".bin";
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(path)) {
                fos.write(blob);
            }
            System.out.println("[✓] Zero-Knowledge Sync Blob exported to: " + path);
            System.out.println("[ℹ] This file is encrypted & signed by your HSM. It is safe for cloud storage.");
        } catch (Exception e) {
            System.out.println("[!] Export Failed: " + e.getMessage());
        }
    }

    private void importSyncBlobFlow() {
        System.out.println("\n--- Import Cloud Sync Blob ---");
        if (sync == null) {
            System.out.println("[!] Sync services not available.");
            return;
        }
        String path = getSecureInput("Enter path to sync blob file: ");
        try {
            java.io.File file = new java.io.File(path);
            if (!file.exists()) {
                System.out.println("[!] File not found.");
                return;
            }
            byte[] blob = new byte[(int) file.length()];
            try (java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
                fis.read(blob);
            }
            if (sync.restoreFromSyncBlob(blob)) {
                System.out.println("[✓] System logic restored from Sync Blob.");
                System.out.println("[ℹ] Please restart the application to finalize the restoration.");
                System.exit(0);
            }
        } catch (Exception e) {
            System.out.println("[!] Import Failed: " + e.getMessage());
        }
    }

    public User selectUserInteractively() {
        String inputName = getSecureInput("Enter Username to access: ");
        User u = admin.findSubUser(inputName);
        if (u == null) {
            System.out.println("User not found.");
        }
        return u;
    }

    public void runUserSession(User currentUser) {
        boolean sessionActive = true;
        lastActivityTime = System.currentTimeMillis();

        while (sessionActive) {
            try {
                checkThreadHealth(); // NEW: Concurrency Watchdog
                checkSessionTimeout(currentUser);

                System.out.println("\n--- USER VAULT MENU (" + currentUser.username + ") ["
                        + (cyberResistanceMode ? "CYBER" : "NORMAL") + "] ---");
                System.out.println("1. Add Password");
                System.out.println("2. View Vault");
                System.out.println("3. Search");
                System.out.println("4. Update Password");
                System.out.println("5. Export Preview");
                System.out.println("6. Password Generator");
                System.out.println("7. Password Analysis");
                System.out.println("8. View Password History");
                System.out.println("9. SETUP MFA (NEW)");
                System.out.println("10. LOGOUT (Return to Admin)");

                String choiceStr = getSecureInput("Option: ");
                int choice = stringToInt(choiceStr);

                if (choice == 1) {
                    addAccount(currentUser);
                } else if (choice == 2) {
                    viewAccounts(currentUser);
                } else if (choice == 3) {
                    searchAccount(currentUser);
                } else if (choice == 4) {
                    updatePasswordFlow(currentUser);
                } else if (choice == 5) {
                    exportPreview(currentUser);
                } else if (choice == 6) {
                    passwordGeneratorFlow(currentUser);
                } else if (choice == 7) {
                    passwordValidatorFlow(currentUser);
                } else if (choice == 8) {
                    viewPasswordHistory(currentUser);
                } else if (choice == 9) {
                    setupMFAFlow(currentUser);
                } else if (choice == 10) {
                    System.out.println("Logging out user...");
                    currentUser.encryptionKey = null; // Security clear
                    sessionActive = false;
                } else {
                    System.out.println("Invalid Option.");
                }
                lastActivityTime = System.currentTimeMillis();
            } catch (RuntimeException e) {
                if (e.getMessage().equals("SESSION_TIMEOUT")) {
                    sessionActive = false;
                } else {
                    throw e;
                }
            }
        }
    }

    private void checkSessionTimeout(User currentUser) {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastActivityTime > SESSION_TIMEOUT_MS) {
            System.out.println("\n⚠️  Session timeout - please login again");
            currentUser.encryptionKey = null;
            currentUser.sessionManager.isLoggedIn = false;
            throw new RuntimeException("SESSION_TIMEOUT");
        }
    }

    public void viewPasswordHistory(User currentUser) {
        System.out.println("\n--- Password History Viewer ---");
        String site = getSecureInput("Enter Site Name: ");

        // NEW: Try database first
        if (db != null && currentUser.userId != null && currentUser.encryptionKey != null) {
            try {
                List<DatabaseManager.AccountData> accounts = db.getAccounts(currentUser.userId);
                DatabaseManager.AccountData target = null;
                for (DatabaseManager.AccountData acc : accounts) {
                    if (compareIgnoreCase(acc.siteName, site)) {
                        target = acc;
                        break;
                    }
                }

                if (target != null) {
                    System.out.println("\n=== Password History (DB) for: " + target.siteName + " ===");
                    List<DatabaseManager.PasswordHistory> history = db.getPasswordHistory(target.accountId);
                    if (history.isEmpty()) {
                        System.out.println("  [No history found]");
                    } else {
                        for (int i = 0; i < history.size(); i++) {
                            DatabaseManager.PasswordHistory h = history.get(i);
                            CryptoManager.EncryptedData enc = new CryptoManager.EncryptedData(h.encryptedPassword, h.iv,
                                    h.authTag);
                            String pwd = crypto.decrypt(enc, currentUser.encryptionKey);
                            System.out.println((i + 1) + ". " + pwd + " [" + h.changedAt + "]");
                        }
                    }
                    return;
                }
            } catch (Exception e) {
                System.out.println("[!] DB fetch failed: " + e.getMessage());
            }
        }

        // Fallback to memory
        for (Account acc : currentUser.getVault()) {
            if (compareIgnoreCase(acc.getSiteName(), site)) {
                System.out.println("\n=== Password History (Memory) for: " + acc.getSiteName() + " ===");
                String[] history = acc.getHistory();
                boolean empty = true;
                for (int i = 0; i < history.length; i++) {
                    if (history[i] != null && !history[i].isEmpty()) {
                        System.out.println((i + 1) + ". " + history[i]);
                        empty = false;
                    }
                }
                if (empty)
                    System.out.println("  [No history available]");
                return;
            }
        }
        System.out.println("Account not found.");
    }

    public void viewSystemAudit(User contextUser) {
        System.out.println("\n--- System Security Audit ---");
        int totalAccounts = 0;
        int strongCount = 0;

        if (contextUser.isAdmin) {
            AdminUser adminContext = (AdminUser) contextUser;
            List<User> users = adminContext.getSubUsers();
            for (User u : users) {
                totalAccounts += getAccountCountForUser(u);
                strongCount += countStrongForUser(u);
            }
            // Include Admin's accounts
            totalAccounts += getAccountCountForUser(adminContext);
            strongCount += countStrongForUser(adminContext);
        } else {
            totalAccounts = getAccountCountForUser(contextUser);
            strongCount = countStrongForUser(contextUser);
        }

        if (totalAccounts == 0) {
            System.out.println("No accounts found to audit.");
            return;
        }

        int auditScore = (strongCount * 100) / totalAccounts;
        System.out.println("Total Accounts Scanned: " + totalAccounts);
        System.out.println("Strong Passwords (Entropy >= 3): " + strongCount);

        // AI Security Rating
        if (ai != null) {
            int aiComplexCount = countAIComplexForUser(contextUser);
            int aiScore = (aiComplexCount * 100) / totalAccounts;
            System.out.println("AI-Complex Passwords (Markov Check): " + aiComplexCount);
            System.out.println("AI Security Rating: " + aiScore + "%");
        }

        System.out.println("Combined Security Health Score: " + auditScore + "%");
    }

    private int countAIComplexForUser(User u) {
        int count = 0;
        for (Account acc : u.getVault()) {
            if (ai != null && !ai.analyzePassword(acc.getPassword()).getStrengthLabel().equals("Weak")) {
                count++;
            }
            for (Account sub : acc.subAccounts) {
                if (ai != null && !ai.analyzePassword(sub.getPassword()).getStrengthLabel().equals("Weak")) {
                    count++;
                }
            }
        }
        return count;
    }

    public int getAccountCountForUser(User u) {
        int count = 0;
        for (Account acc : u.getVault()) {
            count++;
            count += acc.subAccounts.size();
        }
        return count;
    }

    public int countStrongForUser(User u) {
        int count = 0;
        for (Account acc : u.getVault()) {
            if (u.passwordUtils.getStrengthScore(acc.getPassword()) == 3)
                count++;
            for (Account sub : acc.subAccounts) {
                if (u.passwordUtils.getStrengthScore(sub.getPassword()) == 3)
                    count++;
            }
        }
        return count;
    }

    public String getSecureInput(String prompt) {
        if (prompt != null && !prompt.equals("")) {
            System.out.print(prompt);
        }
        if (scanner.hasNextLine()) {
            String input = scanner.nextLine();
            return trimString(input);
        }
        return "";
    }

    public void passwordGeneratorFlow(User currentUser) {
        System.out.println("\n--- Password Generator ---");

        if (ai != null) {
            // AI-powered generation
            System.out.println("1. Random Strong Password (AI-optimized)");
            System.out.println("2. Memorable Passphrase (AI-generated)");
            System.out.println("3. Custom Parameters (Legacy)");
            System.out.println("4. Exit");

            String choice = getSecureInput("Choose option: ");

            if (choice.equals("1") || choice.equals("2")) {
                List<String> suggestions = ai
                        .generateSuggestions(choice.equals("1") ? "strong password" : "memorable passphrase");

                System.out.println("\nGenerated Passwords:");
                for (int i = 0; i < suggestions.size(); i++) {
                    String pwd = suggestions.get(i);
                    AIPasswordAnalyzer.AnalysisResult analysis = ai.analyzePassword(pwd);
                    System.out.println((i + 1) + ". " + pwd + " [" + analysis.getStrengthLabel() + "]");
                }

                String pick = getSecureInput("Pick one (1-" + suggestions.size() + ") or 0 to cancel: ");
                int idx = stringToInt(pick) - 1;

                if (idx >= 0 && idx < suggestions.size()) {
                    addAccountWithPassword(currentUser, suggestions.get(idx));
                    return;
                }
            } else if (choice.equals("4")) {
                return;
            }
            // Fallthrough to legacy for option 3 or invalid
            if (!choice.equals("3"))
                return;
        }

        // Legacy rule-based generation
        String generated = "";
        while (true) {
            generated = currentUser.passwordUtils.generateStrongPassword();
            if (currentUser.passwordUtils.checkBreach(generated)
                    || currentUser.passwordUtils.isPasswordReused(generated, currentUser.getVault())) {
                continue;
            }

            System.out.println("Generated Password: " + generated);
            System.out.println("1. Accept & Add to Account");
            System.out.println("2. Regenerate");
            System.out.println("3. Exit");
            System.out.print("Choice: ");
            String choice = getSecureInput("Choice: ");

            if (choice.equals("1")) {
                addAccountWithPassword(currentUser, generated);
                return;
            } else if (choice.equals("3")) {
                return;
            }
        }
    }

    public void passwordValidatorFlow(User currentUser) {
        System.out.println("\n--- Password Analysis ---");
        String pass = getSecureInput("Enter Password to Verify: ");

        if (ai != null) {
            // AI-powered analysis
            try {
                AIPasswordAnalyzer.AnalysisResult result = ai.analyzePassword(pass);

                System.out.println("\n" + result);

                // Check breach database
                if (ai.checkBreach(pass)) {
                    System.out.println("\n⚠️  CRITICAL WARNING: This password appears in breach databases!");
                    System.out.println("    This password should NEVER be used.");
                }

                // Offer suggestions
                System.out.println("\n--- Suggested Strong Alternatives ---");
                List<String> suggestions = ai.generateContextualSuggestions(pass);
                System.out.println("1. Adjusted Phrase (Secure): " + suggestions.get(0));
                System.out.println("2. Memorable (AI Markov): " + suggestions.get(1));
                System.out.println("3. Strong Random: " + suggestions.get(2));

                String response = getSecureInput("Save original password to a new account anyway? (y/n): ");
                if (compareIgnoreCase(response, "y")) {
                    addAccountWithPassword(currentUser, pass);
                }

            } catch (Exception e) {
                System.out.println("[!] AI analysis failed: " + e.getMessage());
            }
        } else {
            // Rule-based analysis (existing code)
            boolean isStrong = currentUser.passwordUtils.checkStrength(pass);
            boolean isBreached = currentUser.passwordUtils.checkBreach(pass);
            boolean isReused = currentUser.passwordUtils.isPasswordReused(pass, currentUser.getVault());

            if (isStrong) {
                System.out.println("Strength Check: PASS");
            } else {
                System.out.println("Strength Check: FAIL (Weak)");
            }

            if (isBreached) {
                System.out.println("Breach Check: FAIL (Breached)");
            } else {
                System.out.println("Breach Check: PASS");
            }

            if (isReused) {
                System.out.println("Reuse Check: FAIL (Used Before)");
            } else {
                System.out.println("Reuse Check: PASS");
            }

            if (!isStrong || isBreached || isReused) {
                System.out.println("\nRecommendation: Use Password Generator.");
                String response = getSecureInput("Go to Generator? (y/n): ");
                if (compareIgnoreCase(response, "y")) {
                    passwordGeneratorFlow(currentUser);
                }
            } else {
                System.out.println("\nPassword is Secure.");
                String response = getSecureInput("Save this password to a new account? (y/n): ");
                if (compareIgnoreCase(response, "y")) {
                    addAccountWithPassword(currentUser, pass);
                }
            }
        }
    }

    public void manageUsersFlow() {
        System.out.println("\n--- User Management ---");
        System.out.println("1. Add New User");
        System.out.println("2. Back");
        String choice = getSecureInput("Choice: ");

        if (choice.equals("1")) {
            String newU = getSecureInput("New Username: ");
            if (!isValidUsername(newU)) {
                System.out.println("Invalid Username.");
                return;
            }
            String newP = getSecureInput("New Password: ");
            if (newP.length() < 6) {
                System.out.println("Password too short (Min 6).");
                return;
            }

            // AI INTEGRATION: Breach and Markov Checks for Sub-Users
            if (ai != null) {
                if (ai.checkBreach(newP)) {
                    System.out.println("[🛡️] REJECTED: Password found in global breach list.");
                    showAISuggestions(newP);
                    return;
                }
                if (ai.analyzePassword(newP).getStrengthLabel().equals("Weak")) {
                    System.out.println("[🛡️] REJECTED: Password is too predictable according to AI Markov analysis.");
                    showAISuggestions(newP);
                    return;
                }
            }

            if (admin.addSubUser(newU, newP)) {
                if (db != null) {
                    try {
                        // HSM Integration: Generate random DEK for sub-user
                        SecretKey dek = crypto.generateRandomKey();
                        CryptoManager.EncryptedData wrapped = crypto.wrapKey(dek, hsm.getMasterKEK());

                        if (db.registerUser(newU, newP, false, wrapped.encryptedBytes, wrapped.iv)) {
                            User newUser = admin.getSubUsers().get(admin.getSubUsers().size() - 1);
                            newUser.userId = db.getUserId(newU);
                            newUser.encryptionKey = dek; // Set the unwrapped key in memory
                            System.out.println("[✓] User created and secured with HSM-protected DEK.");
                        } else {
                            System.out.println("[!] ERROR: Username '" + newU + "' already exists in database.");
                            // Remove from memory if DB sync failed due to existing user
                            admin.getSubUsers().remove(admin.getSubUsers().size() - 1);
                        }
                    } catch (Exception e) {
                        System.out.println("[!] DB Sync/Key Wrapping failed: " + e.getMessage());
                    }
                } else {
                    System.out.println("User added to system (Memory Only).");
                }
            }
        }
    }

    public void addAccount(User currentUser) {
        addAccountWithPassword(currentUser, null);
    }

    public void addAccountWithPassword(User currentUser, String preFilledPass) {
        System.out.println("\n--- Add Account ---");
        String site = getSecureInput("Site Name: ");
        String username = getSecureInput("Username: ");
        String category = getSecureInput("Category: ");
        String pass = preFilledPass != null ? preFilledPass : getSecureInput("Password: ");

        // Cyber Resistance: Strict AI Block
        if (ai != null) {
            boolean breached = ai.checkBreach(pass);
            boolean weak = ai.analyzePassword(pass).getStrengthLabel().equals("Weak");

            if (breached || weak) {
                if (breached)
                    System.out.println("[🛡️] REJECTED: Password found in global breach list.");
                if (weak)
                    System.out.println("[🛡️] REJECTED: Password is too predictable (Markov Failure).");

                showAISuggestions(pass);
                // In Cyber Resistance Mode, we strictly block.
                // In Normal Mode, we purely warn (as per existing logic flow).
                if (cyberResistanceMode) {
                    System.out.println("[🚨] BLOCK: Enterprise security policy prohibits this password in Cyber Mode.");
                    return;
                }
            }
        }

        // Logic for sub-accounts
        Account existing = null;
        for (Account a : currentUser.getVault()) {
            if (compareIgnoreCase(a.siteName, site)) {
                existing = a;
                break;
            }
        }

        if (existing != null) {
            String subChoice = getSecureInput("Site exists. Add as sub-account? (y/n): ");
            if (compareIgnoreCase(subChoice, "y")) {
                existing.addSubAccount(new Account(site, username, pass, category));
                System.out.println("[✓] Sub-account added.");
            } else {
                System.out.println("[!] Account addition cancelled.");
                return;
            }
        } else {
            currentUser.getVault().add(new Account(site, username, pass, category));
            System.out.println("[✓] Account added to vault.");
        }

        // DB Sync
        if (db != null && currentUser.userId != null && currentUser.encryptionKey != null) {
            try {
                int score = currentUser.passwordUtils.getStrengthScore(pass);
                db.addAccount(currentUser.userId, site, category, username, pass, currentUser.encryptionKey, score);
                System.out.println("[✓] Database record created.");
            } catch (Exception e) {
                System.out.println("[!] DB error: " + e.getMessage());
            }
        }
    }

    public void viewAccounts(User currentUser) {
        System.out.println("\n--- All Accounts ---");
        List<Account> vault = currentUser.getVault();
        if (vault.isEmpty()) {
            System.out.println("Vault is empty.");
            return;
        }

        for (int i = 0; i < vault.size(); i++) {
            Account acc = vault.get(i);
            System.out.println((i + 1) + ". " + acc.toString());
            for (Account sub : acc.subAccounts) {
                System.out.println("   └─ Site: " + sub.siteName + " | User: " + sub.username + " [Sub]");
            }
        }
    }

    public void searchAccount(User currentUser) {
        System.out.println("\n--- Search Vault ---");
        String term = getSecureInput("Enter search term: ");
        boolean found = false;

        for (Account acc : currentUser.getVault()) {
            if (stringContains(acc.siteName, term) || stringContains(acc.username, term)) {
                System.out.println("[Found] " + acc.toString());
                for (Account sub : acc.subAccounts) {
                    System.out.println("   └─ [Sub] Site: " + sub.siteName + " | User: " + sub.username);
                }
                found = true;
            } else {
                for (Account sub : acc.subAccounts) {
                    if (stringContains(sub.siteName, term) || stringContains(sub.username, term)) {
                        System.out.println("[Found in Sub-Account of " + acc.siteName + "] Site: " + sub.siteName
                                + " | User: " + sub.username);
                        found = true;
                    }
                }
            }
        }
        if (!found)
            System.out.println("No matching accounts found.");
    }

    public void exportPreview(User currentUser) {
        System.out.println("\n--- Export Preview ---");
        System.out.println(padRight("SITE", 15) + " " + padRight("USER", 15) + " " + "CATEGORY");
        System.out.println("----------------------------------------------------------------");
        for (Account acc : currentUser.getVault()) {
            System.out.println(padRight(acc.siteName, 15) + " " + padRight(acc.username, 15) + " " + acc.category);
            for (Account sub : acc.subAccounts) {
                System.out.println(padRight("  (Sub) " + sub.siteName, 15) + " " + padRight(sub.username, 15) + " "
                        + sub.category);
            }
        }
    }

    public void updatePasswordFlow(User currentUser) {
        System.out.println("--- Update Password ---");
        String siteName = getSecureInput("Enter Site Name used to Update: ");

        if (db != null && currentUser.userId != null && currentUser.encryptionKey != null) {
            try {
                List<DatabaseManager.AccountData> accounts = db.getAccounts(currentUser.userId);
                DatabaseManager.AccountData target = null;
                for (DatabaseManager.AccountData acc : accounts) {
                    if (compareIgnoreCase(acc.siteName, siteName)) {
                        target = acc;
                        break;
                    }
                }

                if (target != null) {
                    String newPass = getSecureInput("Enter new password: ");

                    // AI Check
                    if (ai != null) {
                        boolean breached = ai.checkBreach(newPass);
                        boolean weak = ai.analyzePassword(newPass).getStrengthLabel().equals("Weak");
                        if (breached || weak) {
                            if (breached)
                                System.out.println("[🛡️] REJECTED: Password found in global breach list.");
                            if (weak)
                                System.out.println("[🛡️] REJECTED: Password is too predictable (Markov Failure).");
                            showAISuggestions(newPass);
                            if (cyberResistanceMode) {
                                System.out
                                        .println("[🚨] BLOCK: Security policy prohibits this password in Cyber Mode.");
                                return;
                            }
                        }
                    }

                    int score = currentUser.passwordUtils.getStrengthScore(newPass);
                    if (db.updateAccountPassword(target.accountId, newPass, currentUser.encryptionKey, score)) {
                        System.out.println("[✓] Password updated in database.");
                        updatePassword(currentUser, siteName, newPass);
                        return;
                    }
                }
            } catch (Exception e) {
                System.out.println("[!] DB Update failed: " + e.getMessage());
            }
        }
        updatePassword(currentUser, siteName, null);
    }

    public void updatePassword(User currentUser, String siteName, String preFilledPass) {
        Account target = null;
        for (Account acc : currentUser.getVault()) {
            if (compareIgnoreCase(acc.siteName, siteName)) {
                target = acc;
                break;
            }
        }

        if (target != null) {
            String newPass = preFilledPass != null ? preFilledPass : getSecureInput("Enter New Password: ");
            target.setPassword(newPass);
            System.out.println("[✓] Password updated in memory.");
        } else {
            System.out.println("Account not found.");
        }
    }

    public int getTotalAccounts(User contextUser) {
        return getAccountCountForUser(contextUser);
    }

    // ===== UTILITY METHODS =====

    public String trimString(String str) {
        if (str == null || str.equals("")) {
            return "";
        }

        int start = 0;
        int end = str.length() - 1;

        while (start <= end && str.charAt(start) == ' ') {
            start = start + 1;
        }

        while (end >= start && str.charAt(end) == ' ') {
            end = end - 1;
        }

        if (start > end) {
            return "";
        }

        String result = "";
        for (int i = start; i <= end; i++) {
            result = result + str.charAt(i);
        }
        return result;
    }

    public int stringToInt(String str) {
        if (str == null || str.equals("")) {
            return -1;
        }

        str = trimString(str);
        if (str.equals("")) {
            return -1;
        }

        int result = 0;
        boolean isNegative = false;
        int startIndex = 0;

        if (str.charAt(0) == '-') {
            isNegative = true;
            startIndex = 1;
        } else if (str.charAt(0) == '+') {
            startIndex = 1;
        }

        for (int i = startIndex; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c >= '0' && c <= '9') {
                result = result * 10 + (c - '0');
            } else {
                return -1;
            }
        }

        if (isNegative) {
            result = -result;
        }

        return result;
    }

    public boolean compareIgnoreCase(String str1, String str2) {
        if (str1 == null && str2 == null) {
            return true;
        }
        if (str1 == null || str2 == null) {
            return false;
        }
        if (str1.length() != str2.length()) {
            return false;
        }

        for (int i = 0; i < str1.length(); i++) {
            char c1 = str1.charAt(i);
            char c2 = str2.charAt(i);

            if (c1 >= 'A' && c1 <= 'Z') {
                c1 = (char) (c1 + 32);
            }
            if (c2 >= 'A' && c2 <= 'Z') {
                c2 = (char) (c2 + 32);
            }

            if (c1 != c2) {
                return false;
            }
        }
        return true;
    }

    public boolean stringStartsWith(String str, String prefix) {
        if (str == null || prefix == null) {
            return false;
        }
        if (prefix.length() > str.length()) {
            return false;
        }

        for (int i = 0; i < prefix.length(); i++) {
            if (str.charAt(i) != prefix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    public boolean stringContains(String str, String substr) {
        if (str == null || substr == null) {
            return false;
        }
        if (substr.length() > str.length()) {
            return false;
        }
        if (substr.equals("")) {
            return true;
        }

        for (int i = 0; i <= str.length() - substr.length(); i++) {
            boolean found = true;
            for (int j = 0; j < substr.length(); j++) {
                if (str.charAt(i + j) != substr.charAt(j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }

    public boolean isValidUsername(String username) {
        if (username == null || username.equals("")) {
            return false;
        }

        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            boolean valid = (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    public boolean isValidSiteName(String siteName) {
        if (siteName == null || siteName.equals("")) {
            return false;
        }

        for (int i = 0; i < siteName.length(); i++) {
            char c = siteName.charAt(i);
            boolean valid = (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == ' ' || c == '.' || c == '_' || c == '-';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    public boolean containsSpace(String str) {
        if (str == null) {
            return false;
        }
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ' ') {
                return true;
            }
        }
        return false;
    }

    public String padRight(String str, int length) {
        if (str == null) {
            str = "";
        }
        if (str.length() >= length) {
            return str.substring(0, length);
        }

        String result = str;
        for (int i = str.length(); i < length; i++) {
            result = result + " ";
        }
        return result;
    }

    private boolean checkMFAChallenge(User user) {
        if (user.mfaSecret == null || user.mfaSecret.isEmpty()) {
            if (risk.isHighRisk()) {
                System.out.println("\n[🚨] ADAPTIVE SECURITY LOCKDOWN: MFA Setup Required due to High Risk.");
                System.out.println("    Access is blocked until MFA is configured.");
                return false;
            }
            return true; // MFA not set up
        }
        System.out.println("\n[🛡️] MFA Challenge Required.");
        String codeStr = getSecureInput("Enter 6-digit Authenticator Code: ");
        try {
            int code = Integer.parseInt(codeStr);
            if (totp.verifyCode(user.mfaSecret, code)) {
                System.out.println("[✓] MFA Verified.");
                return true;
            } else {
                System.out.println("[✗] Invalid MFA Code.");
                return false;
            }
        } catch (NumberFormatException e) {
            System.out.println("[✗] Code must be numeric.");
            return false;
        }
    }

    private void setupMFAFlow(User user) {
        if (user.mfaSecret != null && !user.mfaSecret.isEmpty()) {
            System.out.println("[ℹ] MFA is already enabled.");
            return;
        }
        String secret = totp.generateSecret();
        System.out.println("\n--- MFA SETUP ---");
        System.out.println("1. Install an Authenticator App (Google/Microsoft/Authy).");
        System.out.println("2. Add a new account manually using this secret: " + secret);
        System.out.println("3. Enter the 6-digit code shown in your app to verify.");

        String codeStr = getSecureInput("Verification Code: ");
        try {
            int code = Integer.parseInt(codeStr);
            if (totp.verifyCode(secret, code)) {
                user.mfaSecret = secret;
                if (db != null && user.userId != null) {
                    try {
                        db.updateMFASecret(user.userId, secret);
                    } catch (SQLException e) {
                        System.out.println("[!] Failed to save MFA secret to DB: " + e.getMessage());
                    }
                }
                System.out.println("[✓] MFA Setup Successful! It will be required at next login.");
            } else {
                System.out.println("[✗] Verification failed. Code was incorrect.");
            }
        } catch (NumberFormatException e) {
            System.out.println("[✗] Invalid input.");
        }
    }

    private void evaluateAutonomousDefense() {
        if (risk.isHighRisk() && !cyberResistanceMode) {
            System.out.println("\n[🚨] AUTONOMOUS DEFENSE TRIGGERED: System entering Cyber Resistance Mode!");
            this.cyberResistanceMode = true;
        }
    }

    private void checkThreadHealth() {
        if (risk.isThreadAnomaly()) {
            System.out.println("\n[🚨] SECURITY BREACH DETECTED: Anomalous Background Threads Found!");
            System.out.println("    Autonomous lockdown engaging to protect Master KEK...");
            evaluateAutonomousDefense();
            if (risk.getRiskScore() > 100) {
                System.out.println("[🚨] FATAL THREAT DETECTED: Revoking all hardware keys and terminating.");
                System.exit(1);
            }
        }
    }

    private void applyRateLimit(String username) {
        long delay = risk.calculateRateLimitDelay(username);
        if (delay > 0) {
            System.out.println(
                    "[🛡️] AI Security: Enforcing " + (delay / 1000.0) + "s rate limit for " + username + "...");
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void showAISuggestions(String rejected) {
        if (ai == null)
            return;
        List<String> suggestions = ai.generateContextualSuggestions(rejected);
        System.out.println("\n[🤖] AI CONTEXTUAL SUGGESTIONS:");
        System.out.println("    1. Adjusted Phrase (Secure): " + suggestions.get(0));
        System.out.println("    2. Memorable (AI Markov): " + suggestions.get(1));
        System.out.println("    3. Strong Random: " + suggestions.get(2));
        System.out.println("    *Tip: Copy one of these to use as your new password.*");
    }
}

class Account {
    public String siteName;
    public String username;
    public String password;
    public String category;
    public String[] history;
    public List<Account> subAccounts; // NEW: Hierarchical support

    public Account(String siteName, String username, String password, String category) {
        this.siteName = siteName;
        this.username = username;
        this.password = password;
        this.category = category;
        this.history = new String[3];
        this.subAccounts = new ArrayList<>();
    }

    public String getSiteName() {
        return siteName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getCategory() {
        return category;
    }

    public void setPassword(String newPassword) {
        this.history[2] = this.history[1];
        this.history[1] = this.history[0];
        this.history[0] = this.password;
        this.password = newPassword;
    }

    public String[] getHistory() {
        return history;
    }

    public void addSubAccount(Account sub) {
        this.subAccounts.add(sub);
    }

    public String toString() {
        return "Site: " + siteName + " | User: " + username + " | Category: " + category + " [" + subAccounts.size()
                + " sub]";
    }
}

class User {
    public String username;
    public String masterPassword;
    public List<Account> vault; // CHANGED: Unlimited storage
    public boolean isAdmin;
    public SessionManager sessionManager;
    public PasswordUtils passwordUtils;

    // NEW fields
    protected Integer userId; // Database ID (null if not in DB yet)
    protected byte[] salt; // For key derivation
    protected SecretKey encryptionKey; // Derived from master password
    public String mfaSecret; // NEW: MFA Secret for TOTP

    public User(String username, String masterPassword) {
        this.username = username;
        this.masterPassword = masterPassword;
        this.isAdmin = false;
        this.sessionManager = new SessionManager();
        this.passwordUtils = new PasswordUtils();

        this.vault = new ArrayList<>();

        // NEW: These will be set during authentication
        this.userId = null;
        this.salt = null;
        this.encryptionKey = null;
    }

    public List<Account> getVault() {
        return vault;
    }

    public boolean login(String inputUser, String inputPass) {
        if (this.username == null || inputUser == null || this.masterPassword == null || inputPass == null) {
            return false;
        }

        if (this.username.equals(inputUser) && this.masterPassword.equals(inputPass)) {
            sessionManager.isLoggedIn = true;
            sessionManager.currentUser = this;

            if (this.isAdmin) {
                sessionManager.isAdminSession = true;
            } else {
                sessionManager.isAdminSession = false;
            }
            return true;
        }
        return false;
    }
}

class AdminUser extends User {
    public List<User> subUsers; // CHANGED: Unlimited users

    public AdminUser(String username, String masterPassword) {
        super(username, masterPassword);
        this.isAdmin = true;
        this.subUsers = new ArrayList<>();
    }

    public List<User> getSubUsers() {
        return subUsers;
    }

    public void viewSystemStats(int totalAccounts) {
        System.out.println("\n=== SYSTEM STATS (Admin Only) ===");
        System.out.println("Current User: " + this.username);
        System.out.println("Total Stored Accounts: " + totalAccounts);
        System.out.println("Sub-Users Registered: " + getSubUserCount());
        System.out.println("Session Active: " + sessionManager.isLoggedIn);
        System.out.println("=================================");
    }

    public boolean addSubUser(String u, String p) {
        subUsers.add(new User(u, p));
        return true;
    }

    public boolean isSubUserFull() {
        return false; // Dynamic now
    }

    public int getSubUserCount() {
        return subUsers.size();
    }

    public boolean authenticateSubUser(String u, String p) {
        for (User user : subUsers) {
            if (user != null && user.login(u, p)) {
                return true;
            }
        }
        return false;
    }

    public User findSubUser(String username) {
        if (username == null) {
            return null;
        }
        for (User user : subUsers) {
            if (user != null) {
                if (user.username != null && user.username.equalsIgnoreCase(username)) {
                    return user;
                }
            }
        }
        return null;
    }
}

class SessionManager {
    public boolean isLoggedIn;
    public User currentUser;
    public boolean isAdminSession;

    public void logout() {
        this.isLoggedIn = false;
        this.currentUser = null;
        this.isAdminSession = false;
    }

    public int sessionOTP;
    public int loginAttempts;

    public SessionManager() {
        this.isLoggedIn = false;
        this.currentUser = null;
        this.isAdminSession = false;
        this.sessionOTP = 0;
        this.loginAttempts = 0;
    }

    public void regenerateOTP() {
        double random = Math.random();
        sessionOTP = (int) (random * 900000) + 100000;
    }

}

class PasswordUtils {
    public String[] breachList;

    public PasswordUtils() {
        breachList = new String[] {
                "123456", "password", "qwerty", "welcome", "111111", "admin", "12345678",
                "12345", "123456789", "iloveyou", "princess", "sunshine", "football",
                "monkey", "dragon", "starwars", "654321", "software", "guest", "network",
                "master", "access", "shadow", "superman", "batman", "letmein", "login", "hello", "user"
        };
    }

    public boolean checkBreach(String password) {
        if (password == null) {
            return false;
        }
        Main tempMain = new Main();
        String normalized = tempMain.trimString(password);
        for (int i = 0; i < breachList.length; i++) {
            if (tempMain.compareIgnoreCase(breachList[i], normalized)) {
                return true;
            }
        }
        return false;
    }

    public boolean checkStrength(String password) {
        return getStrengthScore(password) >= 3;
    }

    public int getStrengthScore(String password) {
        if (password == null) {
            return 0;
        }
        Main tempMain = new Main();
        password = tempMain.trimString(password);
        if (password.length() < 8) {
            return 0;
        }

        boolean hasUpper = false;
        boolean hasSpecial = false;
        boolean hasDigit = false;
        String specials = "!@#$%^&*()_+-=[]{}|;:,.<>?/\\~`'\"";

        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);

            if (c >= 'A' && c <= 'Z') {
                hasUpper = true;
            }

            if (c >= '0' && c <= '9') {
                hasDigit = true;
            }

            boolean foundSpecial = false;
            for (int j = 0; j < specials.length(); j++) {
                if (c == specials.charAt(j)) {
                    foundSpecial = true;
                    break;
                }
            }
            if (foundSpecial) {
                hasSpecial = true;
            }
        }

        int score = 0;
        if (hasUpper) {
            score = score + 1;
        }
        if (hasDigit) {
            score = score + 1;
        }
        if (hasSpecial) {
            score = score + 1;
        }
        return score;
    }

    public String getStrengthLabel(String password) {
        int score = getStrengthScore(password);

        if (score == 3) {
            return "Strong";
        } else if (score == 2) {
            return "Medium";
        } else {
            return "Weak";
        }
    }

    public String generateStrongPassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        String result = "";
        int length = 12;

        for (int i = 0; i < length; i++) {
            double random = Math.random();
            int index = (int) (random * chars.length());
            result = result + chars.charAt(index);
        }
        return result;
    }

    public String maskPassword(String password) {
        if (password == null || password.length() <= 2) {
            return "****";
        }
        String result = "";
        result = result + password.charAt(0);
        result = result + password.charAt(1);
        for (int i = 2; i < password.length(); i++) {
            result = result + '*';
        }
        return result;
    }

    public boolean isPasswordReused(String password, List<Account> accounts) {
        for (Account acc : accounts) {
            if (acc.getPassword().equals(password))
                return true;
            for (Account sub : acc.subAccounts) {
                if (sub.getPassword().equals(password))
                    return true;
            }
        }
        return false;
    }
}
