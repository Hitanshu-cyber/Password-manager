import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;

public class DatabaseManager {
    private Connection connection;
    private CryptoManager crypto;
    private static final String DB_URL = "jdbc:sqlite:password_manager.db";

    public static class AccountData implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        public int accountId;
        public String siteName;
        public String category;
        public String username;
        public byte[] encryptedPassword;
        public byte[] iv;
        public byte[] authTag;
        public int strengthScore;
        public boolean isBreached; // Not stored in DB directly in this schema, but useful for runtime object

        public AccountData(int id, String site, String cat, String user, byte[] encPwd, byte[] iv, int score) {
            this.accountId = id;
            this.siteName = site;
            this.category = cat;
            this.username = user;
            this.encryptedPassword = encPwd;
            this.iv = iv;
            this.strengthScore = score;
        }
    }

    public static class PasswordHistory {
        public byte[] encryptedPassword;
        public byte[] iv;
        public byte[] authTag;
        public String changedAt;

        public PasswordHistory(byte[] enc, byte[] iv, String date) {
            this.encryptedPassword = enc;
            this.iv = iv;
            this.changedAt = date;
        }
    }

    public DatabaseManager(CryptoManager crypto) throws SQLException {
        this.crypto = crypto;
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            System.out.println("Warning: SQLite Driver not found via Class.forName");
        }
        this.connection = DriverManager.getConnection(DB_URL);
        initializeDatabase();
    }

    private void initializeDatabase() throws SQLException {
        Statement stmt = connection.createStatement();
        // Users table
        stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                "user_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT UNIQUE NOT NULL, " +
                "password_hash BLOB NOT NULL, " +
                "salt BLOB NOT NULL, " +
                "is_admin BOOLEAN DEFAULT 0, " +
                "mfa_secret TEXT, " +
                "wrapped_key BLOB, " +
                "key_iv BLOB)");

        // Accounts table
        stmt.execute("CREATE TABLE IF NOT EXISTS accounts (" +
                "account_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "site_name TEXT NOT NULL, " +
                "category TEXT, " +
                "username TEXT, " +
                "encrypted_password BLOB NOT NULL, " +
                "iv BLOB NOT NULL, " +
                "strength_score INTEGER, " +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY (user_id) REFERENCES users(user_id))");

        // History table
        stmt.execute("CREATE TABLE IF NOT EXISTS password_history (" +
                "history_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "account_id INTEGER NOT NULL, " +
                "encrypted_password BLOB NOT NULL, " +
                "iv BLOB NOT NULL, " +
                "changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY (account_id) REFERENCES accounts(account_id))");
    }

    public boolean registerUser(String username, String password, boolean isAdmin) throws Exception {
        return registerUser(username, password, isAdmin, null, null);
    }

    public synchronized boolean registerUser(String username, String password, boolean isAdmin, byte[] wrappedKey,
            byte[] keyIv) throws Exception {
        byte[] salt = crypto.generateSalt();
        byte[] hash = crypto.hashMasterPassword(password, salt); // Storing hash for authentication

        String sql = "INSERT INTO users(username, password_hash, salt, is_admin, wrapped_key, key_iv) VALUES(?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setBytes(2, hash);
            pstmt.setBytes(3, salt);
            pstmt.setBoolean(4, isAdmin);
            pstmt.setBytes(5, wrappedKey);
            pstmt.setBytes(6, keyIv);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                return false; // User exists
            }
            throw e;
        }
    }

    public static class KeyInfo {
        public byte[] wrappedKey;
        public byte[] keyIv;

        public KeyInfo(byte[] wrappedKey, byte[] keyIv) {
            this.wrappedKey = wrappedKey;
            this.keyIv = keyIv;
        }
    }

    public KeyInfo getUserKeyInfo(int userId) throws SQLException {
        String sql = "SELECT wrapped_key, key_iv FROM users WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new KeyInfo(rs.getBytes("wrapped_key"), rs.getBytes("key_iv"));
                }
            }
        }
        return null;
    }

    public boolean updateMFASecret(int userId, String secret) throws SQLException {
        String sql = "UPDATE users SET mfa_secret = ? WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, secret);
            pstmt.setInt(2, userId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public String getMFASecret(int userId) throws SQLException {
        String sql = "SELECT mfa_secret FROM users WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("mfa_secret");
                }
            }
        }
        return null;
    }

    public List<String> getAllUsers() throws SQLException {
        List<String> users = new ArrayList<>();
        String sql = "SELECT username FROM users WHERE is_admin = 0";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                users.add(rs.getString("username"));
            }
        }
        return users;
    }

    public synchronized Integer getUserId(String username) throws SQLException {
        String sql = "SELECT user_id FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("user_id");
            }
        }
        return null;
    }

    public synchronized Integer authenticateUser(String username, String password) throws Exception {
        String sql = "SELECT user_id, password_hash, salt FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                byte[] storedHash = rs.getBytes("password_hash");
                byte[] salt = rs.getBytes("salt");

                // Verify
                byte[] computedHash = crypto.hashMasterPassword(password, salt);
                if (java.util.Arrays.equals(storedHash, computedHash)) {
                    return rs.getInt("user_id");
                }
            }
        }
        return null;
    }

    // Helper to get salt for derivation after interaction
    public byte[] getUserSalt(String username) throws Exception {
        String sql = "SELECT salt FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getBytes("salt");
            }
        }
        return null;
    }

    public synchronized boolean addAccount(int userId, String site, String cat, String username, String password,
            SecretKey key, int score) throws Exception {
        byte[] iv = crypto.generateIV();
        CryptoManager.EncryptedData encData = crypto.encrypt(password, key, iv);

        String sql = "INSERT INTO accounts(user_id, site_name, category, username, encrypted_password, iv, strength_score) VALUES(?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            pstmt.setString(2, site);
            pstmt.setString(3, cat);
            pstmt.setString(4, username);
            pstmt.setBytes(5, encData.encryptedBytes);
            pstmt.setBytes(6, encData.iv);
            pstmt.setInt(7, score);
            pstmt.executeUpdate();
            return true;
        }
    }

    public List<AccountData> getAccounts(int userId) throws SQLException {
        List<AccountData> list = new ArrayList<>();
        String sql = "SELECT * FROM accounts WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                list.add(new AccountData(
                        rs.getInt("account_id"),
                        rs.getString("site_name"),
                        rs.getString("category"),
                        rs.getString("username"),
                        rs.getBytes("encrypted_password"),
                        rs.getBytes("iv"),
                        rs.getInt("strength_score")));
            }
        }
        return list;
    }

    public boolean updateAccountPassword(int accountId, String newPassword, SecretKey key, int score) throws Exception {
        // First get current to save to history
        String getSql = "SELECT encrypted_password, iv FROM accounts WHERE account_id = ?";
        byte[] oldEnc = null;
        byte[] oldIv = null;
        try (PreparedStatement p = connection.prepareStatement(getSql)) {
            p.setInt(1, accountId);
            ResultSet rs = p.executeQuery();
            if (rs.next()) {
                oldEnc = rs.getBytes("encrypted_password");
                oldIv = rs.getBytes("iv");
            }
        }

        if (oldEnc != null) {
            String histSql = "INSERT INTO password_history(account_id, encrypted_password, iv) VALUES(?, ?, ?)";
            try (PreparedStatement p = connection.prepareStatement(histSql)) {
                p.setInt(1, accountId);
                p.setBytes(2, oldEnc);
                p.setBytes(3, oldIv);
                p.executeUpdate();
            }
        }

        byte[] iv = crypto.generateIV();
        CryptoManager.EncryptedData encData = crypto.encrypt(newPassword, key, iv);

        String updateSql = "UPDATE accounts SET encrypted_password = ?, iv = ?, strength_score = ?, updated_at = CURRENT_TIMESTAMP WHERE account_id = ?";
        try (PreparedStatement p = connection.prepareStatement(updateSql)) {
            p.setBytes(1, encData.encryptedBytes);
            p.setBytes(2, encData.iv);
            p.setInt(3, score);
            p.setInt(4, accountId);
            p.executeUpdate();
            return true;
        }
    }

    public List<PasswordHistory> getPasswordHistory(int accountId) throws SQLException {
        List<PasswordHistory> list = new ArrayList<>();
        String sql = "SELECT * FROM password_history WHERE account_id = ? ORDER BY changed_at DESC LIMIT 3";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, accountId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(new PasswordHistory(
                            rs.getBytes("encrypted_password"),
                            rs.getBytes("iv"),
                            rs.getString("changed_at")));
                }
            }
        }
        return list;
    }

    public List<FullUserData> getFullUserSet() throws SQLException {
        List<FullUserData> list = new ArrayList<>();
        String sql = "SELECT * FROM users";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                FullUserData d = new FullUserData();
                d.userId = rs.getInt("user_id");
                d.username = rs.getString("username");
                d.passwordHash = rs.getBytes("password_hash");
                d.salt = rs.getBytes("salt");
                d.isAdmin = rs.getBoolean("is_admin");
                d.mfaSecret = rs.getString("mfa_secret");
                d.wrappedKey = rs.getBytes("wrapped_key");
                d.keyIv = rs.getBytes("key_iv");
                d.accounts = getAccounts(d.userId);
                list.add(d);
            }
        }
        return list;
    }

    public static class FullUserData implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        public int userId;
        public String username;
        public byte[] passwordHash;
        public byte[] salt;
        public boolean isAdmin;
        public String mfaSecret;
        public byte[] wrappedKey;
        public byte[] keyIv;
        public List<AccountData> accounts;
    }

    public void restoreFullUserSet(List<FullUserData> users) throws SQLException {
        // Clear current DB
        Statement stmt = connection.createStatement();
        stmt.execute("DELETE FROM accounts");
        stmt.execute("DELETE FROM users");
        stmt.execute("DELETE FROM password_history");

        String userSql = "INSERT INTO users(user_id, username, password_hash, salt, is_admin, mfa_secret, wrapped_key, key_iv) VALUES(?, ?, ?, ?, ?, ?, ?, ?)";
        String accSql = "INSERT INTO accounts(user_id, site_name, category, username, encrypted_password, iv, strength_score) VALUES(?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement uPstmt = connection.prepareStatement(userSql);
                PreparedStatement aPstmt = connection.prepareStatement(accSql)) {

            for (FullUserData u : users) {
                uPstmt.setInt(1, u.userId);
                uPstmt.setString(2, u.username);
                uPstmt.setBytes(3, u.passwordHash);
                uPstmt.setBytes(4, u.salt);
                uPstmt.setBoolean(5, u.isAdmin);
                uPstmt.setString(6, u.mfaSecret);
                uPstmt.setBytes(7, u.wrappedKey);
                uPstmt.setBytes(8, u.keyIv);
                uPstmt.executeUpdate();

                for (AccountData a : u.accounts) {
                    aPstmt.setInt(1, u.userId);
                    aPstmt.setString(2, a.siteName);
                    aPstmt.setString(3, a.category);
                    aPstmt.setString(4, a.username);
                    aPstmt.setBytes(5, a.encryptedPassword);
                    aPstmt.setBytes(6, a.iv);
                    aPstmt.setInt(7, a.strengthScore);
                    aPstmt.executeUpdate();
                }
            }
        }
    }

    /**
     * Cisco-Grade Database Sanitization:
     * Removes all stress-test artifacts and temporary fuzzing data.
     */
    public synchronized void cleanupTestData() throws SQLException {
        String deleteAccounts = "DELETE FROM accounts WHERE user_id IN (SELECT user_id FROM users WHERE username LIKE 'stress_user_%')";
        String deleteUsers = "DELETE FROM users WHERE username LIKE 'stress_user_%'";
        String deleteFuzz = "DELETE FROM users WHERE username LIKE 'A%' OR username LIKE \"'%;%\" OR username LIKE 'user\\0name'";

        try (Statement stmt = connection.createStatement()) {
            int accountsRemoved = stmt.executeUpdate(deleteAccounts);
            int usersRemoved = stmt.executeUpdate(deleteUsers);
            stmt.executeUpdate(deleteFuzz);
            System.out.println("[🛡️] DB Sanitized: Removed " + usersRemoved + " test users and " + accountsRemoved
                    + " test accounts.");
        }
    }
}
