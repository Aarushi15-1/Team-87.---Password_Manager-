import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PasswordManager {

    public static final class LoginResult {
        private final String email;
        private final String vaultKey;
        private final String legacyVaultKey;

        public LoginResult(String email, String vaultKey, String legacyVaultKey) {
            this.email = email;
            this.vaultKey = vaultKey;
            this.legacyVaultKey = legacyVaultKey;
        }

        public String getEmail() {
            return email;
        }

        public String getVaultKey() {
            return vaultKey;
        }

        public String getLegacyVaultKey() {
            return legacyVaultKey;
        }
    }

    public static void register(String email, String password) throws Exception {
        String salt = HashUtil.generateSalt();
        String hash = HashUtil.hashPassword(password, salt);
        String wrapSalt = HashUtil.generateSalt();
        String wrappingKey = HashUtil.deriveWrappingKey(password, wrapSalt);
        String vaultKey = EncryptionUtil.generateVaultKey();
        String wrappedVaultKey = EncryptionUtil.wrapVaultKey(vaultKey, wrappingKey);
        String sql =
            "INSERT INTO users (email, salt, password_hash, wrap_salt, wrapped_vault_key, wrap_kdf_algorithm, wrap_kdf_iterations) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setString(2, salt);
            ps.setString(3, hash);
            ps.setString(4, wrapSalt);
            ps.setString(5, wrappedVaultKey);
            ps.setString(6, HashUtil.getPasswordKdfAlgorithm());
            ps.setInt(7, HashUtil.getDefaultIterations());
            ps.executeUpdate();
        }
    }

    public static LoginResult login(String email, String password) throws Exception {
        String sql =
            "SELECT salt, password_hash, wrap_salt, wrapped_vault_key, wrap_kdf_algorithm, wrap_kdf_iterations " +
            "FROM users WHERE email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

                String salt = rs.getString("salt");
                String storedHash = rs.getString("password_hash");
                String wrapSalt = rs.getString("wrap_salt");
                String wrappedVaultKey = rs.getString("wrapped_vault_key");

                if (!HashUtil.verifyPassword(password, salt, storedHash)) {
                    return null;
                }

                boolean needsHashUpgrade = !HashUtil.isPbkdf2Hash(storedHash);
                String directVaultKey = HashUtil.deriveVaultKey(password, salt);
                String legacyVaultKey = EncryptionUtil.deriveLegacyVaultKey(password, salt);

                if (needsHashUpgrade || isWrappedVaultKeyMissing(wrapSalt, wrappedVaultKey)) {
                    directVaultKey = upgradeUserCryptoModel(
                        conn,
                        email,
                        password,
                        salt,
                        directVaultKey,
                        legacyVaultKey,
                        needsHashUpgrade
                    );
                    wrapSalt = getWrapSalt(conn, email);
                    wrappedVaultKey = getWrappedVaultKey(conn, email);
                }

                String wrappingKey = HashUtil.deriveWrappingKey(password, wrapSalt);
                String vaultKey = EncryptionUtil.unwrapVaultKey(wrappedVaultKey, wrappingKey);

                return new LoginResult(email, vaultKey, legacyVaultKey);
            }
        }
    }

    public static void savePassword(String email, String website, String username, String password, String vaultKey) throws Exception {
        String encrypted = EncryptionUtil.encrypt(password, vaultKey);
        String strength = PasswordStrength.getStrength(password);

        String sql = "INSERT INTO passwords (user_email, website, username, encrypted_password, strength) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setString(2, website);
            ps.setString(3, username);
            ps.setString(4, encrypted);
            ps.setString(5, strength);
            ps.executeUpdate();
        }
    }

    public static List<PasswordEntry> getPasswords(String email) throws Exception {
        List<PasswordEntry> list = new ArrayList<>();
        String sql = "SELECT website, username, encrypted_password, strength FROM passwords WHERE user_email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    PasswordEntry entry = new PasswordEntry(
                        rs.getString("website"),
                        rs.getString("username"),
                        rs.getString("encrypted_password"),
                        rs.getString("strength")
                    );
                    list.add(entry);
                }
            }
        }

        return list;
    }

    public static int countReusedPasswords(List<PasswordEntry> list) {
        Set<String> seen = new HashSet<>();
        int reused = 0;

        for (PasswordEntry p : list) {
            String enc = p.getEncryptedPassword();

            if (!seen.add(enc)) {
                reused++;
            }
        }

        return reused;
    }

    public static void updatePassword(String email, String website, String newPassword, String vaultKey) throws Exception {
        String encrypted = EncryptionUtil.encrypt(newPassword, vaultKey);
        String strength = PasswordStrength.getStrength(newPassword);

        String sql = "UPDATE passwords SET encrypted_password = ?, strength = ? WHERE user_email = ? AND website = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, encrypted);
            ps.setString(2, strength);
            ps.setString(3, email);
            ps.setString(4, website);
            ps.executeUpdate();
        }
    }

    private static void upgradeLegacyHash(Connection conn, String email, String password, String salt) throws SQLException {
        String sql = "UPDATE users SET password_hash = ? WHERE email = ?";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, HashUtil.hashPassword(password, salt));
            ps.setString(2, email);
            ps.executeUpdate();
        }
    }

    private static boolean isWrappedVaultKeyMissing(String wrapSalt, String wrappedVaultKey) {
        return wrapSalt == null || wrapSalt.isBlank() || wrappedVaultKey == null || wrappedVaultKey.isBlank();
    }

    private static String upgradeUserCryptoModel(
        Connection conn,
        String email,
        String password,
        String salt,
        String directVaultKey,
        String legacyVaultKey,
        boolean needsHashUpgrade
    ) throws Exception {
        boolean originalAutoCommit = conn.getAutoCommit();

        try {
            conn.setAutoCommit(false);

            if (needsHashUpgrade) {
                upgradeLegacyHash(conn, email, password, salt);
            }

            String wrapSalt = HashUtil.generateSalt();
            String wrappingKey = HashUtil.deriveWrappingKey(password, wrapSalt);
            String newVaultKey = EncryptionUtil.generateVaultKey();
            String wrappedVaultKey = EncryptionUtil.wrapVaultKey(newVaultKey, wrappingKey);

            migratePasswordEntries(conn, email, directVaultKey, legacyVaultKey, newVaultKey);
            storeWrappedVaultKey(conn, email, wrapSalt, wrappedVaultKey);

            conn.commit();
            return newVaultKey;
        } catch (Exception e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(originalAutoCommit);
        }
    }

    private static void migratePasswordEntries(
        Connection conn,
        String email,
        String directVaultKey,
        String legacyVaultKey,
        String newVaultKey
    ) throws Exception {
        String selectSql = "SELECT id, encrypted_password FROM passwords WHERE user_email = ?";
        String updateSql = "UPDATE passwords SET encrypted_password = ? WHERE id = ?";

        try (PreparedStatement select = conn.prepareStatement(selectSql);
             PreparedStatement update = conn.prepareStatement(updateSql)) {

            select.setString(1, email);

            try (ResultSet rs = select.executeQuery()) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String encrypted = rs.getString("encrypted_password");
                    String plainText = EncryptionUtil.decrypt(encrypted, directVaultKey, legacyVaultKey);
                    String reEncrypted = EncryptionUtil.encrypt(plainText, newVaultKey);

                    update.setString(1, reEncrypted);
                    update.setInt(2, id);
                    update.addBatch();
                }
            }

            update.executeBatch();
        }
    }

    private static void storeWrappedVaultKey(Connection conn, String email, String wrapSalt, String wrappedVaultKey) throws SQLException {
        String sql =
            "UPDATE users SET wrap_salt = ?, wrapped_vault_key = ?, wrap_kdf_algorithm = ?, wrap_kdf_iterations = ? " +
            "WHERE email = ?";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, wrapSalt);
            ps.setString(2, wrappedVaultKey);
            ps.setString(3, HashUtil.getPasswordKdfAlgorithm());
            ps.setInt(4, HashUtil.getDefaultIterations());
            ps.setString(5, email);
            ps.executeUpdate();
        }
    }

    private static String getWrapSalt(Connection conn, String email) throws SQLException {
        return getUserCryptoField(conn, email, "wrap_salt");
    }

    private static String getWrappedVaultKey(Connection conn, String email) throws SQLException {
        return getUserCryptoField(conn, email, "wrapped_vault_key");
    }

    private static String getUserCryptoField(Connection conn, String email, String columnName) throws SQLException {
        String sql = "SELECT " + columnName + " FROM users WHERE email = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(columnName) : null;
            }
        }
    }
}
