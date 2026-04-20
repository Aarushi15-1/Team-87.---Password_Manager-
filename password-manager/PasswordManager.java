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
        String sql = "INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?)";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setString(2, salt);
            ps.setString(3, hash);
            ps.executeUpdate();
        }
    }

    public static LoginResult login(String email, String password) throws Exception {
        String sql = "SELECT salt, password_hash FROM users WHERE email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

                String salt = rs.getString("salt");
                String storedHash = rs.getString("password_hash");

                if (!HashUtil.verifyPassword(password, salt, storedHash)) {
                    return null;
                }

                if (!HashUtil.isPbkdf2Hash(storedHash)) {
                    upgradeLegacyHash(conn, email, password, salt);
                }

                String vaultKey = HashUtil.deriveVaultKey(password, salt);
                String legacyVaultKey = EncryptionUtil.deriveLegacyVaultKey(password, salt);

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
}
