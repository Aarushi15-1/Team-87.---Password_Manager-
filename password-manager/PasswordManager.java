import java.sql.*;
import java.util.*;

public class PasswordManager {

    // ------------------ REGISTER ------------------
    public static void register(String email, String password) throws Exception {
        String salt = HashUtil.generateSalt();
        String hash = HashUtil.hash(password, salt);

        String sql = "INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?)";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setString(2, salt);
            ps.setString(3, hash);
            ps.executeUpdate();
        }
    }

    // ------------------ LOGIN ------------------
    public static boolean login(String email, String password) throws Exception {
        String sql = "SELECT salt, password_hash FROM users WHERE email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String salt = rs.getString("salt");
                    String storedHash = rs.getString("password_hash");

                    String hash = HashUtil.hash(password, salt);
                    return hash.equals(storedHash);
                }
            }
        }

        return false;
    }

    // ------------------ SAVE PASSWORD ------------------
    public static void savePassword(String email, String website, String username, String password, String key) throws Exception {
        String encrypted = EncryptionUtil.encrypt(password, key);
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

    // ------------------ GET PASSWORDS ------------------
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

    // ------------------ GET SALT ------------------
    public static String getSalt(String email) throws Exception {
        String sql = "SELECT salt FROM users WHERE email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("salt");
                }
            }
        }

        return null;
    }

    // ------------------ DSA: REUSE DETECTION ------------------
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

    // ------------------ UPDATE PASSWORD ------------------
    public static void updatePassword(String email, String website, String newPassword, String key) throws Exception {
        String encrypted = EncryptionUtil.encrypt(newPassword, key);
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

    // ------------------ DERIVE KEY ------------------
    public static String deriveKey(String email, String password) throws Exception {
        String salt = getSalt(email);

        String value = password + ":" + salt;

        for (int i = 0; i < 1000; i++) {
            value = HashUtil.hash(value + i, "");

            if (i % 100 == 0) {
                value = HashUtil.hash(value + salt, "");
            }
        }

        return value.substring(0, 16);
    }
}