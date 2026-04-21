import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DBConnection {
    private static final String AUTH_DATA_RESET_VERSION = getEnv("AUTH_DATA_RESET_VERSION", "2026-04-21-auth-reset");
    private static final String[] HOSTS = {
        getEnv("DB_HOST", "mysql"),
        "127.0.0.1",
        "localhost"
    };
    private static final String PORT = getEnv("DB_PORT", "3306");
    private static final String DATABASE = getEnv("DB_NAME", "projectdb");
    private static final String USER = getEnv("DB_USER", "root");
    private static final String PASSWORD = getEnv("DB_PASSWORD", "rootpassword");
    private static final String PARAMETERS =
        "?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&connectTimeout=5000&socketTimeout=10000";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("MySQL JDBC driver is missing from the classpath.", e);
        }
    }

    public static Connection getConnection() throws Exception {
        SQLException lastException = null;

        for (String host : HOSTS) {
            String url = "jdbc:mysql://" + host + ":" + PORT + "/" + DATABASE + PARAMETERS;
            try {
                DriverManager.setLoginTimeout(5);
                return DriverManager.getConnection(url, USER, PASSWORD);
            } catch (SQLException e) {
                lastException = e;
            }
        }

        throw lastException != null ? lastException : new SQLException("Unable to connect to MySQL.");
    }

    private static String getEnv(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    public static void initializeDatabase() throws Exception {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS users (" +
                "email VARCHAR(255) PRIMARY KEY, " +
                "salt VARCHAR(255) NOT NULL, " +
                "password_hash VARCHAR(255) NOT NULL, " +
                "wrap_salt VARCHAR(255) NULL, " +
                "wrapped_vault_key TEXT NULL, " +
                "wrap_kdf_algorithm VARCHAR(50) NULL, " +
                "wrap_kdf_iterations INT NULL)"
            );
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS app_meta (" +
                "meta_key VARCHAR(100) PRIMARY KEY, " +
                "meta_value VARCHAR(255) NOT NULL)"
            );
            ensureColumn(stmt, "users", "wrap_salt", "VARCHAR(255) NULL");
            ensureColumn(stmt, "users", "wrapped_vault_key", "TEXT NULL");
            ensureColumn(stmt, "users", "wrap_kdf_algorithm", "VARCHAR(50) NULL");
            ensureColumn(stmt, "users", "wrap_kdf_iterations", "INT NULL");

            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS passwords (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "user_email VARCHAR(255) NOT NULL, " +
                "website VARCHAR(255) NOT NULL, " +
                "username VARCHAR(255) NOT NULL, " +
                "encrypted_password TEXT NOT NULL, " +
                "strength VARCHAR(50) NOT NULL, " +
                "FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE)"
            );

            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS phishing_scans (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "user_email VARCHAR(255) NOT NULL, " +
                "url TEXT NOT NULL, " +
                "score INT NOT NULL, " +
                "verdict VARCHAR(50) NOT NULL, " +
                "detail TEXT NOT NULL, " +
                "reasons TEXT NOT NULL, " +
                "scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE)"
            );

            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS login_history (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "user_email VARCHAR(255) NOT NULL, " +
                "latitude DOUBLE NULL, " +
                "longitude DOUBLE NULL, " +
                "login_time_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "speed_kmph DOUBLE NULL, " +
                "risk_status VARCHAR(50) NOT NULL, " +
                "FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE)"
            );

            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS login_security (" +
                "user_email VARCHAR(255) PRIMARY KEY, " +
                "failed_attempts INT NOT NULL DEFAULT 0, " +
                "suspension_level INT NOT NULL DEFAULT 0, " +
                "suspended_until_utc TIMESTAMP NULL, " +
                "two_factor_required BOOLEAN NOT NULL DEFAULT FALSE, " +
                "two_factor_code VARCHAR(20) NULL, " +
                "FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE)"
            );

            resetAuthDataIfNeeded(conn);
        }
    }

    private static void ensureColumn(Statement stmt, String tableName, String columnName, String definition) throws SQLException {
        try {
            stmt.executeUpdate("ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " " + definition);
        } catch (SQLException e) {
            String message = e.getMessage();
            if (message == null || !message.toLowerCase().contains("duplicate column")) {
                throw e;
            }
        }
    }

    private static void resetAuthDataIfNeeded(Connection conn) throws SQLException {
        String appliedVersion = readMetaValue(conn, "auth_data_reset_version");
        if (AUTH_DATA_RESET_VERSION.equals(appliedVersion)) {
            return;
        }

        boolean originalAutoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);

        try (Statement stmt = conn.createStatement()) {
            // One-time cleanup so older accounts do not survive the new auth rules rollout.
            stmt.executeUpdate("DELETE FROM phishing_scans");
            stmt.executeUpdate("DELETE FROM passwords");
            stmt.executeUpdate("DELETE FROM users");
            stmt.executeUpdate("ALTER TABLE phishing_scans AUTO_INCREMENT = 1");
            stmt.executeUpdate("ALTER TABLE passwords AUTO_INCREMENT = 1");
            upsertMetaValue(conn, "auth_data_reset_version", AUTH_DATA_RESET_VERSION);
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(originalAutoCommit);
        }
    }

    private static String readMetaValue(Connection conn, String key) throws SQLException {
        String sql = "SELECT meta_value FROM app_meta WHERE meta_key = ?";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, key);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("meta_value");
                }
            }
        }

        return null;
    }

    private static void upsertMetaValue(Connection conn, String key, String value) throws SQLException {
        String sql =
            "INSERT INTO app_meta (meta_key, meta_value) VALUES (?, ?) " +
            "ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        }
    }
}
