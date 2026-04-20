import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DBConnection {
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
                "password_hash VARCHAR(255) NOT NULL)"
            );

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
        }
    }
}
