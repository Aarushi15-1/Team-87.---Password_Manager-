import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class DBConnection {
    private static final String URL = "jdbc:mysql://mysql:3306/projectdb";
    private static final String USER = "root";
    private static final String PASSWORD = "rootpassword";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("MySQL JDBC driver is missing from the classpath.", e);
        }
    }

    public static Connection getConnection() throws Exception {
        return DriverManager.getConnection(URL, USER, PASSWORD);
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
        }
    }
}
