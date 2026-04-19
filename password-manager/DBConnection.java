import java.sql.Connection;
import java.sql.DriverManager;

public class DBConnection {
    private static final String URL = "jdbc:mysql://mysql:3306/projectdb";
    private static final String USER = "root";
    private static final String PASSWORD = "rootpassword";

    public static Connection getConnection() throws Exception {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }
}