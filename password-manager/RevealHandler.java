import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;

public class RevealHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {

        try {
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");

            String session = null;
            for (String c : cookie.split(";")) {
                if (c.trim().startsWith("session=")) {
                    session = c.split("=")[1];
                }
            }

            String email = SessionManager.getUser(session);
            String masterPassword = SessionManager.getPassword(session);

            String key = PasswordManager.deriveKey(email, masterPassword);

            String query = exchange.getRequestURI().getQuery();
            String encrypted = URLDecoder.decode(query.substring(5), "UTF-8");

            String decrypted = EncryptionUtil.decrypt(encrypted, key);

            exchange.sendResponseHeaders(200, decrypted.length());
            exchange.getResponseBody().write(decrypted.getBytes());
            exchange.close();

        } catch (Exception e) {
            e.printStackTrace();

            String err = "Decryption failed";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes());
            exchange.close();
        }
    }
}