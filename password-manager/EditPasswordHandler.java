import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class EditPasswordHandler implements HttpHandler {

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

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            String website = "", password = "";

            for (String pair : body.split("&")) {
                String[] kv = pair.split("=");
                String val = URLDecoder.decode(kv[1], "UTF-8");

                if (kv[0].equals("website")) website = val;
                if (kv[0].equals("password")) password = val;
            }

            PasswordManager.updatePassword(email, website, password, key);

            exchange.getResponseHeaders().add("Location", "/vault");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}