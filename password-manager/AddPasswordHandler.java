import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class AddPasswordHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {

        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

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

            String website = "", username = "", password = "";

            for (String pair : body.split("&")) {
                String[] kv = pair.split("=", 2);
                String keyName = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";

                if (keyName.equals("website")) website = val;
                if (keyName.equals("username")) username = val;
                if (keyName.equals("password")) password = val;
            }

            PasswordManager.savePassword(email, website, username, password, key);

            exchange.getResponseHeaders().add("Location", "/vault");
            exchange.sendResponseHeaders(302, -1);

        } catch (Exception e) {
            e.printStackTrace();
            String res = "Save failed";
            exchange.sendResponseHeaders(500, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }
}
