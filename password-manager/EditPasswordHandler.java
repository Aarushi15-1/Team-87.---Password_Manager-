import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class EditPasswordHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        try {
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");

            if (cookie == null || !cookie.contains("session=")) {
                redirect(exchange);
                return;
            }

            String sessionId = cookie.split("=")[1];
            String email = SessionManager.getUser(sessionId);
            String key = SessionManager.getKey(sessionId);

            if (email == null) {
                redirect(exchange);
                return;
            }

            String body = new String(
                    exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8
            );

            String website = "", password = "";

            for (String pair : body.split("&")) {
                String[] kv = pair.split("=");
                String val = URLDecoder.decode(kv[1], "UTF-8");

                if (kv[0].equals("website")) website = val;
                if (kv[0].equals("password")) password = val;
            }

            // 🔥 UPDATE PASSWORD (with strength recalculation)
            PasswordManager.updatePassword(email, website, password, key);

            // ✅ SINGLE RESPONSE → redirect
            redirect(exchange);

        } catch (Exception e) {
            e.printStackTrace();

            String err = "Update failed";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes());
            exchange.close();
        }
    }

    // 🔁 helper to avoid duplicate header calls
    private void redirect(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("Location", "/vault");
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }
}