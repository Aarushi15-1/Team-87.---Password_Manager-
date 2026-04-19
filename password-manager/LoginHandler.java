import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class LoginHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String email = "";
            String password = "";

            for (String pair : body.split("&")) {
                String[] kv = pair.split("=", 2);
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";

                if (key.equals("email")) email = val;
                if (key.equals("password")) password = val;
            }

            if (PasswordManager.login(email, password)) {

                String session = SessionManager.createSession(email, password);

                exchange.getResponseHeaders().add("Set-Cookie", "session=" + session + "; Path=/");
                exchange.getResponseHeaders().add("Location", "/dashboard");

                exchange.sendResponseHeaders(302, -1);
                return;
            }

            String res = "Login failed";
            exchange.sendResponseHeaders(200, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            String res = "Login failed";
            exchange.sendResponseHeaders(500, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }
}
