import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class LoginHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {

        if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) return;

        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        String email = "", password = "";

        for (String pair : body.split("&")) {
            String[] kv = pair.split("=");
            String val = URLDecoder.decode(kv[1], "UTF-8");

            if (kv[0].equals("email")) email = val;
            if (kv[0].equals("password")) password = val;
        }

        try {
            if (PasswordManager.login(email, password)) {

                String session = SessionManager.createSession(email, password);

                exchange.getResponseHeaders().add("Set-Cookie", "session=" + session + "; Path=/");
                exchange.getResponseHeaders().add("Location", "/dashboard");

                exchange.sendResponseHeaders(302, -1);
                exchange.close();
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String res = "Login failed";
        exchange.sendResponseHeaders(200, res.length());
        exchange.getResponseBody().write(res.getBytes());
        exchange.close();
    }
}