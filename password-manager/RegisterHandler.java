import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class RegisterHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {

        if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        String email = "", password = "";

        for (String pair : body.split("&")) {
            String[] kv = pair.split("=");
            String val = URLDecoder.decode(kv[1], "UTF-8");

            if (kv[0].equals("email")) email = val;
            if (kv[0].equals("password")) password = val;
        }

        try {
            PasswordManager.register(email, password);
        } catch (Exception e) {
            e.printStackTrace();
        }

        exchange.getResponseHeaders().add("Location", "/");
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }
}
