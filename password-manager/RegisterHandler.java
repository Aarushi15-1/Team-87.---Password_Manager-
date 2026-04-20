import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class RegisterHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            Map<String, String> form = RequestUtil.parseFormBody(exchange);
            String email = form.getOrDefault("email", "");
            String password = form.getOrDefault("password", "");

            PasswordManager.register(email, password);
            exchange.getResponseHeaders().add("Location", "/");
            exchange.sendResponseHeaders(302, -1);
        } catch (Exception e) {
            e.printStackTrace();
            String res = "Registration failed";
            exchange.sendResponseHeaders(500, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }
}
