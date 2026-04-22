import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class AddPasswordHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String session = SessionManager.extractSessionId(
                exchange.getRequestHeaders().getFirst("Cookie")
            );
            String email = SessionManager.getUser(session);
            String vaultKey = SessionManager.getVaultKey(session);

            if (email == null || vaultKey == null) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                return;
            }

            Map<String, String> form = RequestUtil.parseFormBody(exchange);
            String website = form.getOrDefault("website", "");
            String username = form.getOrDefault("username", "");
            String password = form.getOrDefault("password", "");

            PasswordManager.savePassword(email, website, username, password, vaultKey);

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
