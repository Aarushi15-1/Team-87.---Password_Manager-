import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.util.Map;

public class EditPasswordHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
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
            String password = form.getOrDefault("password", "");

            PasswordManager.updatePassword(email, website, password, vaultKey);

            exchange.getResponseHeaders().add("Location", "/vault");
            exchange.sendResponseHeaders(302, -1);
        } catch (Exception e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
        } finally {
            exchange.close();
        }
    }
}
