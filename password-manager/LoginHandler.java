import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class LoginHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            Map<String, String> form = RequestUtil.parseFormBody(exchange);
            String email = form.getOrDefault("email", "");
            String password = form.getOrDefault("password", "");

            PasswordManager.LoginResult login = PasswordManager.login(email, password);
            if (login != null) {
                String session = SessionManager.createSession(
                    login.getEmail(),
                    login.getVaultKey(),
                    login.getLegacyVaultKey()
                );

                exchange.getResponseHeaders().add(
                    "Set-Cookie",
                    "session=" + session + "; Path=/; HttpOnly; SameSite=Lax"
                );
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
