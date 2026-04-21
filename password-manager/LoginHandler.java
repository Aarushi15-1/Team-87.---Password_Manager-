import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
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
                    login.getVaultKey()
                );

                exchange.getResponseHeaders().add(
                    "Set-Cookie",
                    "session=" + session + "; Path=/; HttpOnly; SameSite=Lax"
                );
                exchange.getResponseHeaders().add("Location", "/dashboard");

                exchange.sendResponseHeaders(302, -1);
                return;
            }

            WebUtils.redirectWithFlash(exchange, "/", "login", "error", "Incorrect email or password.");
        } catch (AuthException e) {
            WebUtils.redirectWithFlash(exchange, "/", "login", "error", e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            WebUtils.redirectWithFlash(exchange, "/", "login", "error", "Login failed. Please try again.");
        } finally {
            exchange.close();
        }
    }
}
