import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
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
            WebUtils.redirectWithFlash(exchange, "/", "register", "success", "Registration successful. Please log in.");
        } catch (AuthException e) {
            WebUtils.redirectWithFlash(exchange, "/", "register", "error", e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            WebUtils.redirectWithFlash(exchange, "/", "register", "error", "Registration failed. Please try again.");
        } finally {
            exchange.close();
        }
    }
}
