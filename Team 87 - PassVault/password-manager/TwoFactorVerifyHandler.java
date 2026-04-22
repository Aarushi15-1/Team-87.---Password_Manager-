import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class TwoFactorVerifyHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            Map<String, String> form = RequestUtil.parseFormBody(exchange);
            PendingLogin pendingLogin = LoginSecurityManager.completePendingLogin(
                form.getOrDefault("token", ""),
                form.getOrDefault("code", "")
            );

            if (pendingLogin == null) {
                sendText(exchange, 401, "Invalid verification code. Please go back and try again.");
                return;
            }

            String session = SessionManager.createSession(
                pendingLogin.getEmail(),
                pendingLogin.getVaultKey()
            );
            exchange.getResponseHeaders().add(
                "Set-Cookie",
                "session=" + session + "; Path=/; HttpOnly; SameSite=Lax"
            );
            exchange.getResponseHeaders().add("Location", "/dashboard");
            exchange.sendResponseHeaders(302, -1);
        } catch (Exception e) {
            e.printStackTrace();
            sendText(exchange, 500, "Verification failed");
        } finally {
            exchange.close();
        }
    }

    private static void sendText(HttpExchange exchange, int statusCode, String text) throws IOException {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, data.length);
        exchange.getResponseBody().write(data);
    }
}
