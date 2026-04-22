import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class RevealHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            String session = SessionManager.extractSessionId(
                exchange.getRequestHeaders().getFirst("Cookie")
            );
            String vaultKey = SessionManager.getVaultKey(session);

            if (vaultKey == null) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }

            Map<String, String> query = RequestUtil.parseQuery(exchange.getRequestURI().getQuery());
            String encrypted = query.get("data");

            if (encrypted == null) {
                throw new Exception("Missing data");
            }

            String decrypted = EncryptionUtil.decrypt(encrypted, vaultKey);

            byte[] response = decrypted.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
        } catch (Exception e) {
            e.printStackTrace();

            String err = "Decryption failed";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }
}
