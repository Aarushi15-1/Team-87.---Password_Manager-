import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class DashboardHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");

            if (cookie == null || !cookie.contains("session=")) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
                return;
            }

            String sessionId = cookie.split("=")[1];
            String email = SessionManager.getUser(sessionId);

            if (email == null) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
                return;
            }

            List<PasswordEntry> list = PasswordManager.getPasswords(email);
            int total = list.size();
            int weak = 0;

            for (PasswordEntry p : list) {
                if (p.getStrength().equalsIgnoreCase("Weak")) {
                    weak++;
                }
            }

            String html = new String(
                java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("web/dashboard.html")
                ),
                StandardCharsets.UTF_8
            );

            html = html.replace("{{TOTAL}}", String.valueOf(total));
            html = html.replace("{{WEAK}}", String.valueOf(weak));

            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");

            byte[] response = html.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);

            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        } catch (Exception e) {
            e.printStackTrace();

            String err = "Internal Server Error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes(StandardCharsets.UTF_8));
            exchange.close();
        }
    }
}
