import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class VaultHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String sessionId = SessionManager.extractSessionId(
                exchange.getRequestHeaders().getFirst("Cookie")
            );

            if (sessionId == null) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                return;
            }

            String email = SessionManager.getUser(sessionId);

            if (email == null) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                return;
            }

            List<PasswordEntry> list = PasswordManager.getPasswords(email);
            StringBuilder rows = new StringBuilder();

            for (PasswordEntry p : list) {
                String strengthClass = p.getStrength().toLowerCase();
                String website = escapeHtml(p.getWebsite());
                String username = escapeHtml(p.getUsername());

                rows.append("<tr>")
                    .append("<td>").append(website).append("</td>")
                    .append("<td>").append(username).append("</td>")
                    .append("<td data-revealed='false'>â€¢â€¢â€¢â€¢â€¢â€¢</td>")
                    .append("<td><span class='badge ")
                    .append(strengthClass)
                    .append("'>")
                    .append(p.getStrength())
                    .append("</span></td>")
                    .append("<td>")
                    .append("<button onclick=\"toggle(this,'")
                    .append(p.getEncryptedPassword().replace("\"", ""))
                    .append("')\">Show</button>")
                    .append("<form action='/editPassword' method='post' style='display:inline;'>")
                    .append("<input type='hidden' name='website' value='")
                    .append(website)
                    .append("'>")
                    .append("<input name='password' placeholder='New'>")
                    .append("<button type='submit'>Update</button>")
                    .append("</form>")
                    .append("</td>")
                    .append("</tr>");
            }

            String html = new String(
                Files.readAllBytes(Paths.get("web/vault.html")),
                StandardCharsets.UTF_8
            );

            html = html.replace("{{ROWS}}", rows.toString());

            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.getResponseHeaders().set("Content-Type", "text/html");

            byte[] response = html.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);

            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        } catch (Exception e) {
            e.printStackTrace();

            String err = "Internal Server Error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}
