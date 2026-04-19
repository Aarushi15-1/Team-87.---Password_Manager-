import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class VaultHandler implements HttpHandler {

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

            String sessionId = null;
            for (String c : cookie.split(";")) {
                if (c.trim().startsWith("session=")) {
                    sessionId = c.split("=")[1];
                }
            }

            String email = SessionManager.getUser(sessionId);

            if (email == null) {
                exchange.getResponseHeaders().add("Location", "/");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
                return;
            }

            List<PasswordEntry> list = PasswordManager.getPasswords(email);
            StringBuilder rows = new StringBuilder();

            for (PasswordEntry p : list) {
                String strengthClass = p.getStrength().toLowerCase();
                String safeWebsite = WebUtils.escapeHtml(p.getWebsite());
                String safeUsername = WebUtils.escapeHtml(p.getUsername());
                String safeStrength = WebUtils.escapeHtml(p.getStrength());
                String encodedWebsite = URLEncoder.encode(p.getWebsite(), StandardCharsets.UTF_8);

                rows.append("<tr>")
                    .append("<td>").append(safeWebsite).append("</td>")
                    .append("<td>").append(safeUsername).append("</td>")
                    .append("<td data-revealed='false'>******</td>")
                    .append("<td><span class='badge ")
                    .append(strengthClass)
                    .append("'>")
                    .append(safeStrength)
                    .append("</span></td>")
                    .append("<td>")
                    .append("<button onclick=\"toggle(this,'")
                    .append(p.getEncryptedPassword().replace("\"", ""))
                    .append("')\">Show</button>")
                    .append("<a class='action-link' href='/phishing?url=")
                    .append(encodedWebsite)
                    .append("'>Scan</a>")
                    .append("<form action='/editPassword' method='post' style='display:inline;'>")
                    .append("<input type='hidden' name='website' value='")
                    .append(safeWebsite)
                    .append("'>")
                    .append("<input name='password' placeholder='New'>")
                    .append("<button type='submit'>Update</button>")
                    .append("</form>")
                    .append("</td>")
                    .append("</tr>");
            }

            String html = new String(
                java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("web/vault.html")
                ),
                StandardCharsets.UTF_8
            );

            html = html.replace("{{ROWS}}", rows.toString());

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
