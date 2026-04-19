import com.sun.net.httpserver.*;
import java.io.*;
import java.util.*;

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

            // 🔥 SAFE COOKIE PARSE
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

                rows.append("<tr>")
                    .append("<td>").append(p.getWebsite()).append("</td>")
                    .append("<td>").append(p.getUsername()).append("</td>")

                    // 🔐 Hidden password
                    .append("<td data-revealed='false'>••••••</td>")

                    // 🏷️ Strength
                    .append("<td><span class='badge ")
                    .append(strengthClass)
                    .append("'>")
                    .append(p.getStrength())
                    .append("</span></td>")

                    // ⚡ Actions
                    .append("<td>")

                    // 🔥 ESCAPE ENCRYPTED STRING
                    .append("<button onclick=\"toggle(this,'")
                    .append(p.getEncryptedPassword().replace("\"", ""))
                    .append("')\">Show</button>")

                    // ✏️ Edit
                    .append("<form action='/editPassword' method='post' style='display:inline;'>")
                    .append("<input type='hidden' name='website' value='")
                    .append(p.getWebsite())
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
                )
            );

            html = html.replace("{{ROWS}}", rows.toString());

            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.getResponseHeaders().set("Content-Type", "text/html");

            byte[] response = html.getBytes();

            exchange.sendResponseHeaders(200, response.length);

            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();

        } catch (Exception e) {
            e.printStackTrace();

            String err = "Internal Server Error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes());
            exchange.close();
        }
    }
}