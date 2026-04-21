import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class TwoFactorPageHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            Map<String, String> query = RequestUtil.parseQuery(exchange.getRequestURI().getRawQuery());
            String token = query.getOrDefault("token", "");
            PendingLogin pendingLogin = PendingLoginStore.get(token);

            if (pendingLogin == null) {
                sendHtml(exchange, 404, page("Verification expired", "<p class=\"helper-text\">Please log in again.</p><a class=\"action-link\" href=\"/\">Back to login</a>"));
                return;
            }

            String safeToken = WebUtils.escapeHtml(token);
            String safeCode = WebUtils.escapeHtml(pendingLogin.getCode());
            String speed = pendingLogin.getRiskResult().getSpeedKmph() == null
                ? "unknown"
                : String.format("%.2f km/hr", pendingLogin.getRiskResult().getSpeedKmph());

            String body =
                "<p class=\"helper-text\">A high-risk login was detected from a new location. Complete verification before opening the vault.</p>" +
                "<div class=\"alert-card\">" +
                "<div class=\"eyebrow\">Demo verification code</div>" +
                "<strong>" + safeCode + "</strong>" +
                "<p class=\"helper-text\">No email/SMS API is used in this project, so the demo code is shown here. Production apps deliver this by email, SMS, or authenticator app.</p>" +
                "<p class=\"helper-text\">Estimated travel speed: " + WebUtils.escapeHtml(speed) + "</p>" +
                "</div>" +
                "<form action=\"/submit2fa\" method=\"post\">" +
                "<input type=\"hidden\" name=\"token\" value=\"" + safeToken + "\">" +
                "<input type=\"text\" name=\"code\" placeholder=\"Enter 6-digit code\" required>" +
                "<button type=\"submit\">Verify and Continue</button>" +
                "</form>";

            sendHtml(exchange, 200, page("Two-Factor Verification", body));
        } catch (Exception e) {
            e.printStackTrace();
            sendHtml(exchange, 500, page("Verification failed", "<p class=\"helper-text\">Please try logging in again.</p>"));
        } finally {
            exchange.close();
        }
    }

    private static String page(String title, String body) {
        return "<!DOCTYPE html><html><head><title>" + WebUtils.escapeHtml(title) + "</title>" +
            "<link rel=\"stylesheet\" href=\"style.css\"></head><body>" +
            "<div class=\"sidebar\"><div class=\"logo\">PassVault</div><div class=\"nav\"><a href=\"/\">Login</a></div></div>" +
            "<div class=\"main\"><div class=\"card\"><h2>" + WebUtils.escapeHtml(title) + "</h2>" + body + "</div></div>" +
            "</body></html>";
    }

    private static void sendHtml(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] data = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, data.length);
        exchange.getResponseBody().write(data);
    }
}
