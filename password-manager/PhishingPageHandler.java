import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class PhishingPageHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String sessionId = WebUtils.getSessionId(exchange);
            String email = SessionManager.getUser(sessionId);

            if (email == null) {
                WebUtils.redirect(exchange, "/");
                return;
            }

            String prefillUrl = getQueryValue(exchange.getRequestURI().getQuery(), "url");
            List<PhishingScan> scans = PhishingService.getRecentScans(email, 10);

            String html = new String(Files.readAllBytes(Paths.get("web/phishing.html")), StandardCharsets.UTF_8);
            html = html.replace("{{PREFILL_URL}}", WebUtils.escapeHtml(prefillUrl));
            html = html.replace("{{HISTORY_ROWS}}", buildHistoryRows(scans));

            byte[] response = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        } catch (Exception e) {
            e.printStackTrace();
            String err = "Internal Server Error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes(StandardCharsets.UTF_8));
            exchange.close();
        }
    }

    private String buildHistoryRows(List<PhishingScan> scans) {
        if (scans.isEmpty()) {
            return "<tr><td colspan='4'>No phishing scans yet. Analyze a URL to create history.</td></tr>";
        }

        StringBuilder rows = new StringBuilder();
        for (PhishingScan scan : scans) {
            rows.append("<tr>")
                .append("<td>").append(WebUtils.escapeHtml(scan.getUrl())).append("</td>")
                .append("<td><span class='badge ").append(verdictClass(scan.getScore())).append("'>")
                .append(WebUtils.escapeHtml(scan.getVerdict())).append("</span></td>")
                .append("<td>").append(scan.getScore()).append("</td>")
                .append("<td>").append(WebUtils.escapeHtml(scan.getScannedAt())).append("</td>")
                .append("</tr>");
        }
        return rows.toString();
    }

    private String verdictClass(int score) {
        if (score <= 0) return "strong";
        if (score <= 5) return "medium";
        if (score <= 10) return "weak";
        return "critical";
    }

    private String getQueryValue(String query, String key) throws IOException {
        if (query == null || query.isBlank()) {
            return "";
        }

        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            String currentKey = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            if (currentKey.equals(key)) {
                return kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            }
        }

        return "";
    }
}
