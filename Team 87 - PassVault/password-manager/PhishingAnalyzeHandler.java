import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class PhishingAnalyzeHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                WebUtils.sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }

            String sessionId = WebUtils.getSessionId(exchange);
            String email = SessionManager.getUser(sessionId);
            if (email == null) {
                WebUtils.sendJson(exchange, 401, "{\"error\":\"Unauthorized\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = WebUtils.parseFormBody(body);
            String url = form.getOrDefault("url", "").trim();

            if (url.isEmpty()) {
                WebUtils.sendJson(exchange, 400, "{\"error\":\"URL is required\"}");
                return;
            }

            PhishingAnalysisResult result = PhishingService.analyzeAndStore(email, url);
            WebUtils.sendJson(exchange, 200, buildJson(result));
        } catch (Exception e) {
            e.printStackTrace();
            WebUtils.sendJson(exchange, 500, "{\"error\":\"Unable to analyze URL\"}");
        }
    }

    private String buildJson(PhishingAnalysisResult result) {
        StringBuilder reasons = new StringBuilder("[");
        for (int i = 0; i < result.getReasons().size(); i++) {
            reasons.append("\"")
                .append(WebUtils.jsonEscape(result.getReasons().get(i)))
                .append("\"");
            if (i < result.getReasons().size() - 1) {
                reasons.append(",");
            }
        }
        reasons.append("]");

        return "{"
            + "\"url\":\"" + WebUtils.jsonEscape(result.getUrl()) + "\","
            + "\"score\":" + result.getScore() + ","
            + "\"verdict\":\"" + WebUtils.jsonEscape(result.getVerdict()) + "\","
            + "\"detail\":\"" + WebUtils.jsonEscape(result.getDetail()) + "\","
            + "\"reasons\":" + reasons + ","
            + "\"components\":{"
            + "\"protocol\":\"" + WebUtils.jsonEscape(result.getProtocol()) + "\","
            + "\"domain\":\"" + WebUtils.jsonEscape(result.getDomain()) + "\","
            + "\"subdomain\":\"" + WebUtils.jsonEscape(result.getSubdomain()) + "\","
            + "\"rootDomain\":\"" + WebUtils.jsonEscape(result.getRootDomain()) + "\","
            + "\"tld\":\"" + WebUtils.jsonEscape(result.getTld()) + "\","
            + "\"path\":\"" + WebUtils.jsonEscape(result.getPath()) + "\""
            + "}"
            + "}";
    }
}
