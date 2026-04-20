import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

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

            String html = new String(Files.readAllBytes(Paths.get("web/phishing.html")), StandardCharsets.UTF_8);
            html = html.replace("{{PREFILL_URL}}", WebUtils.escapeHtml(prefillUrl));

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
