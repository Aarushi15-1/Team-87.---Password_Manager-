import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class WebUtils {

    public static Map<String, String> parseFormBody(String body) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();
        if (body == null || body.isBlank()) {
            return values;
        }

        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }

        return values;
    }

    public static String getSessionId(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) {
            return null;
        }

        for (String part : cookie.split(";")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("session=")) {
                String[] pair = trimmed.split("=", 2);
                return pair.length > 1 ? pair[1] : null;
            }
        }

        return null;
    }

    public static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    public static void redirectWithFlash(HttpExchange exchange, String location, String form, String type, String message) throws IOException {
        String separator = location.contains("?") ? "&" : "?";
        String target =
            location +
            separator +
            "form=" + urlEncode(form) +
            "&type=" + urlEncode(type) +
            "&message=" + urlEncode(message);
        redirect(exchange, target);
    }

    public static String escapeHtml(String value) {
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

    public static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }

        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t");
    }

    public static void sendJson(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, data.length);
        exchange.getResponseBody().write(data);
        exchange.close();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
