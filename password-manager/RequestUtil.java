import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class RequestUtil {

    public static Map<String, String> parseFormBody(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return parseUrlEncoded(body);
    }

    public static Map<String, String> parseQuery(String query) {
        return parseUrlEncoded(query);
    }

    private static Map<String, String> parseUrlEncoded(String raw) {
        Map<String, String> values = new LinkedHashMap<>();

        if (raw == null || raw.isEmpty()) {
            return values;
        }

        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }

            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }

        return values;
    }
}
