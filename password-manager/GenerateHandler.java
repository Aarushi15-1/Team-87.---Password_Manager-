import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.util.Map;

public class GenerateHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            int len = 12;
            boolean sym = false;

            Map<String, String> query = RequestUtil.parseQuery(exchange.getRequestURI().getQuery());
            if (query.containsKey("len")) len = Integer.parseInt(query.get("len"));
            if (query.containsKey("sym")) sym = Boolean.parseBoolean(query.get("sym"));

            String pass = PasswordGenerator.generate(len, sym, false);

            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, pass.length());
            exchange.getResponseBody().write(pass.getBytes());
        } catch (Exception e) {
            e.printStackTrace();

            String err = "Generator error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes());
        } finally {
            exchange.close();
        }
    }
}
