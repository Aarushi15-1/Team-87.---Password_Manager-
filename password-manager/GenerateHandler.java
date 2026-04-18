import com.sun.net.httpserver.*;
import java.io.*;

public class GenerateHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        try {
            String query = exchange.getRequestURI().getQuery();

            int len = 12;
            boolean sym = false;

            if (query != null) {
                for (String pair : query.split("&")) {
                    String[] kv = pair.split("=");

                    if (kv[0].equals("len")) len = Integer.parseInt(kv[1]);
                    if (kv[0].equals("sym")) sym = Boolean.parseBoolean(kv[1]);
                }
            }

            String pass = PasswordGenerator.generate(len, sym, false);

            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, pass.length());
            exchange.getResponseBody().write(pass.getBytes());
            exchange.close();

        } catch (Exception e) {
            e.printStackTrace();

            String err = "Generator error";
            exchange.sendResponseHeaders(500, err.length());
            exchange.getResponseBody().write(err.getBytes());
            exchange.close();
        }
    }
}