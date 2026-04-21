import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class LogoutHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) {
        try {
            String session = SessionManager.extractSessionId(
                exchange.getRequestHeaders().getFirst("Cookie")
            );
            SessionManager.removeSession(session);

            exchange.getResponseHeaders().add(
                "Set-Cookie",
                "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            );

            exchange.getResponseHeaders().add("Location", "/logout.html");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
