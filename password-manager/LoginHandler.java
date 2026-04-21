import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public class LoginHandler implements HttpHandler {

    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            Map<String, String> form = RequestUtil.parseFormBody(exchange);
            String email = form.getOrDefault("email", "");
            String password = form.getOrDefault("password", "");
            Double latitude = parseNullableDouble(form.get("latitude"));
            Double longitude = parseNullableDouble(form.get("longitude"));

            LoginSecurityManager.SuspensionStatus suspension = LoginSecurityManager.getSuspensionStatus(email);
            if (suspension.isSuspended()) {
                sendText(exchange, 423, pausedAccountMessage(suspension.getSuspendedUntilUtc()));
                return;
            }

            PasswordManager.LoginResult login = PasswordManager.login(email, password);
            if (login != null) {
                LoginRiskResult riskResult = LoginSecurityManager.analyzeLogin(
                    login.getEmail(),
                    latitude,
                    longitude
                );

                if (riskResult.isHighRisk()) {
                    PendingLogin pendingLogin = LoginSecurityManager.createPendingLogin(
                        login.getEmail(),
                        login.getVaultKey(),
                        latitude,
                        longitude,
                        riskResult
                    );

                    exchange.getResponseHeaders().add("Location", "/verify2fa?token=" + pendingLogin.getToken());
                    exchange.sendResponseHeaders(302, -1);
                    return;
                }

                LoginSecurityManager.recordSuccessfulLogin(login.getEmail(), latitude, longitude, riskResult);
                String session = SessionManager.createSession(
                    login.getEmail(),
                    login.getVaultKey()
                );

                exchange.getResponseHeaders().add(
                    "Set-Cookie",
                    "session=" + session + "; Path=/; HttpOnly; SameSite=Lax"
                );
                exchange.getResponseHeaders().add("Location", "/dashboard");

                exchange.sendResponseHeaders(302, -1);
                return;
            }

            LoginSecurityManager.recordFailedLogin(email);
            String res = "Login failed";
            exchange.sendResponseHeaders(200, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            String res = "Login failed";
            exchange.sendResponseHeaders(500, res.length());
            exchange.getResponseBody().write(res.getBytes(StandardCharsets.UTF_8));
        } finally {
            exchange.close();
        }
    }

    private static Double parseNullableDouble(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void sendText(HttpExchange exchange, int statusCode, String text) throws IOException {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, data.length);
        exchange.getResponseBody().write(data);
    }

    private static String pausedAccountMessage(Instant suspendedUntilUtc) {
        ZonedDateTime utcTime = suspendedUntilUtc.atZone(ZoneOffset.UTC);
        ZonedDateTime indiaTime = suspendedUntilUtc.atZone(java.time.ZoneId.of("Asia/Kolkata"));
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss a z");

        return "Account paused after repeated failed logins.\n" +
            "Unlock time (India): " + indiaTime.format(formatter) + "\n" +
            "Unlock time (UTC): " + utcTime.format(formatter);
    }
}
