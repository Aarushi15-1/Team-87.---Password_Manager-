import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
    private static final int DATABASE_INIT_ATTEMPTS = 30;
    private static final long DATABASE_INIT_DELAY_MS = 2000;

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/", Main::serveStaticFile);
        server.createContext("/register", new RegisterHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/verify2fa", new TwoFactorPageHandler());
        server.createContext("/submit2fa", new TwoFactorVerifyHandler());
        server.createContext("/addPassword", new AddPasswordHandler());
        server.createContext("/dashboard", new DashboardHandler());
        server.createContext("/vault", new VaultHandler());
        server.createContext("/phishing", new PhishingPageHandler());
        server.createContext("/analyzePhishing", new PhishingAnalyzeHandler());
        server.createContext("/reveal", new RevealHandler());
        server.createContext("/logout", new LogoutHandler());
        server.createContext("/editPassword", new EditPasswordHandler());
        server.createContext("/generate", new GenerateHandler());

        server.start();
        System.out.println("Running on http://localhost:8080");
        startDatabaseInitializer();
    }

    private static void startDatabaseInitializer() {
        Thread dbInitializer = new Thread(() -> {
            for (int attempt = 1; attempt <= DATABASE_INIT_ATTEMPTS; attempt++) {
                try {
                    DBConnection.initializeDatabase();
                    System.out.println("Database initialized");
                    return;
                } catch (Exception e) {
                    System.err.println(
                        "Database initialization attempt " + attempt + " failed: " + e.getMessage()
                    );

                    if (attempt == DATABASE_INIT_ATTEMPTS) {
                        e.printStackTrace();
                        return;
                    }

                    try {
                        Thread.sleep(DATABASE_INIT_DELAY_MS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        });

        dbInitializer.setDaemon(true);
        dbInitializer.start();
    }

    private static void serveStaticFile(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            Path webRoot = Paths.get("web").toAbsolutePath().normalize();

            if (path.equals("/")) {
                path = "/index.html";
            }

            Path requested = webRoot.resolve(path.substring(1)).normalize();

            if (!requested.startsWith(webRoot) || Files.isDirectory(requested) || !Files.exists(requested)) {
                sendText(exchange, 404, "404 Not Found", "text/plain");
                return;
            }

            byte[] data = Files.readAllBytes(requested);
            exchange.getResponseHeaders().set("Content-Type", contentTypeFor(path));
            exchange.sendResponseHeaders(200, data.length);
            exchange.getResponseBody().write(data);
        } catch (Exception e) {
            e.printStackTrace();
            sendText(exchange, 500, "Internal Server Error", "text/plain");
        } finally {
            exchange.close();
        }
    }

    private static void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType + "; charset=UTF-8");
        exchange.sendResponseHeaders(status, data.length);
        exchange.getResponseBody().write(data);
    }

    private static String contentTypeFor(String path) {
        if (path.endsWith(".html")) {
            return "text/html; charset=UTF-8";
        }
        if (path.endsWith(".css")) {
            return "text/css; charset=UTF-8";
        }
        if (path.endsWith(".js")) {
            return "application/javascript; charset=UTF-8";
        }

        return "application/octet-stream";
    }
}
