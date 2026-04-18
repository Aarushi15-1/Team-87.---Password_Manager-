import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;

public class Main {

    public static void main(String[] args) throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // Serve static files
        server.createContext("/", exchange -> {
    try {
        String path = exchange.getRequestURI().getPath();

        if (path.equals("/")) path = "/index.html";

        File file = new File("web" + path);

        if (!file.exists()) {
            String res = "404 Not Found";
            exchange.sendResponseHeaders(404, res.length());
            exchange.getResponseBody().write(res.getBytes());
            exchange.close();
            return;
        }

        byte[] data = java.nio.file.Files.readAllBytes(file.toPath());

        // 🔥 THIS IS THE FIX
        if (path.endsWith(".html")) {
            exchange.getResponseHeaders().set("Content-Type", "text/html");
        } else if (path.endsWith(".css")) {
            exchange.getResponseHeaders().set("Content-Type", "text/css");
        } else if (path.endsWith(".js")) {
            exchange.getResponseHeaders().set("Content-Type", "application/javascript");
        }

        exchange.sendResponseHeaders(200, data.length);
        exchange.getResponseBody().write(data);
        exchange.close();

    } catch (Exception e) {
        e.printStackTrace();
    }
});
        server.createContext("/register", new RegisterHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/addPassword", new AddPasswordHandler());
        server.createContext("/dashboard", new DashboardHandler());
        server.createContext("/vault", new VaultHandler());
        server.createContext("/reveal", new RevealHandler());
        server.createContext("/logout", new LogoutHandler());
        server.createContext("/editPassword", new EditPasswordHandler());
        server.createContext("/generate", new GenerateHandler());

        server.start();
        System.out.println("Running on port 8080");
    }
}