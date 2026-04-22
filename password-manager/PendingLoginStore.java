import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PendingLoginStore {
    private static final Map<String, PendingLogin> pendingLogins = new ConcurrentHashMap<>();

    public static void put(PendingLogin pendingLogin) {
        pendingLogins.put(pendingLogin.getToken(), pendingLogin);
    }

    public static PendingLogin get(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }

        return pendingLogins.get(token);
    }

    public static PendingLogin remove(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }

        return pendingLogins.remove(token);
    }
}
