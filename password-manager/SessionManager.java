import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    public static final class SessionData {
        private final String email;
        private final String vaultKey;
        private final String legacyVaultKey;

        public SessionData(String email, String vaultKey, String legacyVaultKey) {
            this.email = email;
            this.vaultKey = vaultKey;
            this.legacyVaultKey = legacyVaultKey;
        }

        public String getEmail() {
            return email;
        }

        public String getVaultKey() {
            return vaultKey;
        }

        public String getLegacyVaultKey() {
            return legacyVaultKey;
        }
    }

    private static final Map<String, SessionData> sessions = new ConcurrentHashMap<>();

    public static String createSession(String email, String vaultKey, String legacyVaultKey) {
        String session = UUID.randomUUID().toString();
        sessions.put(session, new SessionData(email, vaultKey, legacyVaultKey));
        return session;
    }

    public static SessionData getSession(String session) {
        if (session == null || session.isEmpty()) {
            return null;
        }

        return sessions.get(session);
    }

    public static String getUser(String session) {
        SessionData data = getSession(session);
        return data == null ? null : data.getEmail();
    }

    public static String getVaultKey(String session) {
        SessionData data = getSession(session);
        return data == null ? null : data.getVaultKey();
    }

    public static String getLegacyVaultKey(String session) {
        SessionData data = getSession(session);
        return data == null ? null : data.getLegacyVaultKey();
    }

    public static void removeSession(String session) {
        if (session != null && !session.isEmpty()) {
            sessions.remove(session);
        }
    }

    public static String extractSessionId(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return null;
        }

        for (String cookie : cookieHeader.split(";")) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals("session")) {
                return parts[1];
            }
        }

        return null;
    }
}
