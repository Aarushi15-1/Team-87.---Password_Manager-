import java.util.*;

public class SessionManager {

    private static Map<String, String> sessionToUser = new HashMap<>();
    private static Map<String, String> sessionToPassword = new HashMap<>();

    public static String createSession(String email, String password) {
        String session = UUID.randomUUID().toString();
        sessionToUser.put(session, email);
        sessionToPassword.put(session, password);
        return session;
    }

    public static String getUser(String session) {
        return sessionToUser.get(session);
    }

    public static String getPassword(String session) {
        return sessionToPassword.get(session);
    }

    public static void removeSession(String session) {
        sessionToUser.remove(session);
        sessionToPassword.remove(session);
    }
}