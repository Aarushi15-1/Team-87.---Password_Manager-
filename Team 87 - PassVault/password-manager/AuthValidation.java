import java.util.Locale;

public class AuthValidation {
    private static final int MIN_PASSWORD_LENGTH = 8;

    public static String requireValidEmail(String email) throws AuthException {
        String normalized = normalizeEmail(email);
        int atIndex = normalized.indexOf('@');
        int dotIndex = normalized.lastIndexOf('.');

        if (
            atIndex <= 0 ||
            dotIndex <= atIndex + 1 ||
            dotIndex >= normalized.length() - 1 ||
            normalized.contains(" ")
        ) {
            throw new AuthException("Email must include @ and .");
        }

        return normalized;
    }

    public static void requireValidPassword(String password) throws AuthException {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new AuthException("Password must be at least 8 characters long.");
        }
    }

    private static String normalizeEmail(String email) {
        if (email == null) {
            return "";
        }

        return email.trim().toLowerCase(Locale.ROOT);
    }
}
