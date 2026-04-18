import java.util.*;

public class PasswordStrength {

    private static final Set<String> commonPasswords = new HashSet<>(Arrays.asList(
        "password", "123456", "12345678", "qwerty", "abc123", "admin", "letmein"
    ));

    public static int calculateScore(String password) {

        int score = 0;
        int len = password.length();

        // 🔹 1. LENGTH (stronger weight)
        if (len >= 14) score += 40;
        else if (len >= 10) score += 30;
        else if (len >= 8) score += 20;
        else score += 10;

        // 🔹 2. CHARACTER SET
        int charset = 0;
        if (password.matches(".*[a-z].*")) charset += 26;
        if (password.matches(".*[A-Z].*")) charset += 26;
        if (password.matches(".*[0-9].*")) charset += 10;
        if (password.matches(".*[^a-zA-Z0-9].*")) charset += 32;

        // 🔹 3. ENTROPY (STRONG BOOST)
        if (charset > 0) {
            double entropy = len * (Math.log(charset) / Math.log(2));
            score += (int)(entropy / 2); // 🔥 was /4 → now /2
        }

        // 🔹 4. UNIQUE CHARACTERS
        Set<Character> unique = new HashSet<>();
        for (char c : password.toCharArray()) {
            unique.add(c);
        }
        if (unique.size() > len * 0.7) score += 15;

        // 🔹 5. COMMON PASSWORD
        if (commonPasswords.contains(password.toLowerCase())) {
            return 0;
        }

        // 🔹 6. REPETITION PENALTY
        if (hasRepeats(password)) score -= 15;

        // 🔹 7. SEQUENCE PENALTY
        if (hasSequence(password)) score -= 10;

        // 🔹 CLAMP
        score = Math.max(0, Math.min(score, 100));

        return score;
    }

    public static String getStrength(String password) {
        int score = calculateScore(password);

        if (score < 40) return "Weak";
        else if (score < 75) return "Medium";  // 🔥 moved threshold
        else return "Strong";
    }

    private static boolean hasRepeats(String s) {
        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i) == s.charAt(i+1) && s.charAt(i) == s.charAt(i+2)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasSequence(String s) {
        for (int i = 0; i < s.length() - 2; i++) {
            char a = s.charAt(i);
            char b = s.charAt(i+1);
            char c = s.charAt(i+2);

            if (b == a + 1 && c == b + 1) return true;
        }
        return false;
    }
}