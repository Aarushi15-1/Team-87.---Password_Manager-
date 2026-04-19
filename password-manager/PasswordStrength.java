import java.util.*;

public class PasswordStrength {

    private static final Set<String> dictionary = new HashSet<>(Arrays.asList(
        "password", "admin", "qwerty", "abc", "letmein", "welcome", "login"
    ));

    // 🔥 MAIN FUNCTION
    public static String getStrength(String password) {
        long guesses = estimateGuesses(password);

        if (guesses < 1_000_000L) return "Weak";
        else if (guesses < 100_000_000L) return "Medium";
        else return "Strong";
    }

    // 🔥 CORE DSA: DP GUESS ESTIMATION
    public static long estimateGuesses(String password) {

        int n = password.length();
        long[] dp = new long[n + 1];

        Arrays.fill(dp, Long.MAX_VALUE);
        dp[0] = 1;

        for (int i = 0; i < n; i++) {

            if (dp[i] == Long.MAX_VALUE) continue;

            for (int j = i + 1; j <= n; j++) {

                String sub = password.substring(i, j);

                long cost = getPatternCost(sub);

                dp[j] = Math.min(dp[j], dp[i] * cost);
            }
        }

        return dp[n];
    }

    // 🔍 PATTERN COST FUNCTION
    private static long getPatternCost(String s) {

        if (dictionary.contains(s.toLowerCase())) {
            return 100_000L; // dictionary words are weak
        }

        if (isSequence(s)) {
            return 1_000L;
        }

        if (isRepeat(s)) {
            return 500L;
        }

        if (isKeyboardPattern(s)) {
            return 2_000L;
        }

        // 🔐 RANDOM STRING → ENTROPY BASED
        int charset = 0;

        if (s.matches(".*[a-z].*")) charset += 26;
        if (s.matches(".*[A-Z].*")) charset += 26;
        if (s.matches(".*[0-9].*")) charset += 10;
        if (s.matches(".*[^a-zA-Z0-9].*")) charset += 20;

        if (charset == 0) charset = 10;

        double entropy = s.length() * (Math.log(charset) / Math.log(2));

        return (long) Math.pow(2, entropy / 2); // scaled
    }

    // 🔁 SEQUENCE CHECK
    private static boolean isSequence(String s) {
        if (s.length() < 3) return false;

        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i + 1) == s.charAt(i) + 1 &&
                s.charAt(i + 2) == s.charAt(i + 1) + 1) {
                return true;
            }
        }
        return false;
    }

    // 🔁 REPEAT CHECK
    private static boolean isRepeat(String s) {
        if (s.length() < 3) return false;

        char first = s.charAt(0);
        for (char c : s.toCharArray()) {
            if (c != first) return false;
        }
        return true;
    }

    // 🔁 KEYBOARD PATTERN
    private static boolean isKeyboardPattern(String s) {
        String[] patterns = {"qwerty", "asdf", "zxcv", "12345"};

        String lower = s.toLowerCase();
        for (String p : patterns) {
            if (lower.contains(p)) return true;
        }
        return false;
    }
}