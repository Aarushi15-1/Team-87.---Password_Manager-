import java.util.*;

public class PasswordStrength {

    private static final Set<String> dictionary = new HashSet<>(Arrays.asList(
        "password", "admin", "qwerty", "abc", "letmein", "welcome", "login"
    ));

    public static String getStrength(String password) {
        int score = scorePassword(password);

        if (score >= 8) return "Strong";
        if (score >= 5) return "Medium";
        return "Weak";
    }

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

                if (cost > 0 && dp[i] <= Long.MAX_VALUE / cost) {
                    dp[j] = Math.min(dp[j], dp[i] * cost);
                } else {
                    dp[j] = Math.min(dp[j], Long.MAX_VALUE);
                }
            }
        }

        return dp[n];
    }

    private static int scorePassword(String password) {
        int score = 0;
        int length = password.length();

        if (length >= 12) score += 4;
        else if (length >= 10) score += 3;
        else if (length >= 8) score += 2;
        else if (length >= 6) score += 1;

        int variety = 0;
        if (password.matches(".*[a-z].*")) variety++;
        if (password.matches(".*[A-Z].*")) variety++;
        if (password.matches(".*[0-9].*")) variety++;
        if (password.matches(".*[^a-zA-Z0-9].*")) variety++;
        score += variety * 2;

        if (dictionary.contains(password.toLowerCase())) score -= 4;
        if (isSequence(password)) score -= 3;
        if (isRepeat(password)) score -= 3;
        if (isKeyboardPattern(password)) score -= 3;

        long guesses = estimateGuesses(password);
        if (guesses >= 1_000_000L) score += 1;
        if (guesses >= 100_000_000L) score += 1;

        return Math.max(score, 0);
    }

    private static long getPatternCost(String s) {
        if (dictionary.contains(s.toLowerCase())) {
            return 100_000L;
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

        int charset = 0;

        if (s.matches(".*[a-z].*")) charset += 26;
        if (s.matches(".*[A-Z].*")) charset += 26;
        if (s.matches(".*[0-9].*")) charset += 10;
        if (s.matches(".*[^a-zA-Z0-9].*")) charset += 20;

        if (charset == 0) charset = 10;

        double entropy = s.length() * (Math.log(charset) / Math.log(2));
        return Math.max((long) Math.pow(2, entropy / 2), 1L);
    }

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

    private static boolean isRepeat(String s) {
        if (s.length() < 3) return false;

        char first = s.charAt(0);
        for (char c : s.toCharArray()) {
            if (c != first) return false;
        }
        return true;
    }

    private static boolean isKeyboardPattern(String s) {
        String[] patterns = {"qwerty", "asdf", "zxcv", "12345"};

        String lower = s.toLowerCase();
        for (String p : patterns) {
            if (lower.contains(p)) return true;
        }
        return false;
    }
}
