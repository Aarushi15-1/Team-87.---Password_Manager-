import java.security.SecureRandom;
import java.util.*;

public class PasswordGenerator {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*-_=.?";

    private static final SecureRandom rand = new SecureRandom();

    // 🔥 MAIN GENERATOR
    public static String generate(int length, boolean useSymbols, boolean avoidAmbiguous) {

        if (length < 10) length = 10; // stronger baseline

        String password;

        // 🔁 KEEP GENERATING UNTIL STRONG
        do {
            password = generateOnce(length, useSymbols, avoidAmbiguous);
        } while (!PasswordStrength.getStrength(password).equals("Strong"));

        return password;
    }

    // 🔐 SINGLE GENERATION
    private static String generateOnce(int length, boolean useSymbols, boolean avoidAmbiguous) {

        List<Character> password = new ArrayList<>();

        String lower = LOWER;
        String upper = UPPER;
        String digits = DIGITS;
        String symbols = SYMBOLS;

        // 🔥 remove ambiguous chars
        if (avoidAmbiguous) {
            lower = lower.replaceAll("[l]", "");
            upper = upper.replaceAll("[IO]", "");
            digits = digits.replaceAll("[01]", "");
        }

        // ✅ enforce diversity
        password.add(randomChar(lower));
        password.add(randomChar(upper));
        password.add(randomChar(digits));
        if (useSymbols) password.add(randomChar(symbols));

        String fullSet = lower + upper + digits;
        if (useSymbols) fullSet += symbols;

        while (password.size() < length) {
            password.add(randomChar(fullSet));
        }

        shuffle(password);

        StringBuilder result = new StringBuilder();
        for (char c : password) result.append(c);

        String candidate = result.toString();

        // ❌ reject bad patterns
        if (hasBadPatterns(candidate)) {
            return generateOnce(length, useSymbols, avoidAmbiguous);
        }

        return candidate;
    }

    // 🎯 RANDOM CHAR
    private static char randomChar(String s) {
        return s.charAt(rand.nextInt(s.length()));
    }

    // 🔀 SHUFFLE (Fisher-Yates)
    private static void shuffle(List<Character> list) {
        for (int i = list.size() - 1; i > 0; i--) {
            int j = rand.nextInt(i + 1);
            char temp = list.get(i);
            list.set(i, list.get(j));
            list.set(j, temp);
        }
    }

    // 🔥 PATTERN FILTER (IMPORTANT)
    private static boolean hasBadPatterns(String s) {

        // sequence
        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i+1) == s.charAt(i) + 1 &&
                s.charAt(i+2) == s.charAt(i+1) + 1) {
                return true;
            }
        }

        // repeat
        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i) == s.charAt(i+1) &&
                s.charAt(i) == s.charAt(i+2)) {
                return true;
            }
        }

        // keyboard patterns
        String lower = s.toLowerCase();
        String[] patterns = {"qwerty", "asdf", "zxcv", "12345"};

        for (String p : patterns) {
            if (lower.contains(p)) return true;
        }

        return false;
    }
}