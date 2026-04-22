import java.security.SecureRandom;
import java.util.*;

public class PasswordGenerator {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*-_.";

    private static final SecureRandom rand = new SecureRandom();

    public static String generate(int length, boolean useSymbols, boolean avoidAmbiguous) {

        // 🔒 enforce range
        if (length < 6) length = 6;
        if (length > 18) length = 18;

        int maxAttempts = 40;

        String best = "";
        String bestStrength = "Weak";

        for (int i = 0; i < maxAttempts; i++) {

            String pwd = generateOnce(length, useSymbols, avoidAmbiguous);

            if (hasBadPatterns(pwd)) continue;

            String strength = PasswordStrength.getStrength(pwd);

            // 🔥 return immediately if strong
            if (strength.equals("Strong")) {
                return pwd;
            }

            // store best seen
            if (strength.equals("Medium") && bestStrength.equals("Weak")) {
                best = pwd;
                bestStrength = "Medium";
            }

            if (best.isEmpty()) {
                best = pwd;
            }
        }

        return best;
    }

    private static String generateOnce(int length, boolean useSymbols, boolean avoidAmbiguous) {

        List<Character> password = new ArrayList<>();

        String lower = LOWER;
        String upper = UPPER;
        String digits = DIGITS;
        String symbols = SYMBOLS;

        if (avoidAmbiguous) {
            lower = lower.replaceAll("[l]", "");
            upper = upper.replaceAll("[IO]", "");
            digits = digits.replaceAll("[01]", "");
        }

        password.add(randomChar(lower));
        password.add(randomChar(upper));
        password.add(randomChar(digits));
        if (useSymbols) password.add(randomChar(symbols));

        String full = lower + upper + digits;
        if (useSymbols) full += symbols;

        while (password.size() < length) {
            password.add(randomChar(full));
        }

        shuffle(password);

        StringBuilder sb = new StringBuilder();
        for (char c : password) sb.append(c);

        return sb.toString();
    }

    private static char randomChar(String s) {
        return s.charAt(rand.nextInt(s.length()));
    }

    private static void shuffle(List<Character> list) {
        for (int i = list.size() - 1; i > 0; i--) {
            int j = rand.nextInt(i + 1);
            char t = list.get(i);
            list.set(i, list.get(j));
            list.set(j, t);
        }
    }

    private static boolean hasBadPatterns(String s) {

        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i+1) == s.charAt(i) + 1 &&
                s.charAt(i+2) == s.charAt(i+1) + 1) return true;
        }

        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i) == s.charAt(i+1) &&
                s.charAt(i) == s.charAt(i+2)) return true;
        }

        String lower = s.toLowerCase();
        String[] patterns = {"qwerty", "asdf", "zxcv", "12345"};

        for (String p : patterns) {
            if (lower.contains(p)) return true;
        }

        return false;
    }
}