import java.util.*;

public class PasswordGenerator {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()_+-=[]{}";

    // 🚀 MAIN GENERATOR
    public static String generate(int length, boolean useSymbols, boolean avoidAmbiguous) {

        List<Character> password = new ArrayList<>();
        Random rand = new Random();

        String lower = LOWER;
        String upper = UPPER;
        String digits = DIGITS;
        String symbols = SYMBOLS;

        // 🔥 Remove ambiguous characters
        if (avoidAmbiguous) {
            lower = lower.replaceAll("[l]", "");
            upper = upper.replaceAll("[I|O]", "");
            digits = digits.replaceAll("[0|1]", "");
        }

        // 🔐 Ensure at least one of each type (DSA constraint satisfaction)
        password.add(randomChar(lower, rand));
        password.add(randomChar(upper, rand));
        password.add(randomChar(digits, rand));

        if (useSymbols) {
            password.add(randomChar(symbols, rand));
        }

        // 🔢 Build full charset
        String fullSet = lower + upper + digits;
        if (useSymbols) fullSet += symbols;

        // 🧠 Fill remaining length
        while (password.size() < length) {
            password.add(randomChar(fullSet, rand));
        }

        // 🔀 Shuffle (Fisher–Yates algorithm)
        shuffle(password, rand);

        // 📏 Convert to string
        StringBuilder result = new StringBuilder();
        for (char c : password) result.append(c);

        return result.toString();
    }

    // 🎯 RANDOM CHAR
    private static char randomChar(String str, Random rand) {
        return str.charAt(rand.nextInt(str.length()));
    }

    // 🔀 FISHER–YATES SHUFFLE (DSA)
    private static void shuffle(List<Character> list, Random rand) {
        for (int i = list.size() - 1; i > 0; i--) {
            int j = rand.nextInt(i + 1);
            char temp = list.get(i);
            list.set(i, list.get(j));
            list.set(j, temp);
        }
    }

    // 📊 ENTROPY CALCULATION
    public static double calculateEntropy(int length, int charsetSize) {
        return length * (Math.log(charsetSize) / Math.log(2));
    }
}