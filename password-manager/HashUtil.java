import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HashUtil {

    private static final String PBKDF2_PREFIX = "PBKDF2_SHA256";
    private static final int DEFAULT_ITERATIONS = 210_000;
    private static final int HASH_LENGTH_BITS = 256;
    private static final int VAULT_KEY_LENGTH_BITS = 256;

    public static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(String password, String salt) {
        byte[] derived = deriveBytes(password, salt, "auth", DEFAULT_ITERATIONS, HASH_LENGTH_BITS);
        return PBKDF2_PREFIX + "$" + DEFAULT_ITERATIONS + "$" +
            Base64.getEncoder().encodeToString(derived);
    }

    public static boolean verifyPassword(String password, String salt, String storedHash) {
        if (storedHash == null || storedHash.isEmpty()) {
            return false;
        }

        if (!isPbkdf2Hash(storedHash)) {
            return legacyHash(password, salt).equals(storedHash);
        }

        String[] parts = storedHash.split("\\$", 3);
        if (parts.length != 3) {
            return false;
        }

        int iterations = Integer.parseInt(parts[1]);
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        byte[] actual = deriveBytes(password, salt, "auth", iterations, expected.length * 8);
        return MessageDigest.isEqual(expected, actual);
    }

    public static boolean isPbkdf2Hash(String storedHash) {
        return storedHash != null && storedHash.startsWith(PBKDF2_PREFIX + "$");
    }

    public static String getPasswordKdfAlgorithm() {
        return PBKDF2_PREFIX;
    }

    public static int getDefaultIterations() {
        return DEFAULT_ITERATIONS;
    }

    public static String deriveVaultKey(String password, String salt) {
        byte[] key = deriveBytes(password, salt, "vault", DEFAULT_ITERATIONS, VAULT_KEY_LENGTH_BITS);
        return Base64.getEncoder().encodeToString(key);
    }

    public static String deriveWrappingKey(String password, String salt) {
        byte[] key = deriveBytes(password, salt, "wrap", DEFAULT_ITERATIONS, VAULT_KEY_LENGTH_BITS);
        return Base64.getEncoder().encodeToString(key);
    }

    public static String legacyHash(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));

            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashed);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] deriveBytes(String password, String salt, String purpose, int iterations, int lengthBits) {
        char[] passwordChars = password.toCharArray();

        try {
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            byte[] purposeBytes = purpose.getBytes(StandardCharsets.UTF_8);
            byte[] scopedSalt = Arrays.copyOf(saltBytes, saltBytes.length + purposeBytes.length);
            System.arraycopy(purposeBytes, 0, scopedSalt, saltBytes.length, purposeBytes.length);

            PBEKeySpec spec = new PBEKeySpec(passwordChars, scopedSalt, iterations, lengthBits);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }
}
