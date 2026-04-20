import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String CURRENT_PREFIX = "v2";

    public static String encrypt(String plainText, String vaultKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(vaultKey);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return CURRENT_PREFIX + ":" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(iv) + ":" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
    }

    public static String decrypt(String cipherText, String vaultKey, String legacyVaultKey) throws Exception {
        if (cipherText != null && cipherText.startsWith(CURRENT_PREFIX + ":")) {
            return decryptCurrent(cipherText, vaultKey);
        }

        if (legacyVaultKey == null || legacyVaultKey.isEmpty()) {
            throw new IllegalStateException("Legacy vault key is unavailable for this entry.");
        }

        return decryptLegacy(cipherText, legacyVaultKey);
    }

    public static String deriveLegacyVaultKey(String password, String salt) {
        String value = password + ":" + salt;

        for (int i = 0; i < 1000; i++) {
            value = HashUtil.legacyHash(value + i, "");

            if (i % 100 == 0) {
                value = HashUtil.legacyHash(value + salt, "");
            }
        }

        return value.substring(0, 16);
    }

    private static String decryptCurrent(String cipherText, String vaultKey) throws Exception {
        String[] parts = cipherText.split(":", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid encrypted payload.");
        }

        byte[] iv = Base64.getUrlDecoder().decode(parts[1]);
        byte[] encrypted = Base64.getUrlDecoder().decode(parts[2]);
        byte[] keyBytes = Base64.getDecoder().decode(vaultKey);

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static String decryptLegacy(String cipherText, String legacyVaultKey) throws Exception {
        byte[] combined = Base64.getUrlDecoder().decode(cipherText);
        byte[] keyBytes = legacyVaultKey.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[16];
        System.arraycopy(combined, 0, iv, 0, 16);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
