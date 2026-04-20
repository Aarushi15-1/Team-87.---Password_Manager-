import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String CURRENT_PREFIX = "v2";
    private static final String WRAPPED_KEY_PREFIX = "wrap1";

    public static String encrypt(String plainText, String vaultKey) throws Exception {
        return encryptGcmPayload(plainText, vaultKey, CURRENT_PREFIX);
    }

    public static String generateVaultKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    public static String wrapVaultKey(String vaultKey, String wrappingKey) throws Exception {
        return encryptGcmPayload(vaultKey, wrappingKey, WRAPPED_KEY_PREFIX);
    }

    public static String unwrapVaultKey(String wrappedVaultKey, String wrappingKey) throws Exception {
        return decryptGcmPayload(wrappedVaultKey, wrappingKey, WRAPPED_KEY_PREFIX);
    }

    private static String encryptGcmPayload(String plainText, String encodedKey, String prefix) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return prefix + ":" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(iv) + ":" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
    }

    public static String decrypt(String cipherText, String vaultKey) throws Exception {
        return decryptCurrent(cipherText, vaultKey);
    }

    private static String decryptCurrent(String cipherText, String vaultKey) throws Exception {
        return decryptGcmPayload(cipherText, vaultKey, CURRENT_PREFIX);
    }

    private static String decryptGcmPayload(String cipherText, String encodedKey, String expectedPrefix) throws Exception {
        String[] parts = cipherText.split(":", 3);
        if (parts.length != 3 || !expectedPrefix.equals(parts[0])) {
            throw new IllegalArgumentException("Invalid encrypted payload.");
        }

        byte[] iv = Base64.getUrlDecoder().decode(parts[1]);
        byte[] encrypted = Base64.getUrlDecoder().decode(parts[2]);
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

}
