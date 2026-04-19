import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class EncryptionUtil {

    // 🔐 ENCRYPT
    public static String encrypt(String plainText, String key) throws Exception {

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // 🔥 generate random IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // 🔥 combine IV + encrypted
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        // 🔥 USE URL-SAFE BASE64 (THIS FIXES YOUR BUG)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
    }

    // 🔓 DECRYPT
    public static String decrypt(String cipherText, String key) throws Exception {

        // 🔥 URL-SAFE DECODER
        byte[] combined = Base64.getUrlDecoder().decode(cipherText);

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // 🔥 extract IV
        byte[] iv = new byte[16];
        System.arraycopy(combined, 0, iv, 0, 16);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 🔥 extract encrypted data
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}