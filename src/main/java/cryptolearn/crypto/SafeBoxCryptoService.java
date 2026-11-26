package cryptolearn.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SafeBoxCryptoService {

    private static final int SALT_BYTES = 16;        // 128 бит
    private static final int NONCE_BYTES = 12;       // 96 бит для GCM
    private static final int KEY_BITS = 256;         // AES-256
    private static final int GCM_TAG_BITS = 128;     // длина тега аутентичности
    private static final int DEFAULT_ITERATIONS = 100_000;

    private final SecureRandom random = new SecureRandom();

    /**
     * Шифрует произвольный plaintext с помощью пароля.
     * Возвращает шифротекст + соль + nonce + число итераций KDF.
     */

    public EncryptResult encrypt(byte[] plaintext, char[] password) throws Exception {
        // 1. Генерируем соль для PBKDF2
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);

        // 2. Деривируем ключ из пароля + соли
        SecretKey key = deriveKey(password, salt, DEFAULT_ITERATIONS);

        // 3. Генерируем случайный nonce (IV) для AES-GCM
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);

        // 4. Настраиваем AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // 5. Шифруем данные. В ciphertext уже зашит тег аутентичности.
        byte[] ciphertext = cipher.doFinal(plaintext);

        return new EncryptResult(ciphertext, salt, nonce, DEFAULT_ITERATIONS);
    }

    /**
     * Расшифровывает на основе результата encrypt() и пароля.
     * Если пароль неверный или данные повреждены — будет исключение.
     */

    public byte[] decrypt(EncryptResult params, char[] password) throws Exception {
        // 1. Повторно деривируем ключ из того же пароля и соли
        SecretKey key = deriveKey(password, params.salt(), params.iterations());

        // 2. Настраиваем AES-GCM с тем же nonce
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, params.nonce());
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        // 3. Расшифровываем. При повреждении/неверном пароле будет AEADBadTagException.
        return cipher.doFinal(params.ciphertext());
    }

    /**
     * PBKDF2-HMAC-SHA256: пароль + соль → ключ заданной длины.
     */
    private SecretKey deriveKey(char[] password, byte[] salt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public record EncryptResult(
            byte[] ciphertext,
            byte[] salt,
            byte[] nonce,
            int iterations
    ) {}
}
