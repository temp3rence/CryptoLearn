package cryptolearn.service;

import cryptolearn.crypto.EncryptedFileCodec;
import cryptolearn.crypto.SafeBoxCryptoService;
import cryptolearn.crypto.SafeBoxCryptoService.EncryptResult;
import cryptolearn.dao.OperationsDao;
import cryptolearn.model.Operation;

import javax.crypto.AEADBadTagException;
import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

public class SafeBoxService {

    public static final String OP_ENCRYPT = "SAFEBOX_ENCRYPT";
    public static final String OP_DECRYPT = "SAFEBOX_DECRYPT";

    public static final String ALG_AES_GCM = "AES-256-GCM";
    public static final String KDF_PBKDF2_SHA256 = "PBKDF2-HMAC-SHA256";

    public static final String ST_SUCCESS = "SUCCESS";
    public static final String ST_INVALID_INPUT = "INVALID_INPUT";
    public static final String ST_IO_ERROR = "IO_ERROR";
    public static final String ST_AUTH_FAILED = "AUTH_FAILED";
    public static final String ST_CRYPTO_ERROR = "CRYPTO_ERROR";

    private final Path storageDir;
    private final SafeBoxCryptoService crypto;
    private final OperationsDao operationsDao;
    private final EncryptedFileCodec codec;

    public SafeBoxService() throws IOException {
        this(Paths.get("data"), new SafeBoxCryptoService(), new OperationsDao(), new EncryptedFileCodec());
    }

    public SafeBoxService(Path storageDir,
                          SafeBoxCryptoService crypto,
                          OperationsDao operationsDao) throws IOException {
        this(storageDir, crypto, operationsDao, new EncryptedFileCodec());
    }

    public SafeBoxService(Path storageDir,
                          SafeBoxCryptoService crypto,
                          OperationsDao operationsDao,
                          EncryptedFileCodec codec) throws IOException {
        this.storageDir = storageDir;
        this.crypto = crypto;
        this.operationsDao = operationsDao;
        this.codec = codec;
        Files.createDirectories(storageDir);
    }

    public Operation encryptFile(Path inputFile, String password) throws Exception {
        Instant startedAt = null;
        Operation op = new Operation();
        op.setOperationType(OP_ENCRYPT);
        op.setAlgorithm(ALG_AES_GCM);
        op.setKdf(KDF_PBKDF2_SHA256);

        char[] pw = (password == null) ? null : password.toCharArray();

        try {
            // 1) Валидация
            if (pw == null || pw.length == 0) throw new IllegalArgumentException("Password is empty");
            if (inputFile == null) throw new IllegalArgumentException("inputFile is null");
            if (!Files.exists(inputFile) || !Files.isRegularFile(inputFile)) {
                throw new IllegalArgumentException("Input file does not exist or is not a regular file: " + inputFile);
            }

            // 2) Чтение входа (это IO, в crypto-время не входит)
            byte[] plaintext = Files.readAllBytes(inputFile);
            op.setInputSizeBytes((long) plaintext.length);

            // 3) Крипта + crypto-only метрики времени
            startedAt = Instant.now();
            EncryptResult enc = crypto.encrypt(plaintext, pw);
            Instant finishedAt = Instant.now();

            op.setStartedAt(startedAt);
            op.setFinishedAt(finishedAt);
            op.setDurationMs((int) Duration.between(startedAt, finishedAt).toMillis());

            // 4) Пишем .enc КАК САМОДОСТАТОЧНЫЙ ФАЙЛ (header + ciphertext)
            Path out = buildCiphertextPath(inputFile);
            codec.write(out, enc.iterations(), enc.salt(), enc.nonce(), enc.ciphertext());

            // 5) Логи/параметры в БД
            op.setCiphertextPath(out.toString());
            op.setKdfIterations(enc.iterations());
            op.setSalt(enc.salt());
            op.setNonce(enc.nonce());

            // output_size_bytes: фактический размер файла .enc (включая header)
            op.setOutputSizeBytes(Files.size(out));

            op.setStatus(ST_SUCCESS);
            op.setErrorMessage(null);

            operationsDao.insert(op);
            return op;

        } catch (IllegalArgumentException e) {
            finishWithError(op, startedAt, ST_INVALID_INPUT, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } catch (IOException e) {
            finishWithError(op, startedAt, ST_IO_ERROR, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } catch (Exception e) {
            finishWithError(op, startedAt, ST_CRYPTO_ERROR, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } finally {
            if (pw != null) Arrays.fill(pw, '\0');
        }
    }

    /**
     * Расшифровка:
     * - читаем header из .enc (salt/nonce/iterations)
     * - decrypt(ciphertext, password)
     */
    public Operation decryptFile(Path encryptedFile, String password, Path outputFile) throws Exception {
        Instant startedAt = null;

        Operation op = new Operation();
        op.setOperationType(OP_DECRYPT);
        op.setAlgorithm(ALG_AES_GCM);
        op.setKdf(KDF_PBKDF2_SHA256);

        char[] pw = (password == null) ? null : password.toCharArray();

        try {
            // 1) Валидация
            if (pw == null || pw.length == 0) throw new IllegalArgumentException("Password is empty");
            if (encryptedFile == null) throw new IllegalArgumentException("encryptedFile is null");
            if (!Files.exists(encryptedFile) || !Files.isRegularFile(encryptedFile)) {
                throw new IllegalArgumentException("Encrypted file does not exist or is not a regular file: " + encryptedFile);
            }
            if (outputFile == null) throw new IllegalArgumentException("outputFile is null");

            // input_size_bytes: фактический размер входного .enc
            op.setInputSizeBytes(Files.size(encryptedFile));
            op.setCiphertextPath(encryptedFile.toString());

            // 2) Читаем header + ciphertext (это IO, не входит в crypto-время)
            EncryptedFileCodec.ParsedEncryptedFile parsed = codec.read(encryptedFile);

            op.setKdfIterations(parsed.iterations());
            op.setSalt(parsed.salt());
            op.setNonce(parsed.nonce());

            // 3) Дешифруем (crypto-only таймер)
            startedAt = Instant.now();
            EncryptResult params = new EncryptResult(parsed.ciphertext(), parsed.salt(), parsed.nonce(), parsed.iterations());
            byte[] plaintext = crypto.decrypt(params, pw);
            Instant finishedAt = Instant.now();

            op.setStartedAt(startedAt);
            op.setFinishedAt(finishedAt);
            op.setDurationMs((int) Duration.between(startedAt, finishedAt).toMillis());

            // 4) Пишем результат
            Files.write(outputFile, plaintext, StandardOpenOption.CREATE_NEW);
            op.setOutputSizeBytes((long) plaintext.length);

            op.setStatus(ST_SUCCESS);
            op.setErrorMessage(null);

            operationsDao.insert(op);
            return op;

        } catch (AEADBadTagException e) {
            finishWithError(op, startedAt, ST_AUTH_FAILED, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } catch (IllegalArgumentException e) {
            finishWithError(op, startedAt, ST_INVALID_INPUT, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } catch (IOException e) {
            finishWithError(op, startedAt, ST_IO_ERROR, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } catch (Exception e) {
            finishWithError(op, startedAt, ST_CRYPTO_ERROR, e);
            safeInsertIgnoreIfDbFails(op);
            throw e;

        } finally {
            if (pw != null) Arrays.fill(pw, '\0');
        }
    }

    private Path buildCiphertextPath(Path inputFile) {
        String original = inputFile.getFileName().toString();
        String ts = String.valueOf(System.currentTimeMillis());
        String outName = original + "." + ts + ".enc";
        return storageDir.resolve(outName);
    }

    // startedAt может быть null (если упали до crypto-таймера)
    private static void finishWithError(Operation op, Instant startedAt, String status, Exception e) {
        Instant finished = Instant.now();

        if (startedAt == null) {
            op.setStartedAt(finished);
            op.setFinishedAt(finished);
            op.setDurationMs(0);
        } else {
            op.setStartedAt(startedAt);
            op.setFinishedAt(finished);
            op.setDurationMs((int) Duration.between(startedAt, finished).toMillis());
        }

        op.setStatus(status);
        op.setErrorMessage(shortMessage(e));
    }

    private void safeInsertIgnoreIfDbFails(Operation op) {
        try {
            operationsDao.insert(op);
        } catch (Exception ignored) {
            // если БД умерла — логировать уже некуда
        }
    }

    private static String shortMessage(Exception e) {
        String msg = e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "" : e.getMessage());
        return msg.length() > 500 ? msg.substring(0, 500) : msg;
    }
}
