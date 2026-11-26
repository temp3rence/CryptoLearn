package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cryptolearn.crypto.EncryptedFileCodec;
import cryptolearn.crypto.SafeBoxCryptoService;
import cryptolearn.dao.OperationsDao;
import cryptolearn.logging.AppLogger;
import cryptolearn.model.Operation;
import cryptolearn.service.SafeBoxService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Обработчик POST /api/safebox/encrypt.
 * На вход: JSON с password + plaintextBase64 (+ необязательный filename).
 * На выход: JSON с base64 всего .enc файла и временем шифрования.
 */
public final class EncryptHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB
    private static final Logger LOG_HTTP = AppLogger.http();
    private static final Logger LOG_ERR = AppLogger.error();

    private final SafeBoxCryptoService crypto;
    private final EncryptedFileCodec codec;
    private final OperationsDao operationsDao;

    public EncryptHandler(SafeBoxCryptoService crypto,
                          EncryptedFileCodec codec,
                          OperationsDao operationsDao) {
        this.crypto = crypto;
        this.codec = codec;
        this.operationsDao = operationsDao;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        long startedNs = System.nanoTime();
        char[] passwordChars = null;
        int httpStatus = 500;

        String sessionId = ex.getRequestHeaders().getFirst("X-Session-Id");

        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                httpStatus = 405;
                ex.sendResponseHeaders(httpStatus, -1);
                return;
            }

            // 1. Читаем JSON-запрос
            EncryptRequest req = JsonSupport.readJson(ex, EncryptRequest.class, MAX_BODY_BYTES);

            if (req.password == null || req.password.isBlank()) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "password is required");
                return;
            }
            if (req.plaintextBase64 == null || req.plaintextBase64.isBlank()) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "plaintextBase64 is required");
                return;
            }

            String filename = (req.filename == null || req.filename.isBlank())
                    ? "input.bin"
                    : req.filename;

            // 2. base64 → байты
            byte[] plaintext;
            try {
                plaintext = Base64.getDecoder().decode(req.plaintextBase64);
            } catch (IllegalArgumentException e) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "plaintextBase64 is not valid base64");
                return;
            }

            passwordChars = req.password.toCharArray();

            // 3. Шифрование (меряем только крипту)
            Instant startCrypto = Instant.now();
            SafeBoxCryptoService.EncryptResult enc = crypto.encrypt(plaintext, passwordChars);
            long cryptoDurationMs = Duration.between(startCrypto, Instant.now()).toMillis();

            // 4. Собираем .enc в память через EncryptedFileCodec
            byte[] encBytes;
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                codec.write(baos, enc.iterations(), enc.salt(), enc.nonce(), enc.ciphertext());
                encBytes = baos.toByteArray();
            }

            // 5. .enc → base64 для JSON
            String encryptedFileBase64 = Base64.getEncoder().encodeToString(encBytes);

            // 6. Пишем Operation в БД (только SUCCESS)
            try {
                Operation op = new Operation();
                op.setOperationType(SafeBoxService.OP_ENCRYPT);
                op.setAlgorithm(SafeBoxService.ALG_AES_GCM);
                op.setKdf(SafeBoxService.KDF_PBKDF2_SHA256);

                op.setInputSizeBytes((long) plaintext.length);
                op.setOutputSizeBytes((long) encBytes.length);

                op.setKdfIterations(enc.iterations());
                op.setSalt(enc.salt());
                op.setNonce(enc.nonce());

                op.setStartedAt(startCrypto);
                op.setFinishedAt(Instant.now());
                op.setDurationMs((int) cryptoDurationMs);

                op.setCiphertextPath("API_INLINE:" + filename);

                op.setStatus(SafeBoxService.ST_SUCCESS);
                op.setErrorMessage(null);

                operationsDao.insert(op);
            } catch (Exception dbEx) {
                LOG_ERR.log(Level.WARNING, "Failed to insert encrypt Operation into DB", dbEx);
            }

            // 7. Ответ клиенту
            EncryptResponse resp = new EncryptResponse(
                    "SUCCESS",
                    null,
                    filename,
                    encryptedFileBase64,
                    cryptoDurationMs
            );

            httpStatus = 200;
            JsonSupport.writeJson(ex, httpStatus, resp);

            long totalMs = (System.nanoTime() - startedNs) / 1_000_000L;
            LOG_HTTP.info(String.format(
                    "session=%s POST /api/safebox/encrypt status=%d filename=%s inputBytes=%d encBytes=%d cryptoMs=%d totalMs=%d",
                    sessionId,
                    httpStatus,
                    filename,
                    plaintext.length,
                    encBytes.length,
                    cryptoDurationMs,
                    totalMs
            ));

        } catch (Exception e) {
            LOG_ERR.log(Level.SEVERE, "Error in /api/safebox/encrypt handler", e);
            httpStatus = 500;
            JsonSupport.writeProblem(ex, httpStatus, "SERVER_ERROR", e.getMessage());
        } finally {
            if (passwordChars != null) {
                java.util.Arrays.fill(passwordChars, '\0');
            }
            ex.close();
        }
    }

    public record EncryptRequest(
            String password,
            String plaintextBase64,
            String filename
    ) {
    }

    public record EncryptResponse(
            String status,
            String errorCode,
            String filename,
            String encryptedFileBase64,
            long durationMs
    ) {
    }
}
