package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cryptolearn.crypto.EncryptedFileCodec;
import cryptolearn.crypto.SafeBoxCryptoService;
import cryptolearn.dao.OperationsDao;
import cryptolearn.logging.AppLogger;
import cryptolearn.model.Operation;
import cryptolearn.service.SafeBoxService;

import javax.crypto.AEADBadTagException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Обработчик POST /api/safebox/decrypt.
 */
public final class DecryptHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB
    private static final Logger LOG_HTTP = AppLogger.http();
    private static final Logger LOG_ERR = AppLogger.error();

    private final SafeBoxCryptoService crypto;
    private final EncryptedFileCodec codec;
    private final OperationsDao operationsDao;

    public DecryptHandler(SafeBoxCryptoService crypto,
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

            DecryptRequest req = JsonSupport.readJson(ex, DecryptRequest.class, MAX_BODY_BYTES);

            if (req.password == null || req.password.isBlank()) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "password is required");
                return;
            }
            if (req.encryptedFileBase64 == null || req.encryptedFileBase64.isBlank()) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "encryptedFileBase64 is required");
                return;
            }

            String filename = (req.filename == null || req.filename.isBlank())
                    ? "output.bin"
                    : req.filename;

            byte[] encBytes;
            try {
                encBytes = Base64.getDecoder().decode(req.encryptedFileBase64);
            } catch (IllegalArgumentException e) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "encryptedFileBase64 is not valid base64");
                return;
            }

            passwordChars = req.password.toCharArray();

            EncryptedFileCodec.ParsedEncryptedFile parsed;
            try (ByteArrayInputStream bais = new ByteArrayInputStream(encBytes)) {
                parsed = codec.read(bais);
            } catch (IOException e) {
                httpStatus = 400;
                JsonSupport.writeProblem(ex, httpStatus, "INVALID_INPUT", "encryptedFileBase64 is not a valid .enc file");
                return;
            }

            Instant startCrypto = Instant.now();
            SafeBoxCryptoService.EncryptResult params =
                    new SafeBoxCryptoService.EncryptResult(
                            parsed.ciphertext(),
                            parsed.salt(),
                            parsed.nonce(),
                            parsed.iterations()
                    );

            byte[] plaintext;
            try {
                plaintext = crypto.decrypt(params, passwordChars);
            } catch (AEADBadTagException e) {
                long cryptoDurationMs = Duration.between(startCrypto, Instant.now()).toMillis();
                httpStatus = 401;
                DecryptResponse resp = new DecryptResponse(
                        "ERROR",
                        "AUTH_FAILED",
                        filename,
                        null,
                        cryptoDurationMs
                );
                JsonSupport.writeJson(ex, httpStatus, resp);

                long totalMs = (System.nanoTime() - startedNs) / 1_000_000L;
                LOG_HTTP.info(String.format(
                        "session=%s POST /api/safebox/decrypt status=%d filename=%s auth_failed=true cryptoMs=%d totalMs=%d",
                        sessionId,
                        httpStatus,
                        filename,
                        cryptoDurationMs,
                        totalMs
                ));
                return;
            }

            long cryptoDurationMs = Duration.between(startCrypto, Instant.now()).toMillis();

            String plaintextBase64 = Base64.getEncoder().encodeToString(plaintext);

            // Пишем SUCCESS-операцию в БД
            try {
                Operation op = new Operation();
                op.setOperationType(SafeBoxService.OP_DECRYPT);
                op.setAlgorithm(SafeBoxService.ALG_AES_GCM);
                op.setKdf(SafeBoxService.KDF_PBKDF2_SHA256);

                op.setInputSizeBytes((long) encBytes.length);
                op.setOutputSizeBytes((long) plaintext.length);

                op.setKdfIterations(parsed.iterations());
                op.setSalt(parsed.salt());
                op.setNonce(parsed.nonce());

                op.setStartedAt(startCrypto);
                op.setFinishedAt(Instant.now());
                op.setDurationMs((int) cryptoDurationMs);

                op.setCiphertextPath("API_INLINE:" + filename);

                op.setStatus(SafeBoxService.ST_SUCCESS);
                op.setErrorMessage(null);

                operationsDao.insert(op);
            } catch (Exception dbEx) {
                LOG_ERR.log(Level.WARNING, "Failed to insert decrypt Operation into DB", dbEx);
            }

            DecryptResponse resp = new DecryptResponse(
                    "SUCCESS",
                    null,
                    filename,
                    plaintextBase64,
                    cryptoDurationMs
            );

            httpStatus = 200;
            JsonSupport.writeJson(ex, httpStatus, resp);

            long totalMs = (System.nanoTime() - startedNs) / 1_000_000L;
            LOG_HTTP.info(String.format(
                    "session=%s POST /api/safebox/decrypt status=%d filename=%s encBytes=%d plainBytes=%d cryptoMs=%d totalMs=%d",
                    sessionId,
                    httpStatus,
                    filename,
                    encBytes.length,
                    plaintext.length,
                    cryptoDurationMs,
                    totalMs
            ));

        } catch (Exception e) {
            LOG_ERR.log(Level.SEVERE, "Error in /api/safebox/decrypt handler", e);
            httpStatus = 500;
            JsonSupport.writeProblem(ex, httpStatus, "SERVER_ERROR", e.getMessage());
        } finally {
            if (passwordChars != null) {
                java.util.Arrays.fill(passwordChars, '\0');
            }
            ex.close();
        }
    }

    public record DecryptRequest(
            String password,
            String encryptedFileBase64,
            String filename
    ) {
    }

    public record DecryptResponse(
            String status,
            String errorCode,
            String filename,
            String plaintextBase64,
            long durationMs
    ) {
    }
}
