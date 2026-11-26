package cryptolearn.model;

import java.time.Instant;

public class Operation {
    private Long id;                 // PK
    private String operationType;    // SAFEBOX_ENCRYPT / SAFEBOX_DECRYPT /
    private String algorithm;        // AES-256-GCM
    private String kdf;              // PBKDF2-HMAC-SHA256
    private Integer kdfIterations;   // 100_000
    private String status;           // SUCCESS / AUTH_FAILED / IO_ERROR / DB_ERROR / INVALID_INPUT ...
    private String errorMessage;
    private String ciphertextPath;

    // --- operation_metrics ---
    private Long inputSizeBytes;
    private Long outputSizeBytes;
    private Instant startedAt;
    private Instant finishedAt;
    private Integer durationMs;

    // --- crypto_details ---
    private byte[] salt;
    private byte[] nonce;

    // --- getters/setters ---

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getOperationType() { return operationType; }
    public void setOperationType(String operationType) { this.operationType = operationType; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getKdf() { return kdf; }
    public void setKdf(String kdf) { this.kdf = kdf; }

    public Integer getKdfIterations() { return kdfIterations; }
    public void setKdfIterations(Integer kdfIterations) { this.kdfIterations = kdfIterations; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public String getCiphertextPath() { return ciphertextPath; }
    public void setCiphertextPath(String ciphertextPath) { this.ciphertextPath = ciphertextPath; }

    public Long getInputSizeBytes() { return inputSizeBytes; }
    public void setInputSizeBytes(Long inputSizeBytes) { this.inputSizeBytes = inputSizeBytes; }

    public Long getOutputSizeBytes() { return outputSizeBytes; }
    public void setOutputSizeBytes(Long outputSizeBytes) { this.outputSizeBytes = outputSizeBytes; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getFinishedAt() { return finishedAt; }
    public void setFinishedAt(Instant finishedAt) { this.finishedAt = finishedAt; }

    public Integer getDurationMs() { return durationMs; }
    public void setDurationMs(Integer durationMs) { this.durationMs = durationMs; }

    public byte[] getSalt() { return salt; }
    public void setSalt(byte[] salt) { this.salt = salt; }

    public byte[] getNonce() { return nonce; }
    public void setNonce(byte[] nonce) { this.nonce = nonce; }
}
