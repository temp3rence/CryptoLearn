package cryptolearn.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Кодек формата .enc:
 * [MAGIC "CL"][VERSION=1][iterations:int][saltLen:byte][nonceLen:byte][salt][nonce][ciphertext+tag]
 */
public final class EncryptedFileCodec {
    private static final byte MAGIC_1 = 'C';
    private static final byte MAGIC_2 = 'L';
    private static final byte VERSION = 1;
    private static final int MAX_SALT_LEN = 64;
    private static final int MAX_NONCE_LEN = 32;

    public EncryptedFileCodec() {
    }

    /**
     * Запись .enc структуры в OutputStream.
     */
    public void write(OutputStream out,
                      int iterations,
                      byte[] salt,
                      byte[] nonce,
                      byte[] ciphertext) throws IOException {

        if (salt == null || nonce == null || ciphertext == null) {
            throw new IllegalArgumentException("salt/nonce/ciphertext must not be null");
        }
        if (salt.length == 0 || nonce.length == 0) {
            throw new IllegalArgumentException("salt/nonce must not be empty");
        }
        if (salt.length > MAX_SALT_LEN) {
            throw new IllegalArgumentException("salt too long: " + salt.length);
        }
        if (nonce.length > MAX_NONCE_LEN) {
            throw new IllegalArgumentException("nonce too long: " + nonce.length);
        }

        DataOutputStream dos = new DataOutputStream(out);

        // MAGIC "CL"
        dos.writeByte(MAGIC_1);
        dos.writeByte(MAGIC_2);

        // VERSION
        dos.writeByte(VERSION);

        // iterations (int, 4 байта)
        dos.writeInt(iterations);

        // длины salt / nonce (по 1 байту)
        dos.writeByte(salt.length);
        dos.writeByte(nonce.length);

        // salt и nonce
        dos.write(salt);
        dos.write(nonce);

        // ciphertext (GCM ciphertext + tag)
        dos.write(ciphertext);

        dos.flush();
    }

    public void write(Path out,
                      int iterations,
                      byte[] salt,
                      byte[] nonce,
                      byte[] ciphertext) throws IOException {
        try (OutputStream os = Files.newOutputStream(out)) {
            write(os, iterations, salt, nonce, ciphertext);
        }
    }

    /**
     * Чтение .enc структуры из InputStream.
     */
    public ParsedEncryptedFile read(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);

        int m1 = dis.readUnsignedByte();
        int m2 = dis.readUnsignedByte();
        if (m1 != MAGIC_1 || m2 != MAGIC_2) {
            throw new IOException("Invalid magic header");
        }

        int version = dis.readUnsignedByte();
        if (version != VERSION) {
            throw new IOException("Unsupported version: " + version);
        }

        int iterations = dis.readInt();

        int saltLen = dis.readUnsignedByte();
        int nonceLen = dis.readUnsignedByte();

        if (saltLen <= 0 || saltLen > MAX_SALT_LEN) {
            throw new IOException("Invalid salt length: " + saltLen);
        }
        if (nonceLen <= 0 || nonceLen > MAX_NONCE_LEN) {
            throw new IOException("Invalid nonce length: " + nonceLen);
        }

        byte[] salt = dis.readNBytes(saltLen);
        if (salt.length != saltLen) {
            throw new IOException("Unexpected EOF while reading salt");
        }

        byte[] nonce = dis.readNBytes(nonceLen);
        if (nonce.length != nonceLen) {
            throw new IOException("Unexpected EOF while reading nonce");
        }

        byte[] ciphertext = dis.readAllBytes();
        if (ciphertext.length == 0) {
            throw new IOException("Empty ciphertext");
        }

        return new ParsedEncryptedFile(iterations, salt, nonce, ciphertext);
    }

    public ParsedEncryptedFile read(Path in) throws IOException {
        try (InputStream is = Files.newInputStream(in)) {
            return read(is);
        }
    }

    public record ParsedEncryptedFile(
            int iterations,
            byte[] salt,
            byte[] nonce,
            byte[] ciphertext
    ) {
    }
}
