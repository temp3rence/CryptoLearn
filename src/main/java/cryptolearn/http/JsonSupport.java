package cryptolearn.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.nio.charset.StandardCharsets;

public final class JsonSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private JsonSupport() {}

    public static <T> T readJson(HttpExchange ex, Class<T> clazz) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return MAPPER.readValue(in, clazz);
        }
    }

    public static <T> T readJson(HttpExchange ex, Class<T> clazz, int maxBytes) throws IOException {
        byte[] data = readAllBytesLimited(ex.getRequestBody(), maxBytes);
        if (data.length == 0) throw new EOFException("Empty request body");
        return MAPPER.readValue(data, clazz);
    }

    private static byte[] readAllBytesLimited(InputStream in, int maxBytes) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int total = 0;
            int r;
            while ((r = in.read(buf)) != -1) {
                total += r;
                if (total > maxBytes) {
                    throw new IOException("Request body too large (>" + maxBytes + " bytes)");
                }
                baos.write(buf, 0, r);
            }
            return baos.toByteArray();
        } finally {
            in.close();
        }
    }

    public static void writeJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] json = toJsonBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, json.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(json);
        }
    }

    public static void writeProblem(HttpExchange ex, int status, String code, String message) throws IOException {
        writeJson(ex, status, new ApiError(code, message));
    }

    public static ApiError error(String code, String message) {
        return new ApiError(code, message);
    }

    public record ApiError(String code, String message) {}

    private static byte[] toJsonBytes(Object body) throws JsonProcessingException {
        return MAPPER.writeValueAsBytes(body);
    }

    public static void writeText(HttpExchange ex, int status, String text) throws IOException {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(status, data.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(data);
        }
    }
}
