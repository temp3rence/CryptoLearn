package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cryptolearn.logging.AppLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Простой обработчик статики.
 *
 * - GET /               -> static/index.html
 * - GET /static/...     -> static/...
 *
 * Все файлы берём из classpath (src/main/resources/static).
 */
public final class StaticFileHandler implements HttpHandler {

    private static final Logger LOG_HTTP = AppLogger.http();
    private static final Logger LOG_ERR  = AppLogger.error();

    @Override
    public void handle(HttpExchange ex) throws IOException {
        long startedNs = System.nanoTime();
        int status = 500;

        try {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())
                    && !"HEAD".equalsIgnoreCase(ex.getRequestMethod())) {
                status = 405;
                ex.sendResponseHeaders(status, -1);
                return;
            }

            URI uri = ex.getRequestURI();
            String path = uri.getPath(); // /, /static/app.js, /favicon.ico etc.

            String resourcePath = mapPathToResource(path);
            if (resourcePath == null) {
                status = 404;
                sendText(ex, status, "Not Found");
                return;
            }

            String contentType = detectContentType(resourcePath);
            ex.getResponseHeaders().set("Content-Type", contentType + "; charset=utf-8");

            try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    status = 404;
                    sendText(ex, status, "Not Found");
                    return;
                }

                if ("HEAD".equalsIgnoreCase(ex.getRequestMethod())) {
                    ex.sendResponseHeaders(200, -1);
                    status = 200;
                    return;
                }

                byte[] buf = is.readAllBytes();
                status = 200;
                ex.sendResponseHeaders(status, buf.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(buf);
                }
            }

        } catch (Exception e) {
            LOG_ERR.log(Level.SEVERE, "StaticFileHandler failed", e);
            status = 500;
            sendText(ex, status, "Internal Server Error");
        } finally {
            ex.close();
            long totalMs = (System.nanoTime() - startedNs) / 1_000_000L;
            LOG_HTTP.info(String.format("STATIC %s %s status=%d totalMs=%d",
                    ex.getRequestMethod(), ex.getRequestURI().getPath(), status, totalMs));
        }
    }

    /**
     * Маппинг URL → ресурса в classpath.
     */
    private String mapPathToResource(String path) {
        if (path == null || path.isEmpty() || "/".equals(path)) {
            // главная страница
            return "static/index.html";
        }

        if (path.startsWith("/static/")) {
            // обрезаем префикс /static/ → static/...
            return "static" + path.substring("/static".length());
        }

        // favicon можно просто проигнорировать
        if ("/favicon.ico".equals(path)) {
            return null;
        }

        // всё остальное, что не /api/... — 404
        return null;
    }

    /**
     * Простейшее определение content-type по расширению.
     */
    private String detectContentType(String resourcePath) {
        String lower = resourcePath.toLowerCase();
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".js"))   return "application/javascript";
        if (lower.endsWith(".css"))  return "text/css";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".png"))  return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".svg"))  return "image/svg+xml";
        return "application/octet-stream";
    }

    private void sendText(HttpExchange ex, int status, String text) throws IOException {
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        if ("HEAD".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(status, -1);
            return;
        }
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }
}
