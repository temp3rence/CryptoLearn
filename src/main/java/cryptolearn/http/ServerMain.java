package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import cryptolearn.crypto.EncryptedFileCodec;
import cryptolearn.crypto.SafeBoxCryptoService;
import cryptolearn.dao.OperationsDao;
import cryptolearn.db.Database;
import cryptolearn.logging.AppLogger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Точка входа HTTP-сервера CryptoLearn.
 */
public final class ServerMain {

    private static final Logger LOG = Logger.getLogger(ServerMain.class.getName());

    public static void main(String[] args) throws Exception {
        AppLogger.init();
        Database.init();
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));

        SafeBoxCryptoService crypto = new SafeBoxCryptoService();
        EncryptedFileCodec codec = new EncryptedFileCodec();
        OperationsDao operationsDao = new OperationsDao();

        server.createContext("/", new StaticFileHandler());

        server.createContext("/api/health", ServerMain::handleHealth);

        server.createContext(
                "/api/safebox/encrypt",
                new EncryptHandler(crypto, codec, operationsDao)
        );

        server.createContext(
                "/api/safebox/decrypt",
                new DecryptHandler(crypto, codec, operationsDao)
        );

        server.createContext(
                "/api/operations",
                new OperationsHandler(operationsDao)
        );

        server.createContext(
                "/api/admin/summary",
                new AdminSummaryHandler(operationsDao)
        );

        server.start();
        LOG.info("CryptoLearn HTTP server started on http://localhost:" + port);
    }

    /**
     * Простейший health-check: GET /api/health → "OK".
     */
    private static void handleHealth(HttpExchange ex) throws IOException {
        try {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.sendResponseHeaders(405, -1);
                return;
            }

            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Health-check handler failed", e);
            throw e;
        } finally {
            ex.close();
        }
    }
}
