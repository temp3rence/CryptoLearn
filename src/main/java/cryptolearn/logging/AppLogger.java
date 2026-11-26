package cryptolearn.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.*;

public final class AppLogger {

    private static final Logger HTTP_LOGGER = Logger.getLogger("cryptolearn.http");
    private static final Logger ERROR_LOGGER = Logger.getLogger("cryptolearn.error");

    private AppLogger() {
    }

    public static void init() throws IOException {
        LogManager.getLogManager().reset();

        Logger root = Logger.getLogger("");
        root.setLevel(Level.INFO);

        Path logsDir = Paths.get("logs");
        Files.createDirectories(logsDir);

        // Общий лог: INFO и выше
        FileHandler serverHandler = new FileHandler(
                logsDir.resolve("server.log").toString(),
                1_000_000,
                5,
                true
        );
        serverHandler.setFormatter(new SimpleFormatter());
        serverHandler.setLevel(Level.INFO);
        root.addHandler(serverHandler);

        // Лог ошибок: только WARNING и SEVERE
        FileHandler errorHandler = new FileHandler(
                logsDir.resolve("error.log").toString(),
                1_000_000,
                5,
                true
        );
        errorHandler.setFormatter(new SimpleFormatter());
        errorHandler.setLevel(Level.WARNING);
        root.addHandler(errorHandler);
    }

    public static Logger http() {
        return HTTP_LOGGER;
    }

    public static Logger error() {
        return ERROR_LOGGER;
    }
}
