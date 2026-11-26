package cryptolearn.db;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

public class Database {

    private static final Properties PROPS = new Properties();
    private static final String URL;
    private static final String USER;
    private static final String PASSWORD;

    static {
        try (InputStream in = Database.class
                .getClassLoader()
                .getResourceAsStream("application.properties")) {

            if (in == null) {
                throw new IllegalStateException("application.properties not found on classpath");
            }
            PROPS.load(in);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load application.properties", e);
        }

        // 2) Явно загружаем JDBC-драйвер PostgreSQL (можно и без этого, но ок)
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("PostgreSQL JDBC driver not found", e);
        }

        //Читаем значения из properties
        String propUrl  = PROPS.getProperty("db.url");
        String propUser = PROPS.getProperty("db.user");

        // 4) ENV override (Docker): DB_URL / DB_USER / DB_PASSWORD
        // Если env нет — используем properties.
        String envUrl  = getenv("DB_URL");
        String envUser = getenv("DB_USER");

        URL = (envUrl != null) ? envUrl : propUrl;
        USER = (envUser != null) ? envUser : propUser;
        PASSWORD = getenv("DB_PASSWORD");

        if (PASSWORD == null) {
            throw new IllegalStateException("DB_PASSWORD is required");
        }
    }

    private static String getenv(String name) {
        String v = System.getenv(name);
        if (v == null) return null;
        v = v.trim();
        return v.isEmpty() ? null : v;
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    // Инициализация схемы БД: создаём таблицы, если их ещё нет
    public static void init() throws SQLException {
        try (Connection conn = getConnection();
             Statement st = conn.createStatement()) {

            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS operations (
                  id              BIGSERIAL PRIMARY KEY,
                  operation_type  VARCHAR(32) NOT NULL,
                  algorithm       VARCHAR(64),
                  kdf             VARCHAR(64),
                  kdf_iterations  INTEGER,
                  status          VARCHAR(16) NOT NULL,
                  error_message   TEXT,
                  ciphertext_path TEXT
                );
                """);

            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS operation_metrics (
                  operation_id      BIGINT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
                  input_size_bytes  BIGINT,
                  output_size_bytes BIGINT,
                  started_at        TIMESTAMPTZ,
                  finished_at       TIMESTAMPTZ,
                  duration_ms       INTEGER
                );
                """);

            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS crypto_details (
                  operation_id BIGINT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
                  salt         BYTEA,
                  nonce        BYTEA
                );
                """);

            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_operations_type ON operations(operation_type);");
            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_operations_status ON operations(status);");
        }
    }
}
