package cryptolearn.dao;

import cryptolearn.db.Database;
import cryptolearn.model.Operation;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class OperationsDao {

    public long insert(Operation op) throws SQLException {
        try (Connection conn = Database.getConnection()) {
            conn.setAutoCommit(false);
            try {
                long id = insertOperations(conn, op);
                insertMetrics(conn, id, op);
                insertCryptoDetails(conn, id, op);
                conn.commit();
                op.setId(id);
                return id;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        }
    }

    private long insertOperations(Connection conn, Operation op) throws SQLException {
        String sql = """
            INSERT INTO operations (
              operation_type, algorithm, kdf, kdf_iterations,
              status, error_message, ciphertext_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, op.getOperationType());
            ps.setString(2, op.getAlgorithm());
            ps.setString(3, op.getKdf());

            if (op.getKdfIterations() == null) ps.setNull(4, Types.INTEGER);
            else ps.setInt(4, op.getKdfIterations());

            ps.setString(5, op.getStatus());
            ps.setString(6, op.getErrorMessage());
            ps.setString(7, op.getCiphertextPath());

            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private void insertMetrics(Connection conn, long opId, Operation op) throws SQLException {
        String sql = """
            INSERT INTO operation_metrics (
              operation_id, input_size_bytes, output_size_bytes,
              started_at, finished_at, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
        """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, opId);

            if (op.getInputSizeBytes() == null) ps.setNull(2, Types.BIGINT);
            else ps.setLong(2, op.getInputSizeBytes());

            if (op.getOutputSizeBytes() == null) ps.setNull(3, Types.BIGINT);
            else ps.setLong(3, op.getOutputSizeBytes());

            if (op.getStartedAt() == null) {
                ps.setNull(4, Types.TIMESTAMP_WITH_TIMEZONE);
            } else {
                ps.setObject(
                        4,
                        OffsetDateTime.ofInstant(op.getStartedAt(), ZoneOffset.UTC)
                );
            }

            if (op.getFinishedAt() == null) {
                ps.setNull(5, Types.TIMESTAMP_WITH_TIMEZONE);
            } else {
                ps.setObject(
                        5,
                        OffsetDateTime.ofInstant(op.getFinishedAt(), ZoneOffset.UTC)
                );
            }

            if (op.getDurationMs() == null) ps.setNull(6, Types.INTEGER);
            else ps.setInt(6, op.getDurationMs());

            ps.executeUpdate();
        }
    }

    private void insertCryptoDetails(Connection conn, long opId, Operation op) throws SQLException {
        String sql = """
            INSERT INTO crypto_details (operation_id, salt, nonce)
            VALUES (?, ?, ?)
        """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, opId);

            if (op.getSalt() == null) ps.setNull(2, Types.BINARY);
            else ps.setBytes(2, op.getSalt());

            if (op.getNonce() == null) ps.setNull(3, Types.BINARY);
            else ps.setBytes(3, op.getNonce());

            ps.executeUpdate();
        }
    }

    public List<Operation> last(int limit) throws SQLException {
        String sql = """
            SELECT
              o.id,
              o.operation_type,
              o.algorithm,
              o.kdf,
              o.kdf_iterations,
              o.status,
              o.error_message,
              o.ciphertext_path,
              m.input_size_bytes,
              m.output_size_bytes,
              m.started_at,
              m.finished_at,
              m.duration_ms
            FROM operations o
            LEFT JOIN operation_metrics m ON m.operation_id = o.id
            ORDER BY o.id DESC
            LIMIT ?
        """;

        List<Operation> out = new ArrayList<>();
        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, limit);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Operation op = new Operation();
                    op.setId(rs.getLong("id"));
                    op.setOperationType(rs.getString("operation_type"));
                    op.setAlgorithm(rs.getString("algorithm"));
                    op.setKdf(rs.getString("kdf"));

                    int it = rs.getInt("kdf_iterations");
                    op.setKdfIterations(rs.wasNull() ? null : it);

                    op.setStatus(rs.getString("status"));
                    op.setErrorMessage(rs.getString("error_message"));
                    op.setCiphertextPath(rs.getString("ciphertext_path"));

                    long in = rs.getLong("input_size_bytes");
                    op.setInputSizeBytes(rs.wasNull() ? null : in);

                    long outSize = rs.getLong("output_size_bytes");
                    op.setOutputSizeBytes(rs.wasNull() ? null : outSize);

                    Timestamp s = rs.getTimestamp("started_at");
                    if (s != null) op.setStartedAt(s.toInstant());

                    Timestamp f = rs.getTimestamp("finished_at");
                    if (f != null) op.setFinishedAt(f.toInstant());

                    int dur = rs.getInt("duration_ms");
                    op.setDurationMs(rs.wasNull() ? null : dur);

                    out.add(op);
                }
            }
        }
        return out;
    }

    public Summary summary() throws SQLException {
        String sql = """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN o.status = 'SUCCESS' THEN 1 ELSE 0 END) AS success,
              SUM(CASE WHEN o.status <> 'SUCCESS' THEN 1 ELSE 0 END) AS failed,
              AVG(m.duration_ms) FILTER (WHERE o.status = 'SUCCESS') AS avg_duration_ms
            FROM operations o
            LEFT JOIN operation_metrics m ON m.operation_id = o.id
        """;

        try (Connection conn = Database.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            rs.next();
            long total = rs.getLong("total");
            long success = rs.getLong("success");
            long failed = rs.getLong("failed");

            Integer avg = null;
            Object o = rs.getObject("avg_duration_ms");
            if (o != null) avg = (int) Math.round(rs.getDouble("avg_duration_ms"));

            return new Summary(total, success, failed, avg);
        }
    }

    public record Summary(long total, long success, long failed, Integer avgDurationMs) {}
}
