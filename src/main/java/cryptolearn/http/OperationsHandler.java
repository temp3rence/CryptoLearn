package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cryptolearn.dao.OperationsDao;

import java.io.IOException;

public class OperationsHandler implements HttpHandler {

    private final OperationsDao dao;

    public OperationsHandler(OperationsDao dao) {
        this.dao = dao;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        try {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                JsonSupport.writeJson(ex, 405, JsonSupport.error("METHOD_NOT_ALLOWED", "Use GET"));
                return;
            }

            int limit = 20;
            String q = ex.getRequestURI().getQuery();
            if (q != null && q.contains("limit=")) {
                try {
                    String raw = q.substring(q.indexOf("limit=") + 6);
                    raw = raw.replaceAll("[^0-9]", "");
                    if (!raw.isBlank()) limit = Integer.parseInt(raw);
                } catch (Exception ignored) {}
            }
            if (limit < 1) limit = 1;
            if (limit > 200) limit = 200;

            JsonSupport.writeJson(ex, 200, dao.last(limit));

        } catch (Exception e) {
            JsonSupport.writeJson(ex, 500, JsonSupport.error("DB_ERROR", safeMsg(e)));
        }
    }

    private static String safeMsg(Exception e) {
        String m = e.getMessage();
        if (m == null) m = e.getClass().getSimpleName();
        return m.length() > 500 ? m.substring(0, 500) : m;
    }
}
