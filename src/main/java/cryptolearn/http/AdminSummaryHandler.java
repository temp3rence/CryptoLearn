package cryptolearn.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cryptolearn.dao.OperationsDao;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AdminSummaryHandler implements HttpHandler {

    private final OperationsDao dao;

    public AdminSummaryHandler(OperationsDao dao) {
        this.dao = dao;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        try {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                JsonSupport.writeJson(ex, 405, JsonSupport.error("METHOD_NOT_ALLOWED", "Use GET"));
                return;
            }

            OperationsDao.Summary s = dao.summary();

            Map<String, Object> response = new HashMap<>();
            response.put("total", s.total());
            response.put("success", s.success());
            response.put("failed", s.failed());
            response.put("avgDurationMs", s.avgDurationMs());

            JsonSupport.writeJson(ex, 200, response);

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
