package example.securitycontext.validation;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import javax.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api")
public class AdvancedController {
    private final DataSource dataSource;

    public AdvancedController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/sql/prepared-template")
    public Map<String, Object> preparedTemplate(@RequestParam(defaultValue = "guest") String value)
            throws Exception {
        String template = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(template);
             ResultSet resultSet = statement.executeQuery()) {
            resultSet.next();
            return result("prepared-template", template, resultSet.getInt(1));
        }
    }

    @PostMapping("/json/sql")
    public Map<String, Object> jsonSql(@RequestBody Map<String, Object> body) throws Exception {
        String value = String.valueOf(body.get("value"));
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "json-sql");
    }

    @PostMapping(value = "/raw/reader/sql", consumes = "text/plain")
    public Map<String, Object> rawReaderSql(HttpServletRequest request) throws Exception {
        String value = request.getReader().readLine();
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "raw-reader-sql");
    }

    @PostMapping(value = "/raw/jackson/sql", consumes = "application/json")
    public Map<String, Object> rawJacksonSql(HttpServletRequest request) throws Exception {
        SqlPayload body = new ObjectMapper().readValue(request.getInputStream(), SqlPayload.class);
        String value = body == null ? "" : body.getValue();
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "raw-jackson-sql");
    }

    @PostMapping("/pojo/sql")
    public Map<String, Object> pojoSql(@RequestBody SqlPayload body) throws Exception {
        String value = body == null ? "" : body.getValue();
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "pojo-sql");
    }

    @PostMapping("/list/sql")
    public Map<String, Object> listSql(@RequestBody List<String> body) throws Exception {
        String value = body == null || body.isEmpty() ? "" : body.get(0);
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "list-sql");
    }

    @PostMapping(value = "/text/sql", consumes = "text/plain")
    public Map<String, Object> textSql(@RequestBody String body) throws Exception {
        String value = body == null ? "" : body;
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "text-sql");
    }

    @GetMapping("/header/sql")
    public Map<String, Object> headerSql(@RequestHeader("X-Security-Value") String value) throws Exception {
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "header-sql");
    }

    @PostMapping("/form/sql")
    public Map<String, Object> formSql(@RequestParam(defaultValue = "guest") String value) throws Exception {
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "form-sql");
    }

    @PostMapping("/model/sql")
    public Map<String, Object> modelSql(@ModelAttribute FormPayload body) throws Exception {
        String value = body == null ? "" : body.getValue();
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        return execute(sql, "model-sql");
    }

    @GetMapping("/file/normalize")
    public Map<String, Object> normalizedFile(@RequestParam String path) throws Exception {
        Path normalized = Paths.get(path).normalize();
        try (InputStream input = new FileInputStream(normalized.toFile())) {
            return result("file-normalize", readLimited(input), normalized.toString());
        }
    }

    @GetMapping("/async/sql")
    public Map<String, Object> asyncSql(@RequestParam(defaultValue = "guest") String value) throws Exception {
        CompletableFuture<Map<String, Object>> future = CompletableFuture.supplyAsync(() -> {
            try {
                String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
                return execute(sql, "async-sql");
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        });
        return future.get(3, TimeUnit.SECONDS);
    }

    @GetMapping("/async/servlet")
    public org.springframework.web.context.request.async.DeferredResult<Map<String, Object>> servletAsync(
            @RequestParam(defaultValue = "guest") String value) {
        org.springframework.web.context.request.async.DeferredResult<Map<String, Object>> result =
                new org.springframework.web.context.request.async.DeferredResult<>(3000L);
        CompletableFuture.runAsync(() -> {
            try {
                String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
                result.setResult(execute(sql, "servlet-async-sql"));
            } catch (Exception error) {
                result.setErrorResult(error);
            }
        });
        return result;
    }

    @GetMapping("/exception")
    public Map<String, Object> exception(@RequestParam(defaultValue = "validation") String value) {
        throw new IllegalStateException("intentional validation exception: " + value);
    }

    @GetMapping("/fetch/response-sql")
    public Map<String, Object> responseSql(@RequestParam String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
        connection.setConnectTimeout(1500);
        connection.setReadTimeout(1500);
        String response;
        try (InputStream input = connection.getInputStream()) {
            response = readLimited(input);
        } finally {
            connection.disconnect();
        }
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + response + "'";
        Map<String, Object> result = execute(sql, "response-sql-control");
        result.put("response", response);
        return result;
    }

    @GetMapping("/fetch/rest-template")
    public String restTemplate(@RequestParam String mode, @RequestParam String value) {
        RestTemplate client = new RestTemplate();
        if ("uri".equals(mode)) return client.getForObject(URI.create(value), String.class);
        if ("interface".equals(mode)) {
            org.springframework.web.client.RestOperations operations = client;
            return operations.getForObject(value, String.class);
        }
        if ("query".equals(mode)) return client.getForObject("http://127.0.0.1:8080/health?q=" + value, String.class);
        if ("body".equals(mode)) return client.postForObject("http://127.0.0.1:8080/api/rest-target", value, String.class);
        return client.getForObject(value, String.class);
    }

    @PostMapping("/rest-target")
    public String restTarget() {
        return "rest-target-ok";
    }

    @GetMapping("/fetch/rest-template-response-sql")
    public Map<String, Object> restTemplateResponseSql(@RequestParam String url) throws Exception {
        String response = new RestTemplate().getForObject(url, String.class);
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + response + "'";
        Map<String, Object> result = execute(sql, "rest-template-response-sql-control");
        result.put("response", response);
        return result;
    }

    public static class SqlPayload {
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    public static class FormPayload {
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    private Map<String, Object> execute(String sql, String operation) throws Exception {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return result(operation, sql, resultSet.getInt(1));
        }
    }

    private static Map<String, Object> result(String operation, Object value, Object detail) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("operation", operation);
        response.put("value", value);
        response.put("detail", detail);
        return response;
    }

    private static String readLimited(InputStream input) throws Exception {
        byte[] buffer = new byte[4096];
        int count = input.read(buffer);
        return count < 0 ? "" : new String(buffer, 0, count, StandardCharsets.UTF_8);
    }
}
