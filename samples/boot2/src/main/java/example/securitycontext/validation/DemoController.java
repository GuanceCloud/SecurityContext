package example.securitycontext.validation;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {
    private final DataSource dataSource;

    public DemoController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/sql")
    public Map<String, Object> dynamicSql(@RequestParam(defaultValue = "guest") String value) throws Exception {
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return result("dynamic-sql", sql, resultSet.getInt(1));
        }
    }

    @GetMapping("/sql/parameterized")
    public Map<String, Object> parameterizedSql(@RequestParam(defaultValue = "guest") String value) throws Exception {
        String sql = "SELECT COUNT(*) FROM demo_users WHERE name = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, value);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return result("parameterized-sql", sql, resultSet.getInt(1));
            }
        }
    }

    @GetMapping("/sql/constant")
    public Map<String, Object> constantSql() throws Exception {
        String sql = "SELECT COUNT(*) FROM demo_users";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return result("constant-sql", sql, resultSet.getInt(1));
        }
    }

    @GetMapping("/command")
    public Map<String, Object> command(@RequestParam(defaultValue = "printf security-command") String value)
            throws Exception {
        Process process = Runtime.getRuntime().exec(new String[] {"sh", "-c", value});
        String output = readLimited(process.getInputStream());
        process.waitFor(3, TimeUnit.SECONDS);
        return result("shell-command", output, process.exitValue());
    }

    @GetMapping("/command/lc")
    public Map<String, Object> loginShellCommand(@RequestParam(defaultValue = "printf security-command-lc") String value)
            throws Exception {
        Process process = Runtime.getRuntime().exec(new String[] {"sh", "-lc", value});
        String output = readLimited(process.getInputStream());
        process.waitFor(3, TimeUnit.SECONDS);
        return result("shell-command-lc", output, process.exitValue());
    }

    @GetMapping("/command/safe")
    public Map<String, Object> safeCommand(@RequestParam(defaultValue = "security-argument") String value)
            throws Exception {
        Process process = new ProcessBuilder("printf", "%s", value).start();
        String output = readLimited(process.getInputStream());
        process.waitFor(3, TimeUnit.SECONDS);
        return result("fixed-command", output, process.exitValue());
    }

    @GetMapping("/fetch")
    public Map<String, Object> fetch(@RequestParam String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
        connection.setConnectTimeout(1500);
        connection.setReadTimeout(1500);
        connection.setRequestMethod("GET");
        try (InputStream input = connection.getInputStream()) {
            return result("url-connection", readLimited(input), connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    @GetMapping("/fetch/query")
    public Map<String, Object> fetchQuery(@RequestParam String query) throws Exception {
        URI target = URI.create("http://127.0.0.1:8080/health?value=" + query);
        HttpURLConnection connection = (HttpURLConnection) target.toURL().openConnection();
        connection.setConnectTimeout(1500);
        connection.setReadTimeout(1500);
        try (InputStream input = connection.getInputStream()) {
            return result("url-query", readLimited(input), connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    @GetMapping("/fetch/address")
    public Map<String, Object> fetchAddress(@RequestParam String host) throws Exception {
        URI target = URI.create("http://" + host + "/health");
        HttpURLConnection connection = (HttpURLConnection) target.toURL().openConnection();
        connection.setConnectTimeout(1500);
        connection.setReadTimeout(1500);
        try (InputStream input = connection.getInputStream()) {
            return result("url-address", readLimited(input), connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    @GetMapping("/fetch/construct")
    public Map<String, Object> constructUrl(@RequestParam String url) {
        URI target = URI.create(url);
        return result("url-construct", target.toString(), target.getHost());
    }

    @GetMapping("/file/read")
    public Map<String, Object> readFile(@RequestParam String path) throws Exception {
        try (InputStream input = new FileInputStream(path)) {
            return result("file-read", readLimited(input), path);
        }
    }

    @GetMapping("/file/write")
    public Map<String, Object> writeFile(@RequestParam String path,
                                         @RequestParam(defaultValue = "security-file") String value)
        throws Exception {
        Path target = Paths.get(path);
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (OutputStream output = Files.newOutputStream(target)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
        }
        return result("file-write", path, value.length());
    }

    @PostMapping(value = "/json", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> json(@RequestBody Map<String, Object> body) {
        Object raw = body.get("value");
        String value = raw == null ? "" : String.valueOf(raw);
        String transformed = String.format("json:%s", value).replace("json:", "");
        return result("json", transformed.substring(0, transformed.length()), body.size());
    }

    @GetMapping("/transform")
    public Map<String, Object> transform(@RequestParam(defaultValue = "security") String value) {
        String transformed = new StringBuilder("prefix:").append(value).append(":suffix").toString();
        transformed = transformed.replace("prefix:", "").replace(":suffix", "");
        return result("transform", transformed, transformed.length());
    }

    @GetMapping("/bytecode")
    public Map<String, Object> bytecodeFixture(@RequestParam(defaultValue = "security-bytecode") String value) {
        long count = value == null ? 0L : value.length() * 3L;
        double ratio = count / 2.0d;
        StringBuilder builder = new StringBuilder("fixture:");
        try {
            ConstructorFixture fixture = new ConstructorFixture(value);
            if ((count & 1L) == 0L) {
                builder.append(fixture.text());
            } else {
                builder.append(fixture.text().substring(0, fixture.text().length()));
            }
            builder.append(':').append(count).append(':').append(ratio);
        } finally {
            builder.append(":finally");
        }
        return result("bytecode", builder.toString(), count);
    }

    private static final class ConstructorFixture extends ConstructorBase {
        private final String text;

        private ConstructorFixture(String input) {
            super();
            if (input == null || input.length() == 0) {
                this.text = "empty";
            } else {
                this.text = input;
            }
        }

        private String text() {
            return text;
        }
    }

    private static class ConstructorBase {
        private ConstructorBase() {
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
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        char[] buffer = new char[256];
        int read;
        while (output.length() < 4096 && (read = reader.read(buffer, 0, Math.min(buffer.length, 4096 - output.length()))) >= 0) {
            output.append(buffer, 0, read);
        }
        return output.toString();
    }
}
