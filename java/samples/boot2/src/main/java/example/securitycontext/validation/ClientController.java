package example.securitycontext.validation;

import java.util.LinkedHashMap;
import java.util.Map;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/fetch")
public class ClientController {
    @GetMapping("/apache4")
    public Map<String, Object> apache4(@RequestParam String url) throws Exception {
        try (org.apache.http.impl.client.CloseableHttpClient client = org.apache.http.impl.client.HttpClients.createDefault()) {
            org.apache.http.client.methods.HttpGet request = new org.apache.http.client.methods.HttpGet(url);
            try (org.apache.http.client.methods.CloseableHttpResponse response = client.execute(request)) {
                return result("apache4", response.getStatusLine().getStatusCode(),
                    response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity()));
            }
        }
    }

    @GetMapping("/apache5")
    public Map<String, Object> apache5(@RequestParam String url) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            try (CloseableHttpResponse response = client.execute(request)) {
                return result("apache5", response.getCode(), response.getEntity() == null ? "" : "body");
            }
        }
    }

    @GetMapping("/okhttp")
    public Map<String, Object> okhttp(@RequestParam String url) throws Exception {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url(url).get().build();
        try (Response response = client.newCall(request).execute()) {
            return result("okhttp", response.code(), response.body() == null ? "" : response.body().string());
        }
    }

    private static Map<String, Object> result(String operation, Object detail, Object body) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("operation", operation);
        response.put("detail", detail);
        response.put("value", body);
        return response;
    }
}
