package io.securitycontext.core;

import static io.securitycontext.core.Values.map;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

public final class Events {
  public static final int SCHEMA_VERSION = 2;
  public static final int FINGERPRINT_VERSION = 2;
  public static final String PRODUCT = "SecurityContext";

  private static final java.time.format.DateTimeFormatter TIMESTAMP =
      new java.time.format.DateTimeFormatterBuilder().appendInstant(3).toFormatter();
  private Events() {}

  public static String timestamp(long epochMillis) { return TIMESTAMP.format(java.time.Instant.ofEpochMilli(epochMillis)); }
  public static String now() { return timestamp(System.currentTimeMillis()); }

  public static Map<String, Object> sink(String rule, String role, String function, String location) {
    String normalized = role;
    if (role.equals("template")) normalized = "sql_template";
    else if (role.equals("shell") || role.equals("shell_command")) normalized = "shell_script";
    else if (role.equals("argv") || role.equals("ordinary_argument")) normalized = "argument";
    else if (role.equals("unknown_target")) normalized = "destination_unknown";
    else if (role.equals("request_path") || role.equals("request_query") || role.equals("path_query")) normalized = "path_or_query";
    Map<String, Object> sink = map("function", function, "role", normalized, "location", location, "operation", "", "path_role", "", "input_part", "");
    if (rule.equals("http_request_input")) sink.put("input_part", role.equals("request_path") ? "path" : role.equals("request_query") ? "query" : "path_or_query");
    if (rule.equals("path_traversal")) {
      sink.put("role", "file_path");
      String name = function.toLowerCase(Locale.ROOT);
      String operation = "unknown";
      if (name.matches(".*(?:copy|\\.cp(?:sync)?$|\\.link(?:sync)?$).*")) operation = "copy";
      else if (name.matches(".*(?:rename|\\.move$).*")) operation = "rename";
      else if (name.matches(".*(?:delete|unlink|rmdir|\\.rm(?:sync)?$).*")) operation = "delete";
      else if (Arrays.asList("read", "write", "delete", "rename").contains(role)) operation = role;
      else if (role.equals("source") || name.matches(".*(?:inputstream|reader|directorystream|\\.read).*")) operation = "read";
      else if (role.equals("target") || name.matches(".*(?:outputstream|writer|\\.write).*")) operation = "write";
      sink.put("operation", operation);
      String pathRole = "unknown";
      if (role.equals("source") || role.equals("read")) pathRole = "source";
      else if (Arrays.asList("target", "write", "delete", "destination_path").contains(role)) pathRole = "target";
      else if (role.equals("file_path") && Arrays.asList("copy", "rename", "read").contains(operation)) pathRole = "source";
      else if (role.equals("file_path") && Arrays.asList("write", "delete").contains(operation)) pathRole = "target";
      sink.put("path_role", pathRole);
    }
    return sink;
  }

  public static String fingerprint(String applicationId, String language, String rule, Map<String, Object> sink, Iterable<String> signatures) {
    try {
      MessageDigest hash = MessageDigest.getInstance("SHA-256");
      List<String> parts = new ArrayList<>(Arrays.asList("2", applicationId, language, rule));
      for (String field : Arrays.asList("role", "function", "location", "operation", "path_role", "input_part")) parts.add(String.valueOf(sink.get(field)));
      TreeSet<String> sorted = new TreeSet<>();
      for (String signature : signatures) sorted.add(signature);
      parts.addAll(sorted);
      for (String part : parts) {
        byte[] value = unicode(part).getBytes(StandardCharsets.UTF_8);
        hash.update(ByteBuffer.allocate(4).putInt(value.length).array());
        hash.update(value);
      }
      StringBuilder result = new StringBuilder("finding-");
      for (byte value : hash.digest()) result.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
      return result.toString();
    } catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
  }

  private static String unicode(String value) {
    StringBuilder result = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (Character.isHighSurrogate(c) && i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) result.append(c).append(value.charAt(++i));
      else result.append(Character.isSurrogate(c) ? '\uFFFD' : c);
    }
    return result.toString();
  }

  public static String traceId(Object value, int length) {
    String text = value == null ? "" : String.valueOf(value).toLowerCase(Locale.ROOT);
    return text.length() == length && text.matches("[0-9a-f]+") && !text.matches("0+") ? text : "";
  }

  public static Map<String, Object> component(Map<String, Object> value, String applicationId) {
    if (value == null) value = java.util.Collections.emptyMap();
    return map("status", value.getOrDefault("status", "unresolved"), "sbom_id", value.getOrDefault("sbom_id", ""), "revision", value.get("revision"), "release_id", value.getOrDefault("release_id", ""), "application_id", value.getOrDefault("application_id", applicationId), "bom-ref", value.getOrDefault("bom-ref", ""), "reason", value.getOrDefault("reason", "resolved".equals(value.get("status")) ? "" : "component_not_resolved"), "observed_url", value.getOrDefault("observed_url", ""), "query", value.getOrDefault("query", ""));
  }

  public static Map<String, Object> request(Map<String, Object> value) {
    Map<String, Object> request = map("method", "", "route", "", "route_status", "unavailable", "status_code", null,
        "started_at", null, "ended_at", null, "framework", "", "transport", "", "error_type", "");
    if (value != null) request.putAll(value);
    return request;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> record(Map<String, Object> input) {
    Map<String, Object> event = new LinkedHashMap<>(input);
    Map<String, Object> identity = new LinkedHashMap<>(Identity.context());
    Object nested = event.remove("identity");
    if (nested instanceof Map) identity.putAll((Map<String, Object>) nested);
    identity.forEach(event::putIfAbsent);
    event.put("schema_version", SCHEMA_VERSION);
    event.putIfAbsent("observed_at", io.securitycontext.core.Events.now());
    String name = String.valueOf(event.get("event_name"));
    event.put("source", name.equals("app-dependencies-loaded") || name.startsWith("security.sbom.")
        ? "security_context_sbom" : "security_context");
    if (name.equals("security.dataflow.observed") || name.equals("security.collection.incomplete")) {
      event.put("request", request((Map<String, Object>) event.get("request")));
      String trace = traceId(event.get("trace_id"), 32);
      String server = trace.isEmpty() ? "" : traceId(event.get("server_span_id"), 16);
      event.put("trace_id", trace);
      event.put("server_span_id", server);
      event.put("current_span_id", trace.isEmpty() ? "" : traceId(event.get("current_span_id"), 16));
      Object flags = event.get("trace_flags");
      event.put("trace_flags", !server.isEmpty() && flags instanceof Number ? ((Number) flags).intValue() & 255 : 0);
      event.put("trace_availability", "not_guaranteed_by_trace_id");
    }
    if (name.equals("security.dataflow.observed")) {
      event.put("component", component((Map<String, Object>) event.get("component"), String.valueOf(event.get("application_id"))));
      event.putIfAbsent("stack", java.util.Collections.emptyList());
    }
    if (name.equals("security.collection.incomplete")) {
      Map<String, Object> counts = map("objects", null, "nodes", null, "sources", null, "findings", null, "retained_bytes", null);
      if (event.get("counts") instanceof Map) counts.putAll((Map<String, Object>) event.get("counts"));
      event.put("counts", counts);
      event.putIfAbsent("collection_status", "unknown");
    }
    if (name.equals("app-dependencies-loaded")) {
      event.putIfAbsent("status", "current");
      event.putIfAbsent("dropped_observations", 0);
    }
    if (name.equals("security.sbom.health")) {
      Map<String, Object> defaults = map("sbom_id", "", "revision", 0, "release_id", "", "status", "initializing", "last_refresh_at", null,
          "last_failure_at", null, "last_error_type", null, "current_components", null, "history_count", null,
          "completeness", "incomplete", "reasons", java.util.Collections.emptyList(), "dropped_observations", 0);
      defaults.forEach(event::putIfAbsent);
    }
    return event;
  }
}
