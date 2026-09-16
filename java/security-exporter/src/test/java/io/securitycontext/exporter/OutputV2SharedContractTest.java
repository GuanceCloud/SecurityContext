package io.securitycontext.exporter;

import static io.securitycontext.core.Values.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.securitycontext.core.Events;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Locks the Java v2 body contract to the shared cross-language fixture. */
class OutputV2SharedContractTest {
  private static final String FIXTURE = "../tests/fixtures/output-v2-cross-language.json";
  private final ObjectMapper json = new ObjectMapper();

  @Test
  void sharedFixtureFingerprintsAndSinkAliasesStayCanonical() throws Exception {
    Map<?, ?> fixture = readFixture();
    for (Map<?, ?> item : maps(fixture.get("fingerprints"))) {
      Map<String, Object> sink = stringObjectMap(item.get("sink"));
      String actual = Events.fingerprint(string(item.get("application_id")), string(item.get("language")),
          string(item.get("rule")), sink, strings(item.get("signatures")));
      assertEquals(string(item.get("expected")), actual, string(item.get("name")));
    }

    for (Map<?, ?> item : maps(fixture.get("sink_aliases"))) {
      Map<?, ?> expected = (Map<?, ?>) item.get("expected");
      Map<String, Object> actual = Events.sink(string(item.get("rule")), string(item.get("role")),
          string(item.get("function")), string(item.get("location")));
      Map<String, Object> canonical = new java.util.LinkedHashMap<>();
      canonical.put("function", item.get("function"));
      canonical.put("role", expected.get("role"));
      canonical.put("location", item.get("location"));
      canonical.put("operation", expected.get("operation"));
      canonical.put("path_role", expected.get("path_role"));
      canonical.put("input_part", expected.get("input_part"));
      assertEquals(canonical, actual, string(item.get("rule")) + ":" + string(item.get("role")));
    }
  }

  @Test
  void sharedFixtureEventsHaveCompleteIdentityAndDiagnosticDefaults() throws Exception {
    Map<?, ?> fixture = readFixture();
    Map<?, ?> identity = (Map<?, ?>) fixture.get("identity");
    for (Object value : ((Map<?, ?>) fixture.get("event_templates")).values()) {
      Map<?, ?> template = (Map<?, ?>) value;
      Map<String, Object> input = new java.util.LinkedHashMap<>(stringObjectMap(template));
      input.put("source", "caller-override");
      Map<String, Object> event = Events.record(input);
      assertTrue(event.keySet().containsAll(java.util.Arrays.asList(
          "schema_version", "source", "event_name", "observed_at", "application_id", "instance_id",
          "service", "code", "runtime", "identity_status")));
      assertEquals(2, event.get("schema_version"));
      assertEquals(template.get("source"), event.get("source"));
      assertFalse(event.containsKey("identity"));
      assertEquals(identity.get("application_id"), event.get("application_id"));
      assertEquals(identity.get("instance_id"), event.get("instance_id"));
      assertEquals(identity.get("service"), event.get("service"));
      assertEquals(identity.get("code"), event.get("code"));
      assertEquals(identity.get("runtime"), event.get("runtime"));
      assertEquals("configured", event.get("identity_status"));
      assertTrue(string(event.get("observed_at")).matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
    }

    Map<String, Object> dataflow = Events.record(stringObjectMap(
        ((Map<?, ?>) fixture.get("event_templates")).get("dataflow")));
    assertEquals(2, dataflow.get("fingerprint_version"));
    assertEquals("bbbbbbbbbbbbbbbb", dataflow.get("server_span_id"));
    assertEquals("cccccccccccccccc", dataflow.get("current_span_id"));
    assertEquals(1, dataflow.get("trace_flags"));
    assertTrue(dataflow.get("sources") instanceof List);
    assertTrue(dataflow.get("ranges") instanceof List);
    assertTrue(dataflow.get("stack") instanceof List);

    Map<String, Object> incomplete = Events.record(stringObjectMap(
        ((Map<?, ?>) fixture.get("event_templates")).get("incomplete")));
    assertEquals(map("objects", null, "nodes", null, "sources", null, "findings", null, "retained_bytes", null),
        incomplete.get("counts"));
    assertEquals("unknown", incomplete.get("collection_status"));
    assertEquals(Boolean.TRUE, incomplete.get("truncated"));

    Map<String, Object> snapshot = Events.record(stringObjectMap(
        ((Map<?, ?>) fixture.get("event_templates")).get("sbom_snapshot")));
    assertEquals(0, snapshot.get("dropped_observations"));
    Map<String, Object> health = Events.record(stringObjectMap(
        ((Map<?, ?>) fixture.get("event_templates")).get("sbom_health")));
    assertEquals("fixture_error", health.get("last_error_type"));
    assertTrue(health.get("reasons") instanceof List);
    assertEquals(0, health.get("dropped_observations"));
  }

  private Map<?, ?> readFixture() throws IOException {
    Path current = Paths.get("").toAbsolutePath().normalize();
    while (current != null) {
      Path candidate = current.resolve(FIXTURE);
      if (Files.isRegularFile(candidate)) return json.readValue(candidate.toFile(), Map.class);
      current = current.getParent();
    }
    throw new IOException("shared fixture not found: " + FIXTURE);
  }

  private static List<Map<?, ?>> maps(Object value) {
    return (List<Map<?, ?>>) value;
  }

  private static List<String> strings(Object value) {
    return (List<String>) value;
  }

  private static Map<String, Object> stringObjectMap(Object value) {
    return (Map<String, Object>) value;
  }

  private static String string(Object value) { return value == null ? "" : String.valueOf(value); }
}
