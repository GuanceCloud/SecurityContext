package io.securitycontext.exporter;

import static io.securitycontext.core.Values.map;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.securitycontext.core.Identity;
import io.securitycontext.core.Events;
import io.securitycontext.core.SecurityState;
import io.securitycontext.core.Settings;
import io.securitycontext.core.Values;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Bounded process-local state. Snapshots are an inspection contract, not a durable backend acknowledgement. */
public final class RuntimeLedger {
  private final ObjectMapper json = new ObjectMapper();
  private final Path output = Paths.get(Settings.text("security.output", "./security-output/" + Identity.INSTANCE)).toAbsolutePath();
  private final Path control = Paths.get(Settings.text("security.control.file", output.resolve("control.json").toString()));
  private final Map<String, Map<String, Object>> findings = new LinkedHashMap<>();
  private final Map<String, Map<String, Object>> runs = new LinkedHashMap<>();
  private final Map<String, Long> counts = new LinkedHashMap<>();
  private final int maxFindings = Settings.limit("security.findings.max", 4096);
  private final int maxRuns = Settings.limit("security.runs.max", 256);
  private final long maxRunCounterBytes = Settings.limit("security.runs.max.bytes", 8 * 1024 * 1024);
  private long runCounterBytes;
  private final Set<Map<?, ?>> sharedRunCounters = Collections.newSetFromMap(new IdentityHashMap<Map<?, ?>, Boolean>());
  private final Object snapshotLock = new Object();
  private final AtomicBoolean shutdownUncertainty = new AtomicBoolean();
  private final long sampleMillis = Settings.limit("security.findings.sample.seconds", 300) * 1000L;
  private final long maxFindingBytes = Settings.limit("security.findings.max.bytes", 32 * 1024 * 1024);
  private long findingBytes;
  private final AtomicLong snapshotFailures = new AtomicLong();
  private volatile Map<String, Object> policy = Collections.emptyMap();
  private volatile Map<String, Object> sbom = map("status", "initializing");
  private volatile Map<String, Object> lastDelivery = Collections.emptyMap();
  private long pauseGeneration;
  private volatile String controlError = "";
  private volatile String controlErrorRevision = "";
  private volatile String appliedRevision = "";
  private long snapshotAt;
  private long lastSnapshotFailureLog;
  private long summaryAt;
  private final long started = System.currentTimeMillis();
  private long active;
  private long completed;
  private long requestSecond;
  private int requestsThisSecond;

  public RuntimeLedger() {
    json.getFactory().setStreamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(4096).build());
  }

  public Path output() { return output; }
  public void shutdownIncomplete() { shutdownUncertainty.set(true); }
  public boolean enabled() { return Settings.enabled("security.enabled", true) && !paused(); }
  public boolean paused() { return Boolean.TRUE.equals(policy.get("paused")); }
  public synchronized void count(String name) { counts.put(name, counts.getOrDefault(name, 0L) + 1); }
  public synchronized void count(String name, long amount) { counts.put(name, counts.getOrDefault(name, 0L) + amount); }
  public void sbom(Map<String, Object> value) {
    Map<String, Object> next = new LinkedHashMap<>(sbom);
    value.forEach((key, item) -> {
      if (!key.equals("dependencies") && !key.equals("part_index") && !key.equals("part_count")) next.put(key, item);
    });
    if ("security.sbom.update_failed".equals(value.get("event_name"))) next.put("status", "degraded");
    sbom = next;
  }

  public synchronized void begin(SecurityState state) {
    active++;
    count("requests_started");
    state.collectionGeneration = pauseGeneration;
    long second = System.nanoTime() / 1000000000L;
    if (second != requestSecond) { requestSecond = second; requestsThisSecond = 0; }
    boolean requestBudget = active <= Settings.limit("security.max.active.requests", 256) && ++requestsThisSecond <= Settings.limit("security.requests-per-second", 1000);
    state.collectionEnabled = enabled() && requestBudget;
    state.collectionStatus = !Settings.enabled("security.enabled", true) ? "disabled" : paused() ? "paused" : !requestBudget ? "budget_skipped" : "enabled";
    Object run = policy.get("run");
    if (run instanceof Map && validUntil(((Map<?, ?>) run).get("expires_at"))) {
      state.run = new LinkedHashMap<>((Map<String, Object>) run);
      String id = String.valueOf(state.run.get("run_id"));
      Map<String, Object> record = runs.get(id);
      if (record != null) increment(record, "active_requests", 1);
    }
  }

  public synchronized List<Map<String, Object>> end(SecurityState state) {
    active = Math.max(0, active - 1);
    completed++;
    count("requests_completed");
    count("sources", state.sourceCount());
    if (state.sourceCount() > 0) count("requests_with_sources");
    if (!state.sinkCounts().isEmpty()) count("requests_with_sinks");
    for (Map.Entry<String, Integer> sink : state.sinkCounts().entrySet()) count("sink." + sink.getKey(), sink.getValue());
    if (!state.collectionEnabled) count("requests_" + state.collectionStatus);
    boolean incomplete = state.truncated() || !state.gaps().isEmpty() || state.collectionEnabled && (!enabled() || state.collectionGeneration != pauseGeneration);
    if (state.collectionEnabled && state.collectionGeneration != pauseGeneration) state.gap("collection_paused_during_request");
    if (incomplete) count("requests_incomplete");
    Map<String, Object> request = Events.request(state.request);
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map<String, Object> original : state.pending()) {
      Map<String, Object> event = Events.record(original);
      event.put("request", new LinkedHashMap<>(request));
      event.put("run", new LinkedHashMap<>(state.run));
      event.put("trace_availability", "not_guaranteed_by_trace_id");
      event.put("occurrence_id", event.get("evidence_id"));
      if (incomplete) { event.put("truncated", true); event.put("coverage_gaps", state.gaps()); }
      String id = String.valueOf(event.get("finding_id"));
      Map<String, Object> finding = findings.get(id);
      if (finding == null) {
        if (findings.size() >= maxFindings) { count("finding_capacity_dropped"); continue; }
        finding = map("finding_id", id, "rule", event.get("rule"), "assessment", event.get("assessment"),
            "validation", "unvalidated", "sink", event.get("sink"), "first_seen", event.get("observed_at"),
            "occurrences", 0L, "last_sample_millis", 0L);
        findings.put(id, finding);
      }
      increment(finding, "occurrences", 1);
      finding.put("last_seen", event.get("observed_at"));
      finding.put("last_trace_id", event.get("trace_id"));
      finding.put("last_evidence_id", event.get("evidence_id"));
      finding.put("last_run", new LinkedHashMap<>(state.run));
      finding.put("code", event.get("code"));
      finding.put("request", event.get("request"));
      finding.put("component", event.get("component"));
      finding.put("triage", triage(id));
      event.put("triage", finding.get("triage"));
      long lastSample = ((Number) finding.get("last_sample_millis")).longValue();
      String runId = String.valueOf(state.run.getOrDefault("run_id", ""));
      if (System.currentTimeMillis() - lastSample >= sampleMillis || !runId.equals(finding.get("sample_run_id"))) {
        finding.put("last_sample_millis", System.currentTimeMillis());
        finding.put("sample_run_id", runId);
        Map<String, Object> representative = new LinkedHashMap<>(event);
        long estimate = estimate(representative, 0);
        long previous = ((Number) finding.getOrDefault("representative_bytes", 0L)).longValue();
        if (estimate > Settings.limit("security.evidence.max.bytes", 65536) || findingBytes - previous + estimate > maxFindingBytes) {
          representative.remove("propagation"); representative.remove("ranges"); representative.remove("sources");
          representative.remove("stack"); representative.put("truncated", true); representative.put("truncation_reason", "finding_snapshot_byte_budget");
          estimate = estimate(representative, 0);
          count("finding_sample_truncated");
        }
        if (findingBytes - previous + estimate <= maxFindingBytes) {
          findingBytes += estimate - previous;
          finding.put("representative_bytes", estimate);
          finding.put("representative", representative);
        } else { count("finding_sample_dropped"); finding.remove("representative"); findingBytes -= previous; finding.put("representative_bytes", 0L); }
        event.put("occurrences_total", finding.get("occurrences"));
        result.add(event);
      } else count("representative_samples_suppressed");
      finding.put("dirty", true);
    }
    Map<String, Object> diagnostic = state.diagnostics();
    if (diagnostic != null) {
      diagnostic.put("request", new LinkedHashMap<>(request));
      diagnostic.put("run", new LinkedHashMap<>(state.run));
      result.add(Events.record(diagnostic));
    }
    Object runId = state.run.get("run_id");
    Map<String, Object> run = runId == null ? null : runs.get(String.valueOf(runId));
    if (run != null) {
      increment(run, "active_requests", -1);
      increment(run, "requests", 1);
      if (state.sourceCount() > 0) increment(run, "source_requests", 1);
      for (String signature : state.sourceSignatures()) boundedIncrement(run, "source_signatures", signature);
      String rule = String.valueOf(run.get("rule"));
      if (state.sinkCounts().getOrDefault(rule, 0) > 0) increment(run, "sink_requests", 1);
      if (incomplete || !state.collectionEnabled) increment(run, "incomplete_requests", 1);
      Object status = state.request.get("status_code");
      if (status instanceof Number && ((Number) status).intValue() >= 500) increment(run, "error_requests", 1);
      for (Map<String, Object> event : state.pending()) if (rule.equals(event.get("rule"))) {
        increment(run, "observations", 1);
        for (Object item : (List<?>) event.get("sources")) {
          Map<?, ?> source = (Map<?, ?>) item;
          boundedIncrement(run, "risk_source_signatures", source.get("type") + "|" + source.get("name"));
        }
        boundedIncrement(run, "finding_counts", String.valueOf(event.get("finding_id")));
      }
      if (!profile().equals(run.get("instrumentation_profile"))) increment(run, "incomplete_requests", 1);
      run.put("last_request", new LinkedHashMap<>(request));
      finishIfIdle(run);
    }
    return result;
  }

  private static long deliveryLoss(Map<String, Object> delivery) {
    long total = ((Number) delivery.getOrDefault("security_dropped", delivery.getOrDefault("dropped", 0L))).longValue();
    Object counts = delivery.get("counters");
    if (counts instanceof Map) for (Object item : ((Map<?, ?>) counts).entrySet()) {
      Map.Entry<?, ?> entry = (Map.Entry<?, ?>) item;
      String key = String.valueOf(entry.getKey());
      if (key.startsWith("security.") && (key.endsWith("failed") || key.endsWith("record_truncated"))) total += ((Number) entry.getValue()).longValue();
    }
    return total;
  }

  public synchronized Map<String, Object> health(Map<String, Object> delivery) {
    String status = !Settings.enabled("security.enabled", true) ? "disabled" : paused() ? "paused" : completed == 0 ? active > 0 ? "in_flight" : "no_traffic" :
        counts.getOrDefault("requests_incomplete", 0L) > 0 || counts.getOrDefault("requests_budget_skipped", 0L) > 0 || counts.getOrDefault("finding_capacity_dropped", 0L) > 0 || counts.getOrDefault("run_counter_capacity_dropped", 0L) > 0 || deliveryLoss(delivery) > 0 ? "incomplete" :
        counts.getOrDefault("requests_with_sources", 0L) == 0 ? "no_source_observed" :
        counts.getOrDefault("requests_with_sinks", 0L) == 0 ? "no_sink_observed" : "observed";
    return map("schema_version", 2, "source", "security_context", "event_name", "security.health", "updated_at", io.securitycontext.core.Events.now(),
        "started_at", io.securitycontext.core.Events.timestamp(started), "identity", Identity.context(), "version", Identity.VERSION, "instrumentation_profile", profile(),
        "collection_status", !Settings.enabled("security.enabled", true) ? "disabled" : paused() ? "paused" : "enabled",
        "delivery_loss", deliveryLoss(delivery),
        "status", status, "configured", Settings.enabled("security.enabled", true), "effective", enabled(),
        "active_requests", active, "counts", new LinkedHashMap<>(counts), "rule_status", rules(),
        "capabilities", java.util.Arrays.asList("http_server", "sql", "command", "http_client", "file", "modeled_string_propagation"),
        "coverage_semantics", "observed_counters_not_vulnerability_recall", "coverage_scope", "modeled_calls_only",
        "sbom", sbom, "delivery", delivery, "control_revision", appliedRevision, "control_error", controlError, "control_error_revision", controlErrorRevision,
        "snapshot_failures", snapshotFailures.get(), "retention", map("findings_max", maxFindings, "runs_max", maxRuns,
            "run_counter_bytes_upper_bound", runCounterBytes, "run_counter_bytes_max", maxRunCounterBytes,
            "representative_bytes_upper_bound", findingBytes, "representative_bytes_max", maxFindingBytes),
        "pause_semantics", "collection_paused_existing_instrumentation_remains_loaded_restart_without_extension_to_unload");
  }

  public void tick(Map<String, Object> delivery, java.util.function.Consumer<Map<String, Object>> emit, boolean force) {
    // Serialize the entire snapshot transaction without holding the monitor
    // used by request begin/end during serialization, callbacks or file I/O.
    synchronized (snapshotLock) { snapshot(delivery, emit, force); }
  }

  private void snapshot(Map<String, Object> delivery, java.util.function.Consumer<Map<String, Object>> emit, boolean force) {
    long now = System.currentTimeMillis();
    if (!force && now - snapshotAt < 1000) return;
    snapshotAt = now;
    lastDelivery = new LinkedHashMap<>(delivery);
    readControl();
    List<Map<String, Object>> findingCopy = new ArrayList<>();
    List<Map<String, Object>> runCopy = new ArrayList<>();
    List<Map<String, Object>> summaries = new ArrayList<>();
    synchronized (this) {
      if (shutdownUncertainty.getAndSet(false)) {
        for (Map<String, Object> run : runs.values()) if (((Number) run.getOrDefault("requests", 0L)).longValue() > 0) {
          increment(run, "delivery_loss", 1);
          increment(run, "incomplete_requests", 1);
        }
      }
      for (Map<String, Object> run : runs.values()) {
        if (!validUntil(run.get("expires_at")) && "active".equals(run.get("status"))) { run.put("status", "draining"); run.put("expired", true); }
        finishIfIdle(run);
      }
      for (Map<String, Object> finding : findings.values()) {
        finding.put("triage", triage(String.valueOf(finding.get("finding_id"))));
        if ((force || now - summaryAt >= Settings.limit("security.findings.flush.seconds", 30) * 1000L) && Boolean.TRUE.equals(finding.remove("dirty")))
          summaries.add(map("event_name", "security.finding.summary", "observed_at", io.securitycontext.core.Events.now(),
              "identity", Identity.context(), "finding_id", finding.get("finding_id"), "occurrences_total", finding.get("occurrences"),
              "first_seen", finding.get("first_seen"), "last_seen", finding.get("last_seen"), "triage", finding.get("triage")));
      }
      if (!summaries.isEmpty()) summaryAt = now;
      for (Map<String, Object> finding : findings.values()) {
        Map<String, Object> copy = new LinkedHashMap<>(finding);
        for (String key : new String[] {"dirty", "last_sample_millis", "sample_run_id", "representative_bytes"}) copy.remove(key);
        findingCopy.add(copy);
      }
      for (Map<String, Object> run : runs.values()) {
        Map<String, Object> copy = new LinkedHashMap<>(run);
        for (String key : new String[] {"finding_counts", "source_signatures", "risk_source_signatures"})
          sharedRunCounters.add((Map<?, ?>) run.get(key));
        copy.remove("loss_start"); copy.remove("snapshot_failures_start");
        runCopy.add(copy);
      }
    }
    for (Map<String, Object> summary : summaries) emit.accept(Events.record(summary));
    try {
      write(output.resolve("findings.json"), json.writeValueAsBytes(envelope("findings", findingCopy)));
      write(output.resolve("runs.json"), json.writeValueAsBytes(envelope("runs", runCopy)));
      write(output.resolve("health.json"), json.writeValueAsBytes(health(delivery)));
    } catch (IOException error) {
      snapshotFailures.incrementAndGet();
      if (now - lastSnapshotFailureLog >= 30000) {
        lastSnapshotFailureLog = now;
        System.err.println("[SecurityContext] local snapshot write failed: " + error.getClass().getSimpleName());
        emit.accept(map("event_name", "security.snapshot.failed", "error_type", error.getClass().getSimpleName(), "count", snapshotFailures.get()));
      }
    }
  }

  private Map<String, Object> envelope(String key, java.util.Collection<?> values) {
    return map("schema_version", 2, "source", "security_context", "updated_at", io.securitycontext.core.Events.now(), "identity", Identity.context(), key, new ArrayList<>(values));
  }

  private void readControl() {
    if (!Files.exists(control)) return;
    String attemptedRevision = "unparsed";
    try {
      if (!Files.isRegularFile(control)) throw new IOException("control_regular_file_required");
      if (Files.size(control) > 256 * 1024) throw new IOException("control_byte_limit");
      Map<String, Object> next = json.readValue(control.toFile(), Map.class);
      String revision = String.valueOf(next.getOrDefault("revision", ""));
      attemptedRevision = revision;
      if (revision.isEmpty()) throw new IOException("control_revision_required");
      if (revision.equals(appliedRevision)) return;
      if (next.containsKey("paused") && !(next.get("paused") instanceof Boolean)) throw new IOException("invalid_pause");
      validateExceptions(next.get("exceptions"));
      Object value = next.get("run");
      if (value != null) {
        if (!(value instanceof Map)) throw new IOException("invalid_run");
        Map<?, ?> run = (Map<?, ?>) value;
        for (String field : new String[] {"run_id", "case_id", "rule", "expires_at"})
          if (!(run.get(field) instanceof String) || ((String) run.get(field)).isEmpty()) throw new IOException("missing_run_" + field);
        if (!validUntil(run.get("expires_at")) || !rules().containsKey(run.get("rule"))) throw new IOException("invalid_run_expiry_or_rule");
        if (!(run.get("conditions") instanceof Map)) throw new IOException("missing_run_conditions");
        Map<?, ?> conditions = (Map<?, ?>) run.get("conditions");
        for (String field : new String[] {"suite", "fixture"}) if (!(conditions.get(field) instanceof String) || ((String) conditions.get(field)).trim().isEmpty()) throw new IOException("missing_condition_" + field);
        if (!(conditions.get("expected_requests") instanceof Number) || ((Number) conditions.get("expected_requests")).longValue() <= 0) throw new IOException("expected_requests_required");
      }
      synchronized (this) {
        Map<String, Object> newRun = (Map<String, Object>) value;
        String nextId = newRun == null ? "" : String.valueOf(newRun.get("run_id"));
        if (newRun != null && runs.containsKey(nextId) && !"active".equals(runs.get(nextId).get("status"))) throw new IOException("run_id_already_closed");
        if (newRun != null && !runs.containsKey(nextId) && runs.size() >= maxRuns) throw new IOException("run_capacity_restart_or_archive");
        for (Map<String, Object> old : runs.values()) if ("active".equals(old.get("status")) && !nextId.equals(old.get("run_id"))) { old.put("status", "draining"); finishIfIdle(old); }
        if (newRun != null && !runs.containsKey(nextId)) {
          Map<String, Object> run = new LinkedHashMap<>(newRun);
          run.put("status", "active"); run.put("started_at", io.securitycontext.core.Events.now()); run.put("identity", Identity.context());
          run.put("rule_enabled", rules().get(run.get("rule"))); run.put("collection_enabled", Settings.enabled("security.enabled", true) && !Boolean.TRUE.equals(next.get("paused")));
          run.put("loss_start", lossTotal()); run.put("snapshot_failures_start", snapshotFailures.get());
          run.put("instrumentation_profile", profile()); run.put("finding_counts", new LinkedHashMap<String, Long>());
          run.put("source_signatures", new LinkedHashMap<String, Long>()); run.put("risk_source_signatures", new LinkedHashMap<String, Long>());
          for (String key : new String[] {"requests", "source_requests", "sink_requests", "observations", "incomplete_requests", "error_requests", "active_requests"}) run.put(key, 0L);
          runs.put(nextId, run);
        }
        if (Boolean.TRUE.equals(policy.get("paused")) != Boolean.TRUE.equals(next.get("paused"))) pauseGeneration++;
        policy = next;
        appliedRevision = revision;
      }
      controlError = ""; controlErrorRevision = "";
    } catch (Exception error) { controlErrorRevision = attemptedRevision; controlError = Values.bounded(error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage(), 256); }
  }

  private static long estimate(Object value, int depth) {
    if (value == null) return 4;
    if (depth > 16) return 65536;
    if (value instanceof String) return ((String) value).length() * 6L + 2;
    if (value instanceof Number || value instanceof Boolean) return 32;
    long bytes = 2;
    if (value instanceof Map) for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) bytes += estimate(entry.getKey(), depth + 1) + estimate(entry.getValue(), depth + 1) + 2;
    else if (value instanceof Iterable) for (Object entry : (Iterable<?>) value) bytes += estimate(entry, depth + 1) + 1;
    return bytes;
  }

  private String profile() { return Identity.digest(Identity.VERSION + "|" + rules() + "|" + Settings.text("security.instrumentation.exclude", "") + "|" +
      Settings.limit("security.max.objects", 4096) + "|" + Settings.limit("security.max.nodes", 8192) + "|" +
      Settings.limit("security.max.tracked.bytes", 1024 * 1024) + "|" + Settings.limit("security.max.process.tracked.bytes", 64 * 1024 * 1024)); }

  private static Map<String, Object> rules() {
    Map<String, Object> result = new LinkedHashMap<>();
    for (String rule : new String[] {"sql_injection", "command_execution", "command_injection", "ssrf", "http_request_input", "path_traversal"})
      result.put(rule, Settings.enabled("security.rules." + rule + ".enabled", true));
    return result;
  }

  private void finishIfIdle(Map<String, Object> run) {
    if ("draining".equals(run.get("status")) && ((Number) run.get("active_requests")).longValue() == 0) {
      run.put("delivery_loss", Math.max(0, lossTotal() - ((Number) run.getOrDefault("loss_start", 0L)).longValue()));
      run.put("snapshot_failures", Math.max(0, snapshotFailures.get() - ((Number) run.getOrDefault("snapshot_failures_start", 0L)).longValue()));
      run.put("status", "closed"); run.put("ended_at", io.securitycontext.core.Events.now());
    }
  }

  private long lossTotal() {
    return deliveryLoss(lastDelivery) + counts.getOrDefault("finding_capacity_dropped", 0L) + counts.getOrDefault("run_counter_capacity_dropped", 0L) + counts.getOrDefault("request_completion_errors", 0L);
  }

  private void validateExceptions(Object value) throws IOException {
    if (value == null) return;
    if (!(value instanceof List) || ((List<?>) value).size() > 128) throw new IOException("invalid_exceptions");
    for (Object entry : (List<?>) value) {
      if (!(entry instanceof Map)) throw new IOException("invalid_exception");
      Map<?, ?> exception = (Map<?, ?>) entry;
      if (!(exception.get("scope") instanceof Map)) throw new IOException("exception_scope_required");
      Map<?, ?> scope = (Map<?, ?>) exception.get("scope");
      for (String field : new String[] {"application_id", "finding_id"})
        if (!(scope.get(field) instanceof String) || ((String) scope.get(field)).isEmpty()) throw new IOException("exception_scope_required");
      if (!(exception.get("reason") instanceof String) || ((String) exception.get("reason")).trim().isEmpty()) throw new IOException("exception_reason_required");
      if (!java.util.Arrays.asList("accepted_risk", "false_positive").contains(exception.get("decision"))) throw new IOException("invalid_exception_decision");
      try { Instant.parse(String.valueOf(exception.get("expires_at"))); } catch (Exception error) { throw new IOException("exception_expiry_required"); }
    }
  }

  private Map<String, Object> triage(String findingId) {
    Object value = policy.get("exceptions");
    if (value instanceof List) for (Object item : (List<?>) value) {
      Map<String, Object> entry = (Map<String, Object>) item;
      Map<?, ?> scope = (Map<?, ?>) entry.get("scope");
      if (Identity.applicationId().equals(scope.get("application_id")) && findingId.equals(scope.get("finding_id")) && validUntil(entry.get("expires_at")))
        return new LinkedHashMap<>(entry);
    }
    return map("decision", "unreviewed");
  }

  private static boolean validUntil(Object expiry) {
    try { return Instant.parse(String.valueOf(expiry)).isAfter(Instant.now()); } catch (Exception error) { return false; }
  }

  private void boundedIncrement(Map<String, Object> run, String field, String key) {
    Map<String, Long> values = (Map<String, Long>) run.get(field);
    if (!values.containsKey(key)) {
      long bytes = 64L + key.length() * 2L;
      if (values.size() >= maxFindings || runCounterBytes + bytes > maxRunCounterBytes) {
        increment(run, "incomplete_requests", 1);
        count("run_counter_capacity_dropped");
        return;
      }
      runCounterBytes += bytes;
    }
    // Snapshots share immutable counter maps. Only the first update after a
    // snapshot copies one bounded table; unchanged historical runs never copy.
    if (sharedRunCounters.remove(values)) {
      values = new LinkedHashMap<>(values);
      run.put(field, values);
    }
    values.put(key, values.getOrDefault(key, 0L) + 1);
  }

  private static void increment(Map<String, Object> record, String key, long amount) {
    record.put(key, ((Number) record.getOrDefault(key, 0L)).longValue() + amount);
  }

  static void write(Path path, byte[] bytes) throws IOException {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Path temporary = Files.createTempFile(path.toAbsolutePath().getParent(), ".security-", ".json");
    try {
      Files.write(temporary, bytes);
      Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally { Files.deleteIfExists(temporary); }
  }
}
