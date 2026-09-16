package io.securitycontext.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class Identity {
  public static final String VERSION = "0.3.4";
  public static final String INSTANCE = UUID.randomUUID().toString();
  private static volatile Map<String, String> resource = Collections.emptyMap();
  private Identity() {}

  public static void configure(Map<String, String> values) {
    resource = Collections.unmodifiableMap(new LinkedHashMap<>(values));
  }

  public static String applicationId() {
    return Settings.text("security.application.id", "app-" + digest(resource.getOrDefault("service.namespace", "") + "|" +
        resource.getOrDefault("service.name", Settings.text("otel.service.name", "unknown-java-application"))));
  }

  public static Map<String, Object> context() {
    return Values.map("application_id", applicationId(), "instance_id", INSTANCE, "service", new LinkedHashMap<>(resource),
        "code", Values.map("repository", bounded("security.code.repository"), "commit", bounded("security.code.commit"),
            "build_id", bounded("security.code.build-id"), "service_version", resource.getOrDefault("service.version", "")),
        "runtime", runtime(), "identity_status", resource.containsKey("service.name") || !Settings.text("security.application.id", "").isEmpty() ? "configured" : "fallback");
  }

  public static Map<String, Object> runtime() {
    String os = System.getProperty("os.name", "unknown").toLowerCase(java.util.Locale.ROOT);
    if (os.startsWith("windows")) os = "win32";
    else if (os.startsWith("mac")) os = "darwin";
    String arch = System.getProperty("os.arch", "unknown").toLowerCase(java.util.Locale.ROOT);
    if (arch.equals("aarch64")) arch = "arm64";
    else if (arch.equals("amd64") || arch.equals("x86_64")) arch = "x64";
    else if (arch.equals("x86") || arch.matches("i[3-6]86")) arch = "ia32";
    return Values.map("language", "java", "implementation", "jvm", "version", System.getProperty("java.version", ""),
        "os", os, "architecture", arch, "details", Values.map("vendor", System.getProperty("java.vendor", ""),
            "vm_name", System.getProperty("java.vm.name", "")));
  }

  private static String bounded(String key) { return Values.bounded(Settings.text(key, ""), 1024); }

  public static String digest(String value) {
    try {
      byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder result = new StringBuilder(64);
      for (byte b : bytes) { result.append(Character.forDigit((b >>> 4) & 15, 16)); result.append(Character.forDigit(b & 15, 16)); }
      return result.toString();
    } catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
  }
}
