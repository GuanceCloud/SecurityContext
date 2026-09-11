package io.securitycontext.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Behavioural acceptance tests for archive discovery and CycloneDX publication. */
class SbomInventoryBehaviorTest {
  private static final String[] SETTINGS = {
      "security.sbom.output",
      "security.sbom.max.archive.bytes",
      "security.sbom.max.scan.bytes",
      "security.sbom.max.entries",
      "security.sbom.max.components",
      "security.sbom.cache.seconds",
      "security.sbom.build.file",
      "security.sbom.build.artifact",
      "security.evidence.max.bytes",
      "security.application.id",
      "java.class.path"
  };

  private final Map<String, String> previousSettings = new HashMap<>();
  private final ObjectMapper json = new ObjectMapper();

  @BeforeEach
  void captureSettings() {
    for (String key : SETTINGS) previousSettings.put(key, System.getProperty(key));
  }

  @AfterEach
  void restoreSettings() {
    for (String key : SETTINGS) {
      String value = previousSettings.get(key);
      if (value == null) System.clearProperty(key);
      else System.setProperty(key, value);
    }
  }

  @Test
  void scansOrdinaryJarCoordinatesHashAndLicense(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "ordinary.jar", "org.example", "ordinary", "1.2.3", "ordinary-payload");
    RecordingReceiver receiver = scan(artifact);

    assertEquals(1, receiver.components.size());
    Component component = receiver.components.get(0).component;
    assertEquals("ordinary", component.name);
    assertEquals("org.example", component.group);
    assertEquals("1.2.3", component.version);
    assertEquals(Component.digest(Files.readAllBytes(artifact)), component.hash);
    assertEquals("maven-metadata", component.source);
    assertTrue(component.licenses.contains("Apache-2.0"));
    assertEquals(artifact.toString(), receiver.components.get(0).location);
    assertTrue(receiver.components.get(0).primary);
    assertTrue(receiver.incomplete.isEmpty());
  }

  @Test
  void scansBootAndWarNestedLibrariesWithContentHashes(@TempDir Path temp) throws Exception {
    byte[] bootDependency = mavenJarBytes("org.boot", "boot-dependency", "2.0.0", "boot");
    Path boot = archive(temp, "application.jar", mapOf(
        "BOOT-INF/classes/example.class", bytes("class"),
        "BOOT-INF/lib/boot-dependency.jar", bootDependency));
    RecordingReceiver bootReceiver = scan(boot);

    Record bootRecord = find(bootReceiver.components, "boot-dependency");
    assertNotNull(bootRecord);
    assertEquals(boot + "!/BOOT-INF/lib/boot-dependency.jar", bootRecord.location);
    assertEquals(Component.digest(bootDependency), bootRecord.component.hash);
    assertTrue(bootRecord.primary);

    byte[] warDependency = mavenJarBytes("org.war", "war-dependency", "3.0.0", "war");
    Path war = archive(temp, "application.war", mapOf(
        "WEB-INF/classes/example.class", bytes("class"),
        "WEB-INF/lib/war-dependency.jar", warDependency));
    RecordingReceiver warReceiver = scan(war);

    Record warRecord = find(warReceiver.components, "war-dependency");
    assertNotNull(warRecord);
    assertEquals(war + "!/WEB-INF/lib/war-dependency.jar", warRecord.location);
    assertEquals(Component.digest(warDependency), warRecord.component.hash);
    assertTrue(warRecord.primary);
  }

  @Test
  void keepsSameCoordinatesWithDifferentContentAsDifferentComponents(@TempDir Path temp) throws Exception {
    Path first = mavenJar(temp, "first.jar", "org.example", "same", "1.0.0", "first");
    Path second = mavenJar(temp, "second.jar", "org.example", "same", "1.0.0", "second");

    RecordingReceiver firstReceiver = scan(first);
    RecordingReceiver secondReceiver = scan(second);
    Component firstComponent = firstReceiver.components.get(0).component;
    Component secondComponent = secondReceiver.components.get(0).component;

    assertEquals(firstComponent.purl, secondComponent.purl);
    assertNotEquals(firstComponent.hash, secondComponent.hash);
    assertNotEquals(firstComponent.ref, secondComponent.ref);
  }

  @Test
  void keepsShadedSameCoordinatesDistinctAcrossContainers(@TempDir Path temp) throws Exception {
    byte[] shared = bytes("groupId=org.example\nartifactId=shared\nversion=1.0.0\n");
    byte[] helper = bytes("groupId=org.example\nartifactId=helper\nversion=1.0.0\n");
    Path first = archive(temp, "first-container.jar", mapOf(
        "META-INF/maven/org.example/shared/pom.properties", shared,
        "META-INF/maven/org.example/helper/pom.properties", helper));
    Path second = archive(temp, "second-container.jar", mapOf(
        "META-INF/maven/org.example/shared/pom.properties", shared,
        "META-INF/maven/org.example/helper/pom.properties", helper));

    Record firstShared = find(scan(first).components, "shared");
    Record secondShared = find(scan(second).components, "shared");
    assertNotNull(firstShared);
    assertNotNull(secondShared);
    assertEquals("shaded-maven-metadata", firstShared.component.source);
    assertEquals("shaded-maven-metadata", secondShared.component.source);
    assertNull(firstShared.component.hash);
    assertNull(secondShared.component.hash);
    assertNotEquals(firstShared.component.ref, secondShared.component.ref);
  }

  @Test
  void reportsMissingMavenIdentityWithoutGuessingVersion(@TempDir Path temp) throws Exception {
    Path artifact = archive(temp, "unidentified.jar", mapOf("payload.class", bytes("class")));
    RecordingReceiver receiver = scan(artifact);

    assertEquals(1, receiver.components.size());
    Component component = receiver.components.get(0).component;
    assertEquals("artifact-file", component.source);
    assertEquals("", component.group);
    assertEquals("", component.version);
    assertEquals(Component.display(artifact.toString()), component.name);
    assertTrue(receiver.incomplete.contains("missing_maven_identity"));
  }

  @Test
  void mergesByteIdenticalUnknownArtifactsAcrossRenamedLocations(@TempDir Path temp) throws Exception {
    Path first = archive(temp, "unknown-first.jar", mapOf("payload.class", bytes("same-bytes")));
    Path renamed = archive(temp, "unknown-renamed.jar", mapOf("payload.class", bytes("same-bytes")));
    System.setProperty("java.class.path", first + java.io.File.pathSeparator + renamed);
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> components = (List<Map<String, Object>>) (List<?>) document.get("components");
      assertEquals(1, components.size());
      Map<String, Object> component = components.get(0);
      assertEquals("artifact-file", property(component, "securitycontext:sbom:identity-source"));
      assertEquals(Component.digest(Files.readAllBytes(first)),
          ((List<Map<String, Object>>) component.get("hashes")).get(0).get("content"));
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> occurrences = (List<Map<String, Object>>) (List<?>)
          ((Map<String, Object>) component.get("evidence")).get("occurrences");
      assertEquals(2, occurrences.size());
      assertTrue(occurrences.stream().anyMatch(value -> "unknown-first.jar".equals(value.get("location"))));
      assertTrue(occurrences.stream().anyMatch(value -> "unknown-renamed.jar".equals(value.get("location"))));
    } finally {
      inventory.close();
    }
  }

  @Test
  void marksOnlyObservedDynamicArtifactAsLoaded(@TempDir Path temp) throws Exception {
    Path deployed = mavenJar(temp, "deployed.jar", "org.example", "deployed", "1.0.0", "deployed");
    Path dynamic = dynamicJar(temp);
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", deployed.toString());

    List<Map<String, Object>> events = new ArrayList<>();
    try (URLClassLoader loader = new URLClassLoader(new URL[] {dynamic.toUri().toURL()}, null)) {
      Class<?> loadedType = Class.forName("sample.dynamic.DynamicFixture", false, loader);
      SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events,
          instrumentation(loadedType));
      try {
        inventory.refresh();
        Map<String, Object> document = read(inventory.output());
        assertCycloneDx1_7(document);
        Map<String, Object> deployedComponent = component(document, "deployed");
        Map<String, Object> dynamicComponent = component(document, "dynamic-loaded");
        assertNotNull(deployedComponent);
        assertNotNull(dynamicComponent);
        assertEquals("false", property(deployedComponent, "securitycontext:sbom:loaded"));
        assertEquals("true", property(dynamicComponent, "securitycontext:sbom:loaded"));
        assertEquals("true", property(dynamicComponent, "securitycontext:sbom:deployed"));
        Map<String, Object> snapshot = event(events, "app-dependencies-loaded", "revision", 1);
        assertEquals(Collections.singletonList(io.securitycontext.core.Values.map("name", "org.dynamic:dynamic-loaded", "version", "9.0.0")), snapshot.get("dependencies"));
        Map<String, Object> resolution = inventory.resolve("sample.dynamic.DynamicFixture", loader);
        assertEquals("resolved", resolution.get("status"));
        assertEquals(dynamicComponent.get("bom-ref"), resolution.get("bom-ref"));
      } finally {
        inventory.close();
      }
    }
    System.setProperty("java.class.path", originalClasspath);
  }

  @Test
  void resolveDoesNotPairDynamicRefWithAnOlderPublishedRevision(@TempDir Path temp) throws Exception {
    Path first = dynamicJar(temp, "dynamic-first.jar", "first");
    Path second = dynamicJar(temp, "dynamic-second.jar", "second");
    CoordinatedLoader firstLoader = new CoordinatedLoader(first, false);
    CoordinatedLoader secondLoader = new CoordinatedLoader(second, false);
    String originalClasspath = System.getProperty("java.class.path");
    AtomicReference<Class<?>[]> loaded = new AtomicReference<>();
    SbomInventory inventory = null;
    try {
      Class<?> firstType = Class.forName("sample.dynamic.DynamicFixture", false, firstLoader);
      loaded.set(new Class<?>[] {firstType});
      System.setProperty("java.class.path", first.toString());
      inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded));
      inventory.refresh();
      Map<String, Object> firstResolution = inventory.resolve("sample.dynamic.DynamicFixture", firstLoader);
      assertEquals(1, ((Number) firstResolution.get("revision")).intValue());
      String firstRef = String.valueOf(firstResolution.get("bom-ref"));
      String secondRef = "urn:securitycontext:component:" + Component.digest(Files.readAllBytes(second));
      assertNotEquals(firstRef, secondRef);

      System.setProperty("java.class.path", first + java.io.File.pathSeparator + second);
      secondLoader.gate = true;
      final SbomInventory activeInventory = inventory;
      AtomicReference<Map<String, Object>> inFlight = new AtomicReference<>();
      Thread resolver = new Thread(() -> inFlight.set(
          activeInventory.resolve("sample.dynamic.DynamicFixture", secondLoader)), "sbom-resolve-regression");
      resolver.start();
      assertTrue(secondLoader.entered.await(5, TimeUnit.SECONDS));

      AtomicReference<Throwable> refreshFailure = new AtomicReference<>();
      Thread publisher = new Thread(() -> {
        try { activeInventory.refresh(); }
        catch (Throwable error) { refreshFailure.set(error); }
      }, "sbom-publish-regression");
      publisher.start();
      publisher.join(10000);
      assertFalse(publisher.isAlive(), "dynamic publication did not complete");
      assertNull(refreshFailure.get());
      assertEquals(2, inventory.revision());

      secondLoader.release.countDown();
      resolver.join(10000);
      assertFalse(resolver.isAlive(), "resolve did not complete");
      Map<String, Object> inFlightResult = inFlight.get();
      assertNotNull(inFlightResult);
      assertEquals(1, ((Number) inFlightResult.get("revision")).intValue());
      assertEquals("unresolved", inFlightResult.get("status"));
      assertEquals("", inFlightResult.get("bom-ref"), "old snapshot must not resolve the newly published artifact");

      secondLoader.gate = false;
      Map<String, Object> publishedResult = inventory.resolve("sample.dynamic.DynamicFixture", secondLoader);
      assertEquals(2, ((Number) publishedResult.get("revision")).intValue());
      assertEquals(secondRef, publishedResult.get("bom-ref"));
    } finally {
      secondLoader.release.countDown();
      if (inventory != null) inventory.close();
      firstLoader.close();
      secondLoader.close();
      System.setProperty("java.class.path", originalClasspath);
    }
  }

  @Test
  void sharedOriginsPreserveAgentExclusionAndLoadedSnapshotChanges(@TempDir Path temp) throws Exception {
    Path application = dynamicJar(temp);
    Path agent = mavenJar(temp, "agent.jar", "io.opentelemetry", "javaagent", "1.0", "agent");
    System.setProperty("java.class.path", application + java.io.File.pathSeparator + agent);
    byte[] applicationBytes;
    byte[] agentBytes;
    try (InputStream input = getClass().getResourceAsStream("/sample/dynamic/DynamicFixture.class")) {
      applicationBytes = readAll(input);
    }
    try (InputStream input = getClass().getResourceAsStream("/io/opentelemetry/javaagent/OpenTelemetryAgent.class")) {
      agentBytes = readAll(input);
    }
    URL sharedOrigin = agent.toUri().toURL();
    NestedSourceLoader agentLoader = new NestedSourceLoader();
    Class<?> helper = agentLoader.define("sample.dynamic.DynamicFixture", applicationBytes, sharedOrigin);
    Class<?> entry = agentLoader.define("io.opentelemetry.javaagent.OpenTelemetryAgent", agentBytes, sharedOrigin);
    Class<?> app = new NestedSourceLoader().define("sample.dynamic.DynamicFixture", applicationBytes, application.toUri().toURL());
    AtomicReference<Class<?>[]> loaded = new AtomicReference<>(new Class<?>[] {helper, app, helper, entry});
    try (SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded))) {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertNull(component(document, "javaagent"), "agent entry may appear after another class sharing its origin");
      assertEquals("true", property(component(document, "dynamic-loaded"), "securitycontext:sbom:loaded"));
      loaded.set(new Class<?>[] {helper, entry});
      inventory.refresh();
      document = read(inventory.output());
      assertNull(component(document, "javaagent"));
      assertEquals("false", property(component(document, "dynamic-loaded"), "securitycontext:sbom:loaded"));
      loaded.set(new Class<?>[] {app, helper, entry});
      inventory.refresh();
      assertEquals("true", property(component(read(inventory.output()), "dynamic-loaded"), "securitycontext:sbom:loaded"));
    }
  }

  @Test
  void keepsBootOuterComponentsWhenApplicationLoadsNestedByteBuddy(@TempDir Path temp) throws Exception {
    byte[] byteBuddyJar = mavenJarBytes("net.bytebuddy", "byte-buddy", "1.18.12", "byte-buddy");
    Path outer = archive(temp, "boot-application.jar", mapOf(
        "META-INF/maven/example/application/pom.properties",
            bytes("groupId=example\nartifactId=application\nversion=1.0.0\n"),
        "META-INF/maven/example/application/pom.xml",
            bytes("<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"),
        "BOOT-INF/classes/app.marker", bytes("application"),
        "BOOT-INF/lib/byte-buddy.jar", byteBuddyJar));
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", outer.toString());
    AtomicReference<Class<?>[]> loaded = new AtomicReference<>();
    try {
      NestedSourceLoader loader = new NestedSourceLoader();
      byte[] applicationBytes;
      try (InputStream input = getClass().getResourceAsStream("/sample/dynamic/DynamicFixture.class")) {
        assertNotNull(input, "application fixture class must be available in test output");
        applicationBytes = readAll(input);
      }
      String outerUrl = outer.toUri().toURL().toExternalForm();
      Class<?> applicationType = loader.define("sample.dynamic.DynamicFixture", applicationBytes,
          new URL(outerUrl + "!/BOOT-INF/classes/"));
      loaded.set(new Class<?>[] {applicationType});
      SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded));
      try {
        inventory.refresh();
        Map<String, Object> initial = read(inventory.output());
        assertNotNull(component(initial, "application"));
        assertNotNull(component(initial, "byte-buddy"));
        assertEquals("resolved", inventory.resolve("sample.dynamic.DynamicFixture", loader).get("status"));

        byte[] byteBuddyBytes;
        try (InputStream input = getClass().getResourceAsStream("/net/bytebuddy/TestByteBuddy.class")) {
          assertNotNull(input, "Byte Buddy namespace fixture must be available in test output");
          byteBuddyBytes = readAll(input);
        }
        Class<?> byteBuddyType = loader.define("net.bytebuddy.TestByteBuddy", byteBuddyBytes,
            new URL(outerUrl + "!/BOOT-INF/lib/byte-buddy.jar/"));
        loaded.set(new Class<?>[] {applicationType, byteBuddyType});
        inventory.refresh();
        Map<String, Object> after = read(inventory.output());
        assertNotNull(component(after, "application"), "nested Byte Buddy must not suppress the Boot outer root");
        assertNotNull(component(after, "byte-buddy"), "business Byte Buddy dependency must remain in the inventory");
        assertEquals("resolved", inventory.resolve("sample.dynamic.DynamicFixture", loader).get("status"));
      } finally {
        inventory.close();
      }
    } finally {
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void separatesApplicationReleaseAndSnapshotInstanceIdentity(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "identity.jar", "org.example", "identity", "1.0.0", "same-release");
    String originalClasspath = System.getProperty("java.class.path");
    String originalApplication = System.getProperty("security.application.id");
    System.setProperty("java.class.path", artifact.toString());
    System.setProperty("security.application.id", "app-identity-test");
    SbomInventory first = inventory(temp.resolve("first/application.cdx.json"), new ArrayList<>(), null);
    SbomInventory second = inventory(temp.resolve("second/application.cdx.json"), new ArrayList<>(), null);
    try {
      first.refresh();
      second.refresh();
      Map<String, Object> firstDocument = read(first.output());
      Map<String, Object> secondDocument = read(second.output());

      assertEquals("app-identity-test", documentProperty(firstDocument, "securitycontext:application-id"));
      assertEquals("app-identity-test", documentProperty(secondDocument, "securitycontext:application-id"));
      assertEquals(documentProperty(firstDocument, "securitycontext:release-id"),
          documentProperty(secondDocument, "securitycontext:release-id"));
      assertEquals(documentProperty(firstDocument, "securitycontext:process-instance-id"),
          documentProperty(secondDocument, "securitycontext:process-instance-id"));
      assertNotEquals(documentProperty(firstDocument, "securitycontext:application-id"),
          documentProperty(firstDocument, "securitycontext:release-id"));
      assertNotEquals(documentProperty(firstDocument, "securitycontext:release-id"),
          documentProperty(firstDocument, "securitycontext:process-instance-id"));
      assertNotEquals(firstDocument.get("serialNumber"), secondDocument.get("serialNumber"),
          "each inventory publication has its own SBOM snapshot identity");
      assertEquals("app-identity-test", applicationComponentRef(firstDocument));
      assertEquals("app-identity-test", applicationComponentRef(secondDocument));
    } finally {
      first.close();
      second.close();
      restore("java.class.path", originalClasspath);
      restore("security.application.id", originalApplication);
    }
  }

  @Test
  void rebuildsCurrentInventoryAfterSamePathReplacement(@TempDir Path temp) throws Exception {
    Path firstArtifact = mavenJar(temp, "first.jar", "org.example", "first-release", "1.0.0", "first-content");
    Path secondArtifact = mavenJar(temp, "second.jar", "org.example", "second-release", "2.0.0", "second-content-that-is-longer");
    Path deployed = temp.resolve("application.jar");
    Files.copy(firstArtifact, deployed);
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", deployed.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      Map<String, Object> firstDocument = read(inventory.output());
      String firstRef = stringValue(component(firstDocument, "first-release").get("bom-ref"));
      String firstRelease = documentProperty(firstDocument, "securitycontext:release-id");

      Files.copy(secondArtifact, deployed, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      Files.setLastModifiedTime(deployed, FileTime.fromMillis(System.currentTimeMillis() + 2000));
      inventory.refresh();
      Map<String, Object> secondDocument = read(inventory.output());

      assertEquals(2, inventory.revision());
      assertNull(component(secondDocument, "first-release"));
      Map<String, Object> current = component(secondDocument, "second-release");
      assertNotNull(current);
      assertNotEquals(firstRef, current.get("bom-ref"));
      assertNotEquals(firstRelease, documentProperty(secondDocument, "securitycontext:release-id"));
      Map<String, Object> history = read(inventory.output().resolveSibling("sbom-history.json"));
      assertEquals("removed", historyEntry(history, firstRef).get("state"));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void retriesAnUnreadableArtifactWhenItBecomesReadable(@TempDir Path temp) throws Exception {
    Path missing = temp.resolve("appears-later.jar");
    Path artifact = mavenJar(temp, "ready.jar", "org.example", "retryable", "1.0.0", "ready");
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", missing.toString());
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> incomplete = read(inventory.output());
      assertTrue(completenessReasons(incomplete).contains("unreadable_artifact"));
      assertTrue(((List<?>) incomplete.get("components")).isEmpty());

      Files.copy(artifact, missing);
      inventory.refresh();
      Map<String, Object> recovered = read(inventory.output());
      assertEquals(2, inventory.revision());
      assertNotNull(component(recovered, "retryable"));
      assertFalse(completenessReasons(recovered).contains("unreadable_artifact"));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void keepsHistoricalRemovalDeltaAndFreshnessAfterArtifactDeletion(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "removed.jar", "org.example", "removed", "1.0.0", "to-remove");
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", artifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      Map<String, Object> initial = read(inventory.output());
      String removedRef = stringValue(component(initial, "removed").get("bom-ref"));
      assertNotNull(((Map<?, ?>) inventory.health()).get("last_refresh_at"));

      System.setProperty("java.class.path", "");
      inventory.refresh();
      Map<String, Object> current = read(inventory.output());
      assertEquals(2, inventory.revision());
      assertTrue(((List<?>) current.get("components")).isEmpty());
      Map<String, Object> snapshot = event(events, "app-dependencies-loaded", "revision", 2);
      assertNotNull(snapshot);
      assertTrue(((List<?>) snapshot.get("dependencies")).isEmpty());

      Map<String, Object> history = read(inventory.output().resolveSibling("sbom-history.json"));
      Map<?, ?> historical = historyEntry(history, removedRef);
      assertNotNull(historical);
      assertEquals("removed", historical.get("state"));
      Map<String, Object> health = inventory.health();
      assertEquals(0, health.get("current_components"));
      assertEquals(1, ((Number) health.get("history_count")).intValue());
      assertNotNull(health.get("last_refresh_at"));
      assertEquals(documentProperty(current, "securitycontext:release-id"), health.get("release_id"));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void mergesExternalBuildSbomMetadataAndReportsQuality(@TempDir Path temp) throws Exception {
    Path artifact = archive(temp, "runtime.jar", mapOf(
        "META-INF/maven/org.build/runtime/pom.properties",
        bytes("groupId=org.build\nartifactId=runtime\nversion=4.0.0\n"),
        "payload.class", bytes("class")));
    Map<String, Object> build = new LinkedHashMap<>();
    build.put("bomFormat", "CycloneDX");
    build.put("specVersion", "1.7");
    build.put("serialNumber", "urn:uuid:build-sbom");
    build.put("metadata", mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "build-app")));
    build.put("components", Collections.singletonList(mapOfObjects(
        "type", "library", "bom-ref", "runtime-ref", "group", "org.build", "name", "runtime",
        "version", "4.0.0", "purl", "pkg:maven/org.build/runtime@4.0.0",
        "licenses", Collections.singletonList(mapOfObjects("license", mapOfObjects("id", "MIT"))))));
    build.put("dependencies", Collections.singletonList(mapOfObjects(
        "ref", "build-app", "dependsOn", Collections.singletonList("runtime-ref"))));
    Path buildFile = temp.resolve("application-build.cdx.json");
    Files.write(buildFile, json.writeValueAsBytes(build));
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", artifact.toString());
    System.setProperty("security.sbom.build.file", buildFile.toString());
    System.setProperty("security.sbom.build.artifact", "build-output");
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertCycloneDx1_7(document);
      Map<String, Object> runtime = component(document, "runtime");
      assertNotNull(runtime);
      assertEquals("pkg:maven/org.build/runtime@4.0.0", runtime.get("purl"));
      assertEquals("MIT", licenseName(runtime));
      assertEquals("build-sbom-declaration", property(runtime, "securitycontext:sbom:license-source"));
      assertEquals("1", quality(document).get("with_license").toString());
      assertTrue(containsDependency((List<?>) document.get("dependencies"), applicationComponentRef(document),
          stringValue(runtime.get("bom-ref"))));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void importsEmbeddedCycloneDxComponentsAndDependencyEdges(@TempDir Path temp) throws Exception {
    Map<String, Object> declared = new LinkedHashMap<>();
    declared.put("bomFormat", "CycloneDX");
    declared.put("specVersion", "1.7");
    declared.put("serialNumber", "urn:uuid:declared");
    declared.put("metadata", mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "app")));
    declared.put("components", Collections.singletonList(mapOfObjects(
        "type", "library", "bom-ref", "dep-ref", "group", "org.build", "name", "declared-dependency",
        "version", "5.0.0", "purl", "pkg:maven/org.build/declared-dependency@5.0.0")));
    declared.put("dependencies", Collections.singletonList(mapOfObjects(
        "ref", "app", "dependsOn", Collections.singletonList("dep-ref"))));
    byte[] embedded = json.writeValueAsBytes(declared);
    Path artifact = archive(temp, "with-build-sbom.jar", mapOf("META-INF/sbom/build.cdx.json", embedded));
    List<Map<String, Object>> events = new ArrayList<>();
    System.setProperty("java.class.path", artifact.toString());
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertCycloneDx1_7(document);
      Map<String, Object> importedComponent = component(document, "declared-dependency");
      assertNotNull(importedComponent);
      assertEquals("pkg:maven/org.build/declared-dependency@5.0.0", importedComponent.get("purl"));
      Map<String, Object> outerComponent = component(document, "with-build-sbom.jar");
      assertNotNull(outerComponent);
      List<?> dependencies = (List<?>) document.get("dependencies");
      assertTrue(containsDependency(dependencies, stringValue(outerComponent.get("bom-ref")),
          stringValue(importedComponent.get("bom-ref"))));
    } finally {
      inventory.close();
    }
  }

  @Test
  void omitsUnresolvedDependencyEdgesInsteadOfPublishingEmptyLeaf(@TempDir Path temp) throws Exception {
    Map<String, Object> declared = new LinkedHashMap<>();
    declared.put("bomFormat", "CycloneDX");
    declared.put("specVersion", "1.7");
    declared.put("serialNumber", "urn:uuid:declared-unresolved");
    declared.put("metadata", mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "app")));
    declared.put("dependencies", Collections.singletonList(mapOfObjects(
        "ref", "app", "dependsOn", Collections.singletonList("missing-ref"))));
    Path artifact = archive(temp, "with-unresolved-build-sbom.jar", mapOf(
        "META-INF/sbom/build.cdx.json", json.writeValueAsBytes(declared)));
    System.setProperty("java.class.path", artifact.toString());
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      List<?> dependencies = (List<?>) document.get("dependencies");
      for (Object value : dependencies) {
        if (!(value instanceof Map)) continue;
        Map<?, ?> dependency = (Map<?, ?>) value;
        assertFalse(((List<?>) dependency.get("dependsOn")).isEmpty());
      }
      assertTrue(completenessReasons(document).contains("unresolved_declared_dependency"));
    } finally {
      inventory.close();
    }
  }

  @Test
  void doesNotPublishUnchangedSnapshot(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "stable.jar", "org.example", "stable", "1.0.0", "stable");
    System.setProperty("java.class.path", artifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      byte[] first = Files.readAllBytes(inventory.output());
      int firstRevision = inventory.revision();
      inventory.refresh();
      assertEquals(1, firstRevision);
      assertEquals(firstRevision, inventory.revision());
      assertEquals(1, countEvents(events, "app-dependencies-loaded"));
      assertTrue(Arrays.equals(first, Files.readAllBytes(inventory.output())));
    } finally {
      inventory.close();
    }
  }

  @Test
  void retainsPreviousSnapshotAndRetriesAfterEnvelopeBudgetFailure(@TempDir Path temp) throws Exception {
    Path first = mavenJar(temp, "first.jar", "org.example", "first", "1.0.0", "first");
    Path second = mavenJar(temp, "second.jar", "org.example", "second", "1.0.0", "second");
    System.setProperty("java.class.path", first.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    String previousLimit = System.getProperty("security.evidence.max.bytes");
    try {
      inventory.refresh();
      byte[] previous = Files.readAllBytes(inventory.output());
      System.setProperty("java.class.path", first + java.io.File.pathSeparator + second);
      System.setProperty("security.evidence.max.bytes", "1");
      assertThrows(IOException.class, inventory::refresh);
      assertEquals(1, inventory.revision());
      assertTrue(Arrays.equals(previous, Files.readAllBytes(inventory.output())));
      System.setProperty("security.evidence.max.bytes", "65536");
      inventory.refresh();
      assertEquals(2, inventory.revision());
      assertNotNull(component(read(inventory.output()), "second"));
      assertNotNull(event(events, "app-dependencies-loaded", "revision", 2));
    } finally {
      if (previousLimit == null) System.clearProperty("security.evidence.max.bytes");
      else System.setProperty("security.evidence.max.bytes", previousLimit);
      inventory.close();
    }
  }

  @Test
  void retainsPreviousSnapshotWhenNextAtomicWriteFails(@TempDir Path temp) throws Exception {
    Path firstArtifact = mavenJar(temp, "first.jar", "org.example", "first", "1.0.0", "first");
    Path secondArtifact = mavenJar(temp, "second.jar", "org.example", "second", "1.0.0", "second");
    Path output = temp.resolve("nested-output/application.cdx.json");
    System.setProperty("java.class.path", firstArtifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(output, events, null);
    Set<PosixFilePermission> writable = PosixFilePermissions.fromString("rwx------");
    Set<PosixFilePermission> readOnly = PosixFilePermissions.fromString("r-x------");
    try {
      inventory.refresh();
      byte[] previous = Files.readAllBytes(output);
      Path parent = output.getParent();
      try {
        Files.setPosixFilePermissions(parent, readOnly);
      } catch (UnsupportedOperationException error) {
        return;
      }
      assumeTrue(!Files.isWritable(parent), "write-failure test requires a non-root POSIX test process");
      System.setProperty("java.class.path", firstArtifact + java.io.File.pathSeparator + secondArtifact);
      assertThrows(IOException.class, inventory::refresh);
      assertEquals(1, inventory.revision());
      assertTrue(Arrays.equals(previous, Files.readAllBytes(output)));
      assertEquals(1, countEvents(events, "app-dependencies-loaded"));
    } finally {
      try { Files.setPosixFilePermissions(output.getParent(), writable); }
      catch (UnsupportedOperationException ignored) { }
      inventory.close();
    }
  }

  @Test
  void reportsZipReadLimitInsteadOfReadingUnboundedEntry(@TempDir Path temp) throws Exception {
    String previousLimit = System.getProperty("security.sbom.max.archive.bytes");
    System.setProperty("security.sbom.max.archive.bytes", "64");
    try {
      byte[] oversized = new byte[2048];
      for (int i = 0; i < oversized.length; i++) oversized[i] = (byte) (i * 31);
      Path artifact = archive(temp, "oversized.jar", mapOf("BOOT-INF/lib/oversized.jar", oversized));
      RecordingReceiver receiver = scan(artifact);
      assertTrue(receiver.incomplete.contains("archive_byte_limit"));
    } finally {
      if (previousLimit == null) System.clearProperty("security.sbom.max.archive.bytes");
      else System.setProperty("security.sbom.max.archive.bytes", previousLimit);
    }
  }

  @Test
  void appliesZipReadLimitToUninterestingEntries(@TempDir Path temp) throws Exception {
    String previousLimit = System.getProperty("security.sbom.max.archive.bytes");
    System.setProperty("security.sbom.max.archive.bytes", "64");
    try {
      byte[] uninteresting = new byte[2048];
      for (int i = 0; i < uninteresting.length; i++) uninteresting[i] = (byte) (i * 17);
      Path artifact = archive(temp, "uninteresting-oversized.jar", mapOf("payload.bin", uninteresting));
      RecordingReceiver receiver = scan(artifact);
      assertTrue(receiver.incomplete.contains("archive_byte_limit"));
    } finally {
      if (previousLimit == null) System.clearProperty("security.sbom.max.archive.bytes");
      else System.setProperty("security.sbom.max.archive.bytes", previousLimit);
    }
  }

  private static RecordingReceiver scan(Path path) {
    RecordingReceiver receiver = new RecordingReceiver();
    new ArchiveScanner(receiver).scan(path);
    return receiver;
  }

  @Test
  void compactSnapshotKeepsFallbackHashAndSplitsWithoutLosingDependencies() throws Exception {
    System.setProperty("security.evidence.max.bytes", "2048");
    List<Map<String, Object>> records = new ArrayList<>();
    for (int i = 0; i < 150; i++) {
      Component component = new Component("library-" + i + "-中文", "org.example", "1.0", "aabb", "maven-metadata");
      component.loaded = true;
      records.add(component.json());
    }
    Component fallback = new Component("no-metadata", "", "2.0", "abcd", "filename");
    fallback.loaded = true;
    records.add(fallback.json());
    records.add(fallback.json());
    records.add(new Component("not-loaded", "org.example", "1.0", "ffff", "maven-metadata").json());
    List<Map<String, Object>> parts = DependencySnapshot.events(io.securitycontext.core.Values.map(
        "event_name", "app-dependencies-loaded", "sbom_id", "fixture", "revision", 2), records);
    assertTrue(parts.size() > 1);
    List<Object> dependencies = new ArrayList<>();
    for (int i = 0; i < parts.size(); i++) {
      Map<String, Object> part = parts.get(i);
      assertEquals(i, part.get("part_index"));
      assertEquals(parts.size(), part.get("part_count"));
      assertTrue(json.writeValueAsBytes(part).length <= 2048);
      dependencies.addAll((List<?>) part.get("dependencies"));
    }
    assertEquals(151, dependencies.size());
    assertTrue(dependencies.contains(io.securitycontext.core.Values.map("name", "no-metadata", "version", "2.0", "hash", "abcd")));
    List<Map<String, Object>> empty = DependencySnapshot.events(io.securitycontext.core.Values.map("event_name", "app-dependencies-loaded"), Collections.emptyList());
    assertEquals(Collections.emptyList(), empty.get(0).get("dependencies"));
  }

  private SbomInventory inventory(Path output, List<Map<String, Object>> events, Instrumentation instrumentation) {
    System.setProperty("security.sbom.output", output.toString());
    return new SbomInventory(instrumentation, events::add);
  }

  private static void restore(String key, String value) {
    if (value == null) System.clearProperty(key);
    else System.setProperty(key, value);
  }

  private static Instrumentation instrumentation(final Class<?>... loaded) {
    return (Instrumentation) Proxy.newProxyInstance(
        SbomInventoryBehaviorTest.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class},
        (proxy, method, args) -> {
          if (method.getName().equals("getAllLoadedClasses")) return loaded;
          if (method.getReturnType() == boolean.class) return false;
          if (method.getReturnType() == int.class) return 0;
          return null;
        });
  }

  private static Instrumentation instrumentation(final AtomicReference<Class<?>[]> loaded) {
    return (Instrumentation) Proxy.newProxyInstance(
        SbomInventoryBehaviorTest.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class},
        (proxy, method, args) -> {
          if (method.getName().equals("getAllLoadedClasses")) return loaded.get();
          if (method.getReturnType() == boolean.class) return false;
          if (method.getReturnType() == int.class) return 0;
          return null;
        });
  }

  private Path dynamicJar(Path temp) throws Exception {
    return dynamicJar(temp, "dynamic-loaded.jar", "dynamic");
  }

  private Path dynamicJar(Path temp, String name, String marker) throws Exception {
    String resourceName = "/sample/dynamic/DynamicFixture.class";
    byte[] classBytes;
    try (InputStream input = getClass().getResourceAsStream(resourceName)) {
      assertNotNull(input, "dynamic fixture class must be available in test output");
      classBytes = readAll(input);
    }
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("META-INF/maven/org.dynamic/dynamic-loaded/pom.properties",
        bytes("groupId=org.dynamic\nartifactId=dynamic-loaded\nversion=9.0.0\n"));
    entries.put("META-INF/maven/org.dynamic/dynamic-loaded/pom.xml", bytes(
        "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"));
    entries.put("sample/dynamic/DynamicFixture.class", classBytes);
    entries.put("META-INF/validation-marker.txt", bytes(marker));
    return archive(temp, name, entries);
  }

  private static Path mavenJar(Path temp, String name, String group, String artifact, String version, String payload)
      throws IOException {
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("META-INF/maven/" + group + "/" + artifact + "/pom.properties",
        bytes("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n"));
    entries.put("META-INF/maven/" + group + "/" + artifact + "/pom.xml", bytes(
        "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"));
    entries.put("payload.txt", bytes(payload));
    return archive(temp, name, entries);
  }

  private static byte[] mavenJarBytes(String group, String artifact, String version, String payload) throws IOException {
    Path temp = Files.createTempFile("sbom-test-", ".jar");
    try {
      return Files.readAllBytes(mavenJar(temp.getParent(), temp.getFileName().toString(), group, artifact, version, payload));
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  private static Path archive(Path temp, String name, Map<String, byte[]> entries) throws IOException {
    Path path = temp.resolve(name);
    Files.createDirectories(path.getParent());
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        output.putNextEntry(new ZipEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return path;
  }

  private static RecordingReceiver receiverWith(List<Record> records) { return new RecordingReceiver(records); }

  private static Record find(List<Record> records, String name) {
    for (Record record : records) if (record.component.name.equals(name)) return record;
    return null;
  }

  private static Map<String, Object> read(Path output) throws IOException {
    return new ObjectMapper().readValue(output.toFile(), Map.class);
  }

  private static void assertCycloneDx1_7(Map<String, Object> document) {
    assertEquals("CycloneDX", document.get("bomFormat"));
    assertEquals("1.7", document.get("specVersion"));
    assertTrue(document.get("serialNumber") instanceof String);
    assertTrue(String.valueOf(document.get("serialNumber")).startsWith("urn:uuid:"));
    assertTrue(document.get("version") instanceof Number);
    assertTrue(((Number) document.get("version")).intValue() > 0);
    assertTrue(document.get("components") instanceof List);
    assertTrue(document.get("dependencies") instanceof List);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> component(Map<String, Object> document, String name) {
    Object value = document.get("components");
    if (!(value instanceof List)) return null;
    for (Object entry : (List<Object>) value) {
      if (entry instanceof Map && name.equals(((Map<String, Object>) entry).get("name"))) return (Map<String, Object>) entry;
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String property(Map<String, Object> component, String name) {
    Object values = component.get("properties");
    if (!(values instanceof List)) return null;
    for (Object value : (List<Object>) values) {
      if (value instanceof Map && name.equals(((Map<String, Object>) value).get("name")))
        return String.valueOf(((Map<String, Object>) value).get("value"));
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String documentProperty(Map<String, Object> document, String name) {
    Object values = document.get("properties");
    if (!(values instanceof List)) return null;
    for (Object value : (List<Object>) values) {
      if (value instanceof Map && name.equals(((Map<String, Object>) value).get("name")))
        return String.valueOf(((Map<String, Object>) value).get("value"));
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> event(List<Map<String, Object>> events, String eventName, String key, Object value) {
    for (Map<String, Object> candidate : events) {
      if (eventName.equals(candidate.get("event_name")) && value.equals(candidate.get(key))) return candidate;
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static Map<?, ?> historyEntry(Map<String, Object> history, String ref) {
    Object entries = history.get("entries");
    if (!(entries instanceof List)) return null;
    for (Object entry : (List<Object>) entries) {
      if (entry instanceof Map && ref.equals(((Map<?, ?>) entry).get("bom-ref"))) return (Map<?, ?>) entry;
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String licenseName(Map<String, Object> component) {
    Object values = component.get("licenses");
    if (!(values instanceof List) || ((List<?>) values).isEmpty()) return null;
    Object first = ((List<?>) values).get(0);
    if (!(first instanceof Map)) return null;
    Object license = ((Map<?, ?>) first).get("license");
    if (!(license instanceof Map)) return null;
    return String.valueOf(((Map<?, ?>) license).get("name"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> quality(Map<String, Object> document) throws IOException {
    String value = documentProperty(document, "securitycontext:sbom:quality");
    return value == null ? Collections.emptyMap() : new ObjectMapper().readValue(value, Map.class);
  }

  @SuppressWarnings("unchecked")
  private static String completenessReasons(Map<String, Object> document) {
    Object values = document.get("properties");
    if (!(values instanceof List)) return "";
    for (Object value : (List<Object>) values) {
      if (value instanceof Map && "securitycontext:sbom:completeness-reasons".equals(((Map<String, Object>) value).get("name")))
        return String.valueOf(((Map<String, Object>) value).get("value"));
    }
    return "";
  }

  @SuppressWarnings("unchecked")
  private static String applicationComponentRef(Map<String, Object> document) {
    Map<String, Object> metadata = (Map<String, Object>) document.get("metadata");
    Map<String, Object> component = (Map<String, Object>) metadata.get("component");
    return String.valueOf(component.get("bom-ref"));
  }

  @SuppressWarnings("unchecked")
  private static boolean containsDependency(List<?> dependencies, String ref, String target) {
    for (Object value : dependencies) {
      if (!(value instanceof Map)) continue;
      Map<String, Object> dependency = (Map<String, Object>) value;
      if (!ref.equals(dependency.get("ref"))) continue;
      Object targets = dependency.get("dependsOn");
      return targets instanceof List && ((List<Object>) targets).contains(target);
    }
    return false;
  }

  private static int countEvents(List<Map<String, Object>> events, String eventName) {
    int count = 0;
    for (Map<String, Object> event : events) if (eventName.equals(event.get("event_name"))) count++;
    return count;
  }

  private static String stringValue(Object value) { return value == null ? null : String.valueOf(value); }

  private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }

  private static byte[] readAll(InputStream input) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
    return output.toByteArray();
  }

  private static Map<String, byte[]> mapOf(Object... pairs) {
    Map<String, byte[]> result = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) result.put(String.valueOf(pairs[i]), (byte[]) pairs[i + 1]);
    return result;
  }

  private static Map<String, Object> mapOfObjects(Object... pairs) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) result.put(String.valueOf(pairs[i]), pairs[i + 1]);
    return result;
  }

  private static final class Record {
    final Component component;
    final String location;
    final boolean primary;
    Record(Component component, String location, boolean primary) {
      this.component = component;
      this.location = location;
      this.primary = primary;
    }
  }

  private static final class RecordingReceiver implements ArchiveScanner.Receiver {
    final List<Record> components = new ArrayList<>();
    final List<Map<String, Object>> imported = new ArrayList<>();
    final List<String> incomplete = new ArrayList<>();
    RecordingReceiver() { }
    RecordingReceiver(List<Record> records) { components.addAll(records); }
    @Override public void component(Component component, String location, boolean primary) {
      components.add(new Record(component, location, primary));
    }
    @Override public void imported(String location, Map<String, Object> bom) { imported.add(bom); }
    @Override public void incomplete(String reason) { incomplete.add(reason); }
  }

  private static final class CoordinatedLoader extends URLClassLoader {
    private static final String TARGET = "sample.dynamic.DynamicFixture";
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    volatile boolean gate;

    CoordinatedLoader(Path artifact, boolean gate) throws IOException {
      super(new URL[] {artifact.toUri().toURL()}, null);
      this.gate = gate;
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      if (gate && TARGET.equals(name)) {
        entered.countDown();
        try {
          if (!release.await(5, TimeUnit.SECONDS)) throw new ClassNotFoundException("resolve gate timeout");
        } catch (InterruptedException error) {
          Thread.currentThread().interrupt();
          throw new ClassNotFoundException("resolve gate interrupted", error);
        }
      }
      return super.loadClass(name, resolve);
    }
  }

  private static final class NestedSourceLoader extends ClassLoader {
    NestedSourceLoader() { super(null); }

    Class<?> define(String name, byte[] bytes, URL location) {
      ProtectionDomain domain = new ProtectionDomain(new CodeSource(location, (Certificate[]) null), null, this, null);
      return defineClass(name, bytes, 0, bytes.length, domain);
    }
  }
}
