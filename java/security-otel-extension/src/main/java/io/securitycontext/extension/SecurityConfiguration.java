package io.securitycontext.extension;

import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SecurityConfiguration implements AutoConfigurationCustomizerProvider {
  static volatile Map<String, String> applicationIdentity = Collections.emptyMap();
  @Override public void customize(AutoConfigurationCustomizer customizer) {
    customizer.addResourceCustomizer((resource, config) -> {
      Map<String, String> identity = new LinkedHashMap<>();
      resource.getAttributes().forEach((key, value) -> {
        String name = key.getKey();
        if (name.equals("service.name") || name.equals("service.version") || name.equals("service.namespace") ||
            name.equals("service.instance.id") || name.equals("deployment.environment.name")) {
          identity.put(name, String.valueOf(value));
        }
      });
      applicationIdentity = Collections.unmodifiableMap(identity);
      io.securitycontext.core.Identity.configure(identity);
      return resource;
    });
  }
}
