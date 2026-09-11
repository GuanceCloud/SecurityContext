package io.securitycontext.extension;

import io.securitycontext.core.Settings;
import io.opentelemetry.javaagent.extension.ignore.IgnoredTypesBuilder;
import io.opentelemetry.javaagent.extension.ignore.IgnoredTypesConfigurer;

public final class SecurityIgnoredTypes implements IgnoredTypesConfigurer {
  @Override public void configure(IgnoredTypesBuilder builder) {
    if (!Settings.enabled("security.enabled", true)) return;
    // The agent excludes these framework paths as an optimization. They contain
    // the binding and execution boundaries used by this security extension.
    builder.allowClass("org.springframework.http.converter.")
        .allowClass("org.springframework.web.method.annotation.")
        .allowClass("org.springframework.web.context.request.ServletWebRequest")
        .allowClass("org.springframework.jdbc.")
        .allowClass("org.springframework.web.client.RestTemplate")
        .allowClass("org.springframework.core.convert.");
  }
  @Override public int order() { return 100; }
}
