package io.securitycontext.extension;

import io.securitycontext.core.SecurityState;
import io.securitycontext.core.Settings;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.api.incubator.instrumenter.InstrumenterCustomizer;
import io.opentelemetry.instrumentation.api.incubator.instrumenter.InstrumenterCustomizerProvider;
import io.opentelemetry.instrumentation.api.instrumenter.OperationListener;

public final class HttpLifecycle implements InstrumenterCustomizerProvider {
  @Override public void customize(InstrumenterCustomizer customizer) {
    if (!customizer.hasType(InstrumenterCustomizer.InstrumentationType.HTTP_SERVER)) return;
    customizer.addOperationMetrics(meter -> new OperationListener() {
      @Override public Context onStart(Context context, Attributes attributes, long startNanos) {
        SecurityState existing = context.get(SecurityRuntime.STATE);
        if (existing != null && existing.active()) return context;
        SecurityState state = new SecurityState();
        state.traceId = Span.fromContext(context).getSpanContext().getTraceId();
        state.serverSpanId = Span.fromContext(context).getSpanContext().getSpanId();
        state.traceFlags = Span.fromContext(context).getSpanContext().getTraceFlags().asByte() & 255;
        request(state, attributes);
        SecurityRuntime.begin(state);
        return context.with(SecurityRuntime.STATE, state);
      }
      @Override public void onEnd(Context context, Attributes attributes, long endNanos) {
        SecurityState state = context.get(SecurityRuntime.STATE);
        Span span = Span.fromContext(context);
        if (state == null || !state.serverSpanId.equals(span.getSpanContext().getSpanId())) return;
        try {
          request(state, attributes);
          SecurityRuntime.end(state, context);
          if (!state.evidenceIds().isEmpty()) {
            span.setAttribute("security.detected", true);
            span.setAttribute("security.finding_count", state.evidenceIds().size());
            span.setAttribute(AttributeKey.stringArrayKey("security.types"), state.types());
            span.setAttribute(AttributeKey.stringArrayKey("security.evidence.ids"), state.evidenceIds());
            span.setAttribute(AttributeKey.stringArrayKey("security.finding.ids"), state.findingIds());
          }
          if (state.truncated()) span.setAttribute("security.truncated", true);
        } finally { state.close(); }
      }
    });
  }

  private static void request(SecurityState state, Attributes attributes) {
    String method = attributes.get(AttributeKey.stringKey("http.request.method"));
    if (method == null) method = attributes.get(AttributeKey.stringKey("http.method"));
    String route = attributes.get(AttributeKey.stringKey("http.route"));
    Long status = attributes.get(AttributeKey.longKey("http.response.status_code"));
    if (status == null) status = attributes.get(AttributeKey.longKey("http.status_code"));
    if (method != null) state.request.put("method", io.securitycontext.core.Values.bounded(method, 32));
    if (route != null) state.request.put("route", io.securitycontext.core.Values.bounded(route, 1024));
    if (status != null) state.request.put("status_code", status);
    state.request.put("route_status", state.request.containsKey("route") ? "observed" : "unavailable");
    state.request.put("started_at", io.securitycontext.core.Events.timestamp(state.startedAt));
  }
}
