from __future__ import annotations

from opentelemetry.instrumentation.instrumentor import BaseInstrumentor

from .config import VERSION as __version__


def bootstrap():
    from . import config
    disabled = {value.strip() for value in config.text("otel.python.disabled.instrumentations").split(",")}
    if "securitycontext" in disabled or "*" in disabled or not config.collection_configured():
        return
    from .loader import install
    install()


class SecurityInstrumentor(BaseInstrumentor):
    def instrumentation_dependencies(self):
        return ()

    def _instrument(self, **kwargs):
        from . import config, runtime

        bootstrap()
        adapters = []
        if config.collection_configured():
            from . import frameworks, sinks
            from opentelemetry.instrumentation.threading import ThreadingInstrumentor

            for module in (frameworks, sinks):
                try:
                    adapters.extend(module.install())
                except Exception as error:
                    runtime.startup_gap("adapter_install_failed:" + module.__name__ + ":" + type(error).__name__)
            threading = ThreadingInstrumentor()
            if not threading.is_instrumented_by_opentelemetry:
                threading.instrument()
            adapters.append("otel.threading")
        runtime.start(adapters)

    def _uninstrument(self, **kwargs):
        from . import runtime
        from .loader import uninstall

        runtime.stop()
        uninstall()
