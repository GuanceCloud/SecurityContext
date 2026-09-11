import os
import uuid
from pathlib import Path


def post_fork(server, worker):
    if server.cfg.preload_app:
        raise RuntimeError("SecurityContext requires Gunicorn preload_app=False")
    worker_directory = f"worker-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    root = Path(os.environ.get("SECURITY_OUTPUT", "security-output"))
    os.environ["SECURITY_OUTPUT"] = str(root / worker_directory)
    for key in ("SECURITY_EVIDENCE_FILE", "SECURITY_CONTROL_FILE", "SECURITY_SBOM_OUTPUT"):
        configured = os.environ.get(key)
        if not configured:
            continue
        path = Path(configured)
        if key == "SECURITY_SBOM_OUTPUT" and path.suffix.lower() != ".json":
            path = path / worker_directory
        else:
            path = path.parent / worker_directory / path.name
        os.environ[key] = str(path)
    from opentelemetry.instrumentation.auto_instrumentation import initialize
    initialize()


preload_app = False
