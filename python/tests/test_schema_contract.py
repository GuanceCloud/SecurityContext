from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from securitycontext.schema import event_record, finding_fingerprint, sink_fields


FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "output-v2-cross-language.json")
    .read_text(encoding="utf-8")
)

assert FIXTURE["schema_version"] == 2
assert FIXTURE["source"] == "security_context"

ROOT_FIELDS = {
    "schema_version",
    "source",
    "event_name",
    "observed_at",
    "application_id",
    "instance_id",
    "service",
    "code",
    "runtime",
    "identity_status",
}


def test_v2_shared_fixture_has_deterministic_utf8_length_prefixed_fingerprints():
    values = [
        finding_fingerprint(
            item["application_id"],
            item["language"],
            item["rule"],
            item["sink"],
            item["signatures"],
        )
        for item in FIXTURE["fingerprints"]
    ]
    for item, value in zip(FIXTURE["fingerprints"], values):
        assert item["expected"].startswith("finding-")
        assert value == item["expected"], item["name"]
    assert values[1] != values[2], "length prefixes must distinguish delimiter-boundary signatures"


def test_v2_sink_aliases_expose_canonical_dimensions():
    for item in FIXTURE["sink_aliases"]:
        expected = {
            "function": item["function"],
            "role": item["expected"]["role"],
            "location": item["location"],
            "operation": item["expected"]["operation"],
            "path_role": item["expected"]["path_role"],
            "input_part": item["expected"]["input_part"],
        }
        assert sink_fields(
            item["rule"], item["role"], item["function"], item["location"]
        ) == expected, f"{item['rule']}:{item['role']}"


def test_v2_event_helper_emits_complete_root_identity_and_diagnostic_defaults():
    for template in FIXTURE["event_templates"].values():
        event = event_record({**template, "source": "caller-override"}, FIXTURE["identity"])
        assert ROOT_FIELDS <= event.keys()
        assert event["schema_version"] == 2
        assert event["source"] == template["source"]
        assert "identity" not in event
        assert event["application_id"] == FIXTURE["identity"]["application_id"]
        assert event["instance_id"] == FIXTURE["identity"]["instance_id"]
        assert event["service"] == FIXTURE["identity"]["service"]
        assert event["code"] == FIXTURE["identity"]["code"]
        assert event["runtime"] == FIXTURE["identity"]["runtime"]
        assert event["identity_status"] == "configured"
        datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))

    dataflow = event_record(FIXTURE["event_templates"]["dataflow"], FIXTURE["identity"])
    assert dataflow["fingerprint_version"] == 2
    assert dataflow["server_span_id"] == FIXTURE["event_templates"]["dataflow"]["server_span_id"]
    assert dataflow["current_span_id"] == FIXTURE["event_templates"]["dataflow"]["current_span_id"]
    assert dataflow["trace_flags"] == FIXTURE["event_templates"]["dataflow"]["trace_flags"]
    assert "severity_text" not in dataflow
    assert "severity_number" not in dataflow
    assert "scope" not in dataflow
    assert isinstance(dataflow["sources"], list)
    assert isinstance(dataflow["ranges"], list)
    assert isinstance(dataflow["stack"], list)

    incomplete = event_record(FIXTURE["event_templates"]["incomplete"], FIXTURE["identity"])
    assert incomplete["counts"] == {
        "objects": None,
        "nodes": None,
        "sources": None,
        "findings": None,
        "retained_bytes": None,
    }
    assert incomplete["collection_status"] == "unknown"
    assert incomplete["truncated"] is True

    snapshot = event_record(FIXTURE["event_templates"]["sbom_snapshot"], FIXTURE["identity"])
    assert snapshot["dropped_observations"] == 0
    health = event_record(FIXTURE["event_templates"]["sbom_health"], FIXTURE["identity"])
    assert health["last_error_type"] == "fixture_error"
    assert isinstance(health["reasons"], list)
    assert health["dropped_observations"] == 0
