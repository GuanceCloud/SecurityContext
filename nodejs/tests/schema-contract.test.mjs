import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  eventRecord,
  findingFingerprint,
  sinkFields,
} from '../src/schema.mjs';

const fixturePath = resolve(dirname(fileURLToPath(import.meta.url)), '../../tests/fixtures/output-v2-cross-language.json');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

assert.equal(fixture.schema_version, 2);
assert.equal(fixture.source, 'security_context');

const rootFields = [
  'schema_version', 'source', 'event_name', 'observed_at', 'application_id',
  'instance_id', 'service', 'code', 'runtime', 'identity_status',
];

test('v2 shared fixture has deterministic UTF-8 length-prefixed fingerprints', () => {
  const values = fixture.fingerprints.map((item) => findingFingerprint(
    item.application_id,
    item.language,
    item.rule,
    item.sink,
    item.signatures,
  ));
  for (const [index, item] of fixture.fingerprints.entries()) {
    assert.match(item.expected, /^finding-[0-9a-f]{64}$/);
    assert.equal(values[index], item.expected, item.name);
  }
  assert.notEqual(values[1], values[2], 'length prefixes must distinguish delimiter-boundary signatures');
});

test('v2 sink aliases expose canonical dimensions', () => {
  for (const item of fixture.sink_aliases) {
    assert.deepEqual(
      sinkFields(item.rule, item.role, item.function, item.location),
      { function: item.function, location: item.location, ...item.expected },
      `${item.rule}:${item.role}`,
    );
  }
});

test('v2 event helper emits complete root identity and diagnostic defaults', () => {
  for (const template of Object.values(fixture.event_templates)) {
    const event = eventRecord({ ...template, source: 'caller-override' }, fixture.identity);
    for (const field of rootFields) assert.ok(field in event, field);
    assert.equal(event.schema_version, 2);
    assert.equal(event.source, template.source);
    assert.equal(event.identity, undefined);
    assert.equal(event.application_id, fixture.identity.application_id);
    assert.equal(event.instance_id, fixture.identity.instance_id);
    assert.deepEqual(event.service, fixture.identity.service);
    assert.deepEqual(event.code, fixture.identity.code);
    assert.deepEqual(event.runtime, fixture.identity.runtime);
    assert.equal(event.identity_status, 'configured');
    assert.ok(!Number.isNaN(Date.parse(event.observed_at)));
  }

  const dataflow = eventRecord(fixture.event_templates.dataflow, fixture.identity);
  assert.equal(dataflow.fingerprint_version, 2);
  assert.equal(dataflow.server_span_id, fixture.event_templates.dataflow.server_span_id);
  assert.equal(dataflow.current_span_id, fixture.event_templates.dataflow.current_span_id);
  assert.equal(dataflow.trace_flags, fixture.event_templates.dataflow.trace_flags);
  assert.equal(dataflow.severity_text, undefined);
  assert.equal(dataflow.severity_number, undefined);
  assert.equal(dataflow.scope, undefined);
  assert.ok(Array.isArray(dataflow.sources));
  assert.ok(Array.isArray(dataflow.ranges));
  assert.ok(Array.isArray(dataflow.stack));

  const incomplete = eventRecord(fixture.event_templates.incomplete, fixture.identity);
  assert.deepEqual(incomplete.counts, {
    objects: null, nodes: null, sources: null, findings: null, retained_bytes: null,
  });
  assert.equal(incomplete.collection_status, 'unknown');
  assert.equal(incomplete.truncated, true);

  const snapshot = eventRecord(fixture.event_templates.sbom_snapshot, fixture.identity);
  assert.equal(snapshot.dropped_observations, 0);
  const health = eventRecord(fixture.event_templates.sbom_health, fixture.identity);
  assert.equal(health.last_error_type, 'fixture_error');
  assert.ok(Array.isArray(health.reasons));
  assert.equal(health.dropped_observations, 0);
});
