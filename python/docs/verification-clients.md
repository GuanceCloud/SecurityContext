# Python client-contract verification

This report belongs to the independent client QA slice. It covers only
controlled loopback HTTP and read-only SQL calls; it does not alter production
code, application data, or unrelated containers.

## Scope

- Actual sends through `requests`, `httpx` sync/async, `aiohttp`, and
  `urllib.request`, including carrier construction without send, fixed-host
  query/params negative cases, a tainted loopback authority positive case,
  response-body non-propagation, subclass override, and observer fail-open.
- Safe `/usr/bin/true` `subprocess.run`/`Popen` and `os.system` calls with
  executable, argument, and shell-script roles.
- `pathlib.Path` read/write/rename/delete calls with return-type assertions.
- SQLAlchemy 2 text/`Connection.execute`, `exec_driver_sql`, and
  `Session.execute`; Django lazy `raw`/`RawSQL` execution and parameterized
  negative; optional actual psycopg3 sync/async and PyMySQL cursor variants.

## Evidence status

The generated JSON artifacts are under
`build/validation/python-v01/clients/`. Each is from an actual OrbStack
execution of the same bounded runner; no result below is inferred from an
unexecuted cross-product.

| Runtime/container | Artifact | Python/profile | Result | Database images |
| --- | --- | --- | --- | --- |
| `securitycontext-py-311` | `client-qa-py311.json` | CPython 3.11.16 / `7cb45c48a8c57d588e6fe19a76b100ac5e9302029d2b3e66f906fec38f3faec6` | 13 passed, 0 failed, 0 unverified | PostgreSQL `16-alpine`; MySQL `8.4.11` |
| `securitycontext-py-312` | `client-qa.json` and `client-qa-py312.json` | CPython 3.12.14 / `7879312d9702811ed621b4b72cc88bffdd7efde6c8a7cbf0c3d84a10aa3c3644` | 13 passed, 0 failed, 0 unverified | PostgreSQL `16-alpine`; MySQL `8.4.11` |
| `securitycontext-py-313` | `client-qa-py313.json` | CPython 3.13.15 / `247be463faa5945b5e4967f992c6012de8b1f5c0409e9481810a42bf5efcdf87` | 13 passed, 0 failed, 0 unverified | PostgreSQL `16-alpine`; MySQL `8.4.11` |
| `securitycontext-py-314` | `client-qa-py314.json` | CPython 3.14.7 / `e696aae2deadb4c58768279fd4748dcab0e311548e6e10fe5977aa1a7396cbf3` | 13 passed, 0 failed, 0 unverified | PostgreSQL `16-alpine`; MySQL `8.4.11` |

The dependency set was the same in all four containers: OpenTelemetry API
`1.44.0`, instrumentation `0.65b0`, requests `2.34.2`, httpx `0.28.1`,
aiohttp `3.14.3`, SQLAlchemy `2.0.52`, Django `5.2.17`, psycopg `3.3.5`, and
PyMySQL distribution metadata `1.2.0` with module `__version__` `2.2.8`.

The task-owned database containers were
`securitycontext-client-qa-pg-20260907b` and
`securitycontext-client-qa-mysql-20260907b`; both were left `Paused` after QA,
with no persistent volumes. They were read-only from the runner (`SELECT 1`
only). Host loopback mappings were
provisioned as requested; sibling-container probes used the task-owned Docker
bridge endpoints because the MySQL host-mapped route closed during handshake.

## Verified boundaries

- HTTP actual sends through requests, httpx sync/async, aiohttp, and
  `urllib.request`; construction-only calls produced no sink, fixed-host
  query/params produced input evidence without SSRF, a polluted loopback
  authority produced an SSRF event, and response bodies remained untainted.
- Subclass overrides and injected observer failures preserved the application
  result. Safe subprocess calls covered executable/argument/shell-script roles;
  pathlib covered read/write/rename/delete and preserved return types.
- SQLAlchemy verified both `sqlalchemy.text` aliases, `Connection.execute`,
  `exec_driver_sql`, and `Session.execute`. Django verified lazy `raw` and
  `RawSQL` execution plus a dynamic multi-character parameterized negative.
- psycopg3 verified sync and async connection/cursor execution. PyMySQL
  verified `Cursor`, `DictCursor`, `SSCursor`, and `SSDictCursor` with tuple or
  dict result shapes.

There are no required `failed` or `unverified` cases in the four final
artifacts. The earlier failed/intermediate artifact was overwritten for the
canonical 3.12 output (`client-qa.json`).

## Constraints

The runner does not use fixed external hosts, does not report request/query
payloads or database credentials, and does not reuse existing database
containers. Independent serial benchmarks are intentionally outside this QA
slice.
