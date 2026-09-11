# SecurityContext 演示应用与样例入口

`boot2` 和 `boot3` 是通过真实 OTel Java Agent 注入扩展的黑盒样例。它们用于构造 source、传播、sink、响应对照和 Servlet 生命周期场景，不代表业务安全结论。candidate3 已完成 Boot 2 Java 8/11、Boot 3 Java 17/21 的路由、负对照、async、smoke 和 SBOM 关联验收；Boot 3 Java 17/21 另有正常退出的 ledger flush 产物。

## HTTP 合约

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | readiness probe |
| `GET /api/sql?value=...` | dynamic SQL statement sink |
| `GET /api/sql/constant` | constant SQL sink-only fixture |
| `GET /api/sql/parameterized?value=...` | parameterized SQL control |
| `GET /api/sql/prepared-template?value=...` | polluted PreparedStatement template |
| `POST /api/json/sql` | JSON body to dynamic SQL |
| `POST /api/raw/reader/sql` | Servlet reader body to dynamic SQL |
| `POST /api/raw/jackson/sql` | Servlet stream parsed by Jackson to dynamic SQL |
| `POST /api/pojo/sql` | JSON POJO field to dynamic SQL |
| `POST /api/list/sql` | JSON list element to dynamic SQL |
| `POST /api/text/sql` | text body to dynamic SQL |
| `GET /api/header/sql` | header to dynamic SQL |
| `POST /api/form/sql` | form parameter to dynamic SQL |
| `POST /api/model/sql` | `@ModelAttribute` form binding to dynamic SQL |
| `GET /api/command?value=...` | shell text passed to `Runtime.exec` |
| `GET /api/command/lc?value=...` | shell text passed to `sh -lc` |
| `GET /api/command/safe?value=...` | fixed executable with an ordinary argument |
| `GET /api/fetch?url=...` | URLConnection outbound request |
| `GET /api/fetch/address?host=...` | controlled URL destination address |
| `GET /api/fetch/query?query=...` | controlled URL query with fixed destination |
| `GET /api/fetch/construct?url=...` | URL construction without a send |
| `GET /api/fetch/response-sql?url=...` | dynamic remote response concatenated into SQL; URL source must not contaminate response |
| `GET /api/fetch/rest-template?mode=raw&value=...` | RestTemplate destination, query-only and body-only controls |
| `GET /api/fetch/rest-template-response-sql?url=...` | RestTemplate response followed by dynamic SQL control |
| `GET /api/fetch/apache4?url=...` | Apache HttpClient 4 outbound request |
| `GET /api/fetch/apache5?url=...` | Apache HttpClient 5 outbound request |
| `GET /api/fetch/okhttp?url=...` | OkHttp outbound request |
| `GET /api/fetch/jdk?url=...` | Java 11+ HttpClient (Boot 3 only) |
| `GET /api/file/read?path=...` | file path read sink |
| `GET /api/file/write?path=...` | file path write sink |
| `GET /api/file/normalize?path=...` | normalized path to file read |
| `GET /api/async/sql?value=...` | async task to SQL sink |
| `GET /api/async/servlet?value=...` | Servlet `DeferredResult` async SQL sink |
| `GET /api/exception?value=...` | intentional request exception for lifecycle cleanup |
| `POST /api/json` | JSON binding and string propagation |
| `GET /api/transform?value=...` | string transformations |
| `GET /api/bytecode?value=...` | constructor branch, long/double and `try/finally` fixture |

响应对照的 SQL 使用动态拼接；对照的意义是验证来源边界，而不是声明 RestTemplate 或响应数据流已完整建模。

## 构建和运行

`boot2` 目标为 Spring Boot 2.7.18、`javax` Servlet 和 Java 8 字节码；`boot3` 目标为 Spring Boot 3.5.0、`jakarta` Servlet 和 Java 17 字节码。仓库根目录构建：

```bash
./scripts/orbstack_build.sh \
  :security-otel-extension:shadowJar \
  :samples:boot2:bootJar \
  :samples:boot3:bootJar
```

产物名分别为 `security-validation-boot2.jar` 和 `security-validation-boot3.jar`。使用 OTel Agent 2.31.1 注入时，建议显式设置本次 output 和代码身份：

```bash
java \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -Dsecurity.output=./build/validation/my-run \
  -Dsecurity.application.id=security-validation-boot2 \
  -Dsecurity.code.repository=https://example.invalid/SecurityContext \
  -Dsecurity.code.commit=local-commit \
  -Dsecurity.code.build-id=local-build \
  -Dsecurity.evidence.file=./build/validation/my-run/evidence.jsonl \
  -jar samples/boot2/build/libs/security-validation-boot2.jar
```

默认 output 目录是带 process instance UUID 的 `./security-output/<instance-id>`。在 run 验证中不要让其他流量进入同一个进程：`run-start` 的作用域是 run 期间该进程接收的所有 HTTP 请求。

## 本地回归入口

响应 smoke：

```bash
tests/smoke.sh
```

对已启动的注入应用执行单请求证据矩阵：

```bash
ASSERT_ROUTE_EVIDENCE=1 scripts/validate_injection.sh
```

原始请求体、并发隔离和开关入口：

```bash
EVIDENCE_FILE=build/validation/<leg>/evidence.jsonl \
  tests/raw_body_evidence.sh http://127.0.0.1:<port> \
  build/validation/<leg>/evidence.jsonl

EVIDENCE_FILE=build/validation/<leg>/evidence.jsonl \
  tests/concurrency_isolation.sh http://127.0.0.1:<port> \
  build/validation/<leg>/evidence.jsonl

scripts/validate_switches.sh
```

这些脚本是可复用的回归入口；它们产生的旧 e604/da99 目录不能直接作为 0.2.0 验收。0.2.0 run 应使用本地 CLI：

```bash
python3 scripts/securityctl.py --dir ./build/validation/my-run run-start \
  --case sql-dynamic --rule sql_injection \
  --suite security-matrix --fixture boot2-java8 \
  --expected-requests 1 --ttl 300

# 发送唯一的 case 请求后：
python3 scripts/securityctl.py --dir ./build/validation/my-run run-stop \
  --output ./build/validation/my-run/sql-dynamic.run.json
```

baseline/candidate 的 `identity.code.repository`、`commit`、`build_id` 必须完整，`securityctl.py verify` 的 `not_observed` 只表示指定 fixture/suite 和请求门槛下未观察到风险，不表示 fixed。完整命令和 output 字段见[运行运维与 CLI](../docs/operations.md)。

## 客户端版本和边界

正式样例的网络路由覆盖 Apache HttpClient 4/5、OkHttp 4.12.0 和 Java 17/21 JDK HttpClient；OkHttp 3.14.9 仅作为 Java 8 的独立兼容样例。RestTemplate 的 String/URI 目的地及 RestOperations 调用通过统一 execute 入口观察，query-only 和 body-only 有独立对照；URLConnection/RestTemplate response 对照验证“URL 来源不自动进入响应值”。任意 URI 模板、RequestEntity 和自定义客户端覆盖仍需独立验证。

请求体采集不提前读取：Servlet `getReader`/`getInputStream` 只登记 carrier，应用执行 `readLine` 或 Jackson `readValue` 后登记；Spring MVC 在 `readWithMessageConverters` 返回后登记绑定结果。URL/URI accessor 会按结构区段裁剪来源，构造 URL 不算发送。WebFlux、跨服务传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化漏洞和动态 attach 不在本原型范围。
