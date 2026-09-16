# SecurityContext Java 0.3.4

SecurityContext `0.3.4` 是一个 OpenTelemetry Java Agent extension，提供有界的安全数据流观察和运行时 SBOM。应用不需要修改业务源码。包内 `validation.json`、`manifest.json` 和 `SHA256SUMS` 随包记录本次制品和验证结果；独立解包后的 `release-validation.json` 是 bundle `java/` 目录中与归档并列的可选发行验收记录，不进入包内；请以这些记录为准，不把历史数字复制到当前报告。

## 包内容

- `lib/securitycontext.jar`：Java 8 字节码扩展，命名空间 `io.securitycontext.*`；
- `lib/opentelemetry-javaagent-2.31.1.jar`：配套 OTel Java Agent；
- `examples/apps/`：Boot 2/3 黑盒样例；
- `examples/observed/`：本次包产生的观察结果（存在时）；
- `collector/`：随包 Collector 配置；
- `bin/securityctl.py`、`bin/run-demo.sh`：本地查询、控制、验证和样例启动；
- `docs/`：中英文完整指南；
- `validation.json`、`manifest.json`、`SHA256SUMS`：包内实际制品和验证记录；
- bundle `java/` 目录中与归档并列的 `release-validation.json`（若提供）：独立解包/收件验收记录，不属于包内容；
- `licenses/`：SecurityContext 的 Apache-2.0 许可证、第三方许可证和来源索引。

Java 目标运行时为 8/11/17/21，Agent 目标版本为 `2.31.1`，extension API 为 `2.31.1-alpha`。解压后执行：

```bash
shasum -a 256 -c SHA256SUMS       # macOS
sha256sum -c SHA256SUMS           # Linux
```

## 快速启动

```bash
./bin/run-demo.sh boot2
./bin/run-demo.sh boot3
```

接入自己的应用：

```bash
java \
  -javaagent:/path/to/lib/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/lib/securitycontext.jar \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=my-application \
  -Dsecurity.output=./security-output \
  -Dsecurity.evidence.file=./security-output/evidence.jsonl \
  -jar application.jar
```

已有 OTel Agent 时只追加 extension，不启动第二个 Agent。HTTP Server instrumentation 应在应用请求前可用；否则不能保证 request 和 server span 状态。

## 输出契约

`health.json`、`findings.json`、`runs.json`、`sbom-history.json` 等自有状态快照顶层带 `source=security_context`。SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。health、SBOM 和 history 是进程级快照，不强行关联请求 trace。schema v2 事件平铺 `application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status` 六个 identity 字段，scope 为 `SecurityContext`，native `eventName`、`event.name` attribute 和 body `event_name` 一致。source、sink、range、component、fingerprint2、trace 和截断规则见包内[中文指南](docs/guide.zh-CN.md)或[English guide](docs/guide.en.md)。

CycloneDX 保持标准顶层结构，source 放在标准 `properties[]`，组件 ref 使用 `urn:securitycontext:component:`。SBOM 事件走独立通道，不写 security JSONL。CLI report/control 仍带 source，但自身状态 schema 可以为 v1。

## CLI、停用与排障

```bash
OUT=/absolute/path/to/security-output
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
python3 bin/securityctl.py --dir "$OUT" query sbom
python3 bin/securityctl.py --dir "$OUT" pause
python3 bin/securityctl.py --dir "$OUT" resume
```

验证结果应通过包内 `validation.json`、bundle `java/` 目录中与归档并列的可选 `release-validation.json` 和 run 输出解释。停用时使用 `-Dsecurity.enabled=false -Dsecurity.sbom.enabled=false` 并重启；卸载前停止 JVM、移除 `otel.javaagent.extensions` 中的 JAR，再删除文件。运行中的 JVM 不会热卸载扩展。

默认不输出请求原文、完整 SQL、命令文本、完整 URL 或命令参数值。未建模动态代码、跨服务传播、任意二进制请求体、强杀/主机故障恢复、trace replay、Collector/backend ACK、性能和 SLA 不在默认保证范围内。

完整配置、验证 run、升级破坏性改名、fingerprint2、SBOM、trace 和故障排查见[中文使用指南](docs/guide.zh-CN.md)。
