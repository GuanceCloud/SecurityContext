# SecurityContext

[![CI](https://github.com/GuanceCloud/SecurityContext/actions/workflows/ci.yml/badge.svg)](https://github.com/GuanceCloud/SecurityContext/actions/workflows/ci.yml)

SecurityContext 是面向 Java、Node.js 和 Python 应用的 OpenTelemetry 安全数据流与运行时 SBOM 原型。它在不修改业务源码的前提下，采集从 HTTP 输入到 SQL、命令执行、HTTP 外连和文件访问的有界证据，并生成 CycloneDX 1.7 SBOM。

本项目不是漏洞扫描器。`observed` 只表示在指定条件下观察到调用链路，不表示攻击成功；`not_observed` 也不等于证明不存在漏洞。

## 实现与版本

| 实现 | 当前版本 | 运行时范围 | 接入方式 |
| --- | --- | --- | --- |
| Java | 0.3.4 | Java 8/11/17/21 | OTel Java Agent extension |
| Node.js | 0.2.5 | Node.js 22.22.3、24.11.1 | `--import` 预加载 |
| Python | 0.2.5 | CPython 3.11–3.14 | OTel 自动加载入口 |

三种实现共用 schema v2、Collector 配置与 CLI 语义，但分别维护制品、兼容边界和验证记录：

- [Java 工程说明](java/README.md)
- [Node.js 使用说明](nodejs/README.md)
- [Python 使用说明](python/README.md)
- [统一日志结构](docs/security-context-log-schema.md)

当前版本仍处于原型阶段，尚未发布到 Maven Central、npm 或 PyPI。仓库中的测试结果不构成生产容量、性能或 SLA 承诺。

## 快速开始

### Java

构建扩展 JAR：

```bash
cd java
./gradlew :security-otel-extension:shadowJar
```

产物位于 `java/security-otel-extension/build/libs/securitycontext.jar`。与 OpenTelemetry Java Agent 一起启动应用：

```bash
java \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=my-application \
  -jar application.jar
```

完整配置见[配置参考](docs/configuration.md)。

### Node.js

```bash
cd nodejs
npm ci
SECURITY_ENABLED=true node --import ./src/register.mjs your-app.mjs
```

安装、框架适配和环境变量见 [Node.js 指南](nodejs/docs/guide.zh-CN.md)。

### Python

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e "./python[fastapi,otlp]"

SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=myapp \
OTEL_SERVICE_NAME=myapp \
opentelemetry-instrument uvicorn myapp.main:app
```

框架组合、Gunicorn 和输出配置见 [Python 指南](python/docs/guide.zh-CN.md)。

## 本地验证

准备 Node.js 和 Python 依赖后，可从仓库根目录使用统一入口：

```bash
make test
```

也可以分别运行：

```bash
make test-java
make test-node
make test-python
```

Python 的 SBOM 契约测试依赖官方 CycloneDX 1.7 Schema；`make test-python` 会先下载固定版本并校验 SHA-256。更完整的框架、容器、Collector 与产品验证方法见各语言目录；[Java 0.2.1 历史验证记录](docs/verification.md)仅用于追溯，不代表当前 0.3.4 已完成同一矩阵。

## 运行时输出

默认输出目录为 `./security-output/<process-instance-id>/`：

```text
security-output/<instance-id>/
├── health.json
├── findings.json
├── runs.json
├── control.json
├── application.cdx.json
└── sbom-history.json
```

安全事件使用 `source=security_context`，SBOM 日志使用 `source=security_context_sbom`。本地控制文件是主机信任边界；项目不开放 HTTP 管理端口。运维与 CLI 用法见[运行运维文档](docs/operations.md)。

## Java 模块

| 模块 | 责任 |
| --- | --- |
| `security-core` | 请求状态、对象身份、来源、传播、规则和证据模型 |
| `security-otel-extension` | OTel extension、Byte Buddy/ASM 插桩、框架生命周期和最终 JAR |
| `security-sbom` | 制品发现、组件识别、运行时观察与 CycloneDX 快照 |
| `security-exporter` | OTel Logs、JSONL、有界队列、轮转和投递诊断 |

## 仓库目录

```text
SecurityContext/
├── java/       # Java Gradle 工程、模块、样例、测试与发行模板
├── nodejs/     # 独立 npm 包
├── python/     # 独立 Python distribution
├── deploy/     # 三种实现共用的 Collector 配置
├── docs/       # 跨语言契约与项目文档
├── scripts/    # 跨语言发行和公共 CLI
└── tests/      # 跨语言 fixture 与 SBOM Schema 契约
```

语言专属的源码、脚本、测试和样例均放在对应语言目录；根目录只保留跨语言资产和统一入口。

## 安全与隐私边界

默认不输出请求原文、完整 SQL、命令文本、URL 原文或命令参数值。请求体不会被扩展主动提前读取。WebFlux、跨服务污点传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、在线 CVE 查询和动态 attach 不在当前原型范围内。

发现安全问题时，请遵循[安全策略](SECURITY.md)私密报告。参与开发前请阅读[贡献指南](CONTRIBUTING.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可证。

## 文档索引

- [架构与范围](docs/architecture.md)
- [配置参考](docs/configuration.md)
- [运行运维与 CLI](docs/operations.md)
- [证据与 SBOM 语义](docs/evidence-and-sbom.md)
- [Java 0.2.1 历史需求追踪](docs/requirements-traceability.md)
- [资源开销记录](docs/resource-overhead.md)
- [Collector 部署示例](deploy/README.md)
- [Java 演示应用与样例](java/samples/README.md)
