# SecurityContext

Node.js 独立 npm 包见 [Node.js 0.2.5](nodejs/README.md)：`securitycontext`，通过 `--import` 预加载接入，使用 schema v2、CycloneDX 和现有 CLI。安装方式、兼容边界与实际验收结果在包目录内独立维护。

Python 独立发行包见 [Python 0.2.5](python/README.md)：`securitycontext`，支持通过 OTel 自动加载接入 Python Web 应用。它与 Java 共用 schema v2、Collector 和 `scripts/securityctl.py`，版本、制品与验收记录独立管理。以下内容仍描述 Java 版本。

SecurityContext 是一个独立的 OpenTelemetry Java Agent extension 原型。应用不需要修改业务源码，只需在 OTel Java Agent 上追加扩展 JAR，即可采集两类运行时信息：

- HTTP 输入到 SQL、命令执行、HTTP 外连和文件访问的安全数据流证据；
- 应用及其依赖的 CycloneDX 1.7 SBOM，并把安全证据关联到组件引用。

当前完整发行包为 [20260911](dist/securitycontext-releases-20260911/README.zh-CN.md)，包含 Java `0.3.4` 和 Node.js/Python `0.2.5`。本包新增 SBOM 日志 source 分流，并包含四轮 CPU/内存优化及 Promise、数值绑定、别名分析三项已确认的 P1 修复；安装新版本并重启应用后生效。历史发行包保持原样。

SBOM 日志使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP 属性和 JSON body 一致，截断后也保留原 source。本地 CycloneDX 和历史文件保持原有结构与 source，详见[日志结构文档](docs/security-context-log-schema.md)。

本版仍是原型，依赖 OTel Java Agent 2.31.1、extension API 2.31.1-alpha 与 OTel SDK 1.65.0，扩展保持 Java 8 字节码；benchmark 或单次 smoke 不代表生产容量、性能或 SLA。完整的 CLI、配置、Collector、隐私和支持边界见发行包指南。

Git 仓库包含源码、测试、构建脚本和发行模板；二进制发行文件保存在本地 `dist/`，不纳入 Git，尚未向 Maven、npm 或 PyPI 发布。本文中的 `dist/` 链接指向本地发行文件，在 GitLab 源码页面中不可访问。既有历史归档保持原样，不能替代当前发行包的验证记录。

2026-09-10 的四轮 CPU/内存优化已进入本次发行包，包含配置热路径、SBOM 缓存保留与发布、Java 扫描去重及哈希编码；历史测量收益和边界见[资源开销记录](docs/resource-overhead.md)。

针对远端性能报告的第四轮优化已进入源码：Python SBOM 本轮路径匹配复用、Python/Node 重复证据的采样后复制、Python 无污点调用快速路径与标准文件读取模型、Java SBOM 组件身份复用。第四轮已纳入 `20260910-r2` dist；持续 100 QPS 的历史对照中，完整 Python 服务 CPU 时间下降 4.2%，RSS 峰值增加约 1.09 MiB，未证明整体内存下降。验证及性能对照见同一资源开销记录。

## 二进制发行包

最新完整压缩包为 [securitycontext-dist-20260911.tar.gz](dist/securitycontext-dist-20260911.tar.gz)，附 [SHA-256](dist/securitycontext-dist-20260911.tar.gz.sha256) 和[独立解包验证记录](dist/securitycontext-dist-20260911-validation.json)。解开后按 `java/`、`nodejs/`、`python/` 存放全部安装制品、中英文说明书、CLI、Collector 配置、样例及验证记录；目录入口见[中文说明](dist/securitycontext-releases-20260911/README.zh-CN.md) / [English](dist/securitycontext-releases-20260911/README.en.md)。三种语言均重新构建并在 OrbStack 验证：Java 65 项通过、2 项权限前提跳过，四 JVM 及 110 项路由证据/边界检查通过；Node 22/24 各 58 项、安装包框架组合共 12 项通过；Python 3.11–3.14 各 80 项通过，并验证 wheel 重建、安装及真实 Loader。Collector 接收、完整数据库/进程矩阵和长期压力等未验收部分见[验证范围](dist/securitycontext-releases-20260911/release-validation.json)。`release/` 是 Java `securitycontext.jar` 0.3.4 的发行模板。

打包脚本核对扩展 JAR 与包内文件的 SHA-256，并使用本工作区的样例和依赖缓存：

```bash
SOURCE_DATE_EPOCH=1788998400 python3 scripts/package_dist.py --output build/validation/dist-20260910-r2/java-package
```

重新生成本版本的发行文件时追加 `--replace`。发行目录中的 `SHA256SUMS` 校验归档和独立 JAR，归档内部另有完整文件清单及校验和。

## 构建

在仓库根目录使用 OrbStack 构建扩展和两个演示应用：

```bash
./scripts/orbstack_build.sh :security-otel-extension:shadowJar :samples:boot2:bootJar :samples:boot3:bootJar
```

扩展产物为：

```text
security-otel-extension/build/libs/securitycontext.jar
```

扩展固定编译为 Java 8 字节码，运行目标为 Java 8/11/17/21；演示应用分别覆盖 Spring Boot 2 的 `javax` Servlet 和 Spring Boot 3 的 `jakarta` Servlet。

构建依赖固定为 OTel Java Agent/extension API 2.31.1（extension API 为 `2.31.1-alpha`）和 OTel SDK 1.65.0。

## 注入运行

```bash
java \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=my-application \
  -Dsecurity.code.repository=https://example.invalid/repository \
  -Dsecurity.code.commit=git-commit \
  -Dsecurity.code.build-id=build-identifier \
  -jar application.jar
```

`security.enabled` 与 `security.sbom.enabled` 独立生效。默认安全输出目录为 `./security-output/<process-instance-id>/`；SBOM 默认写入该目录下的 `application.cdx.json`。需要本地安全证据 JSONL 时再增加：

```text
-Dsecurity.evidence.file=./security-output/<process-instance-id>/evidence.jsonl
```

`security.code.repository`、`security.code.commit` 和 `security.code.build-id` 只有显式配置才会进入代码身份；验证 CLI 要求两套可比较的 run 都具备这三个字段，不会猜测仓库或提交。

## 运行时产物

每个进程的本地输出目录默认包含：

```text
security-output/<instance-id>/
├── health.json              # 最近的健康与投递快照
├── findings.json            # 按 finding_id 聚合的代表样本和计数
├── runs.json                # 本地验证 run 及 source/sink 计数
├── control.json             # pause、run、exception 的本地控制文件
├── application.cdx.json     # CycloneDX 1.7 当前 SBOM
└── sbom-history.json        # SBOM 组件变化历史
```

`control.json` 是本机文件信任边界，扩展不开放 HTTP 管理端口。状态是有界的 process-local 观察；进程重启后的跨 instance 统计需要由后端按 `application_id` 与 `finding_id` 聚合，文件本身不是历史数据库。

本地查询、暂停、run 生命周期、比较和验证命令见[运行运维与 CLI](docs/operations.md)。完整配置见[配置参考](docs/configuration.md)。

## 模块

| 模块 | 责任 |
| --- | --- |
| `security-core` | 请求状态、对象身份、来源、传播、规则和 SecurityEvidence 模型 |
| `security-otel-extension` | OTel extension、Byte Buddy/ASM 插桩、框架生命周期和最终 JAR |
| `security-sbom` | 制品发现、组件识别、运行时观察、CycloneDX 快照、临时文件和原子替换 |
| `security-exporter` | OTel Logs、安全证据 JSONL、有界队列、轮转和投递诊断；不直接写完整 SBOM 文件 |

安全和 SBOM 使用独立后台队列与线程。安全通道默认每秒最多 100 个事件/524288 字节，SBOM 通道默认每秒最多 200 个事件/262144 字节；OTel API 调用不等于 Collector 或后端 ACK。

## 兼容能力与边界

首版覆盖 Servlet 请求生命周期、参数/Header、Spring MVC 表单、文本和有限深度 JSON、对象身份与字符范围传播，以及 JDBC、命令、HTTP 客户端和文件路径 Sink。请求体不会被扩展提前读取：Reader/Jackson 在应用或 MVC 完成消费/绑定后登记。URL/URI accessor 按 scheme、authority、host、path、query 区段裁剪来源；URL 受控不表示响应值受控。证据中的 `invocation_attempt` 表示观察到调用路径，不表示攻击成功。

默认不输出请求原文、完整 SQL、命令文本、URL 原文或命令参数值。无可读 class 资源的动态生成类会跳过调用点预扫描；SBOM 通过 CodeSource 观察到制品不代表该类已经插桩。请求状态依赖 OTel HTTP Server instrumenter，整体 OTel SDK 或 HTTP Server instrumentation 关闭时不在保证范围内。

WebFlux、跨服务污点传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化漏洞、在线 CVE 查询和动态 attach 不在本原型范围内。

## 文档

- [架构与范围](docs/architecture.md)
- [配置参考](docs/configuration.md)
- [运行运维与 CLI](docs/operations.md)
- [证据与 SBOM 语义](docs/evidence-and-sbom.md)
- [Node.js、Python 与 Java 日志输出结构](docs/security-context-log-schema.md)
- [需求追踪](docs/requirements-traceability.md)
- [验证矩阵与 0.2.1 验收协议](docs/verification.md)
- [Collector 部署示例](deploy/README.md)
- [演示应用与样例入口](samples/README.md)
