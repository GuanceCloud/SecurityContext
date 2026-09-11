# SecurityContext 多语言发行包（2026-09-08）

发行 bundle 根目录为 `securitycontext-releases-20260908/`，下面的链接均相对于该根目录并指向固定制品名。

## 制品

| 语言 | 版本 | 安装包与包内文档 |
| --- | --- | --- |
| Java | `0.3.0` | [`securitycontext-0.3.0/`](java/securitycontext-0.3.0/)、[tar.gz](java/securitycontext-0.3.0.tar.gz)、[zip](java/securitycontext-0.3.0.zip)、[独立 JAR](java/securitycontext-0.3.0.jar)、[包内 JAR](java/securitycontext-0.3.0/lib/securitycontext.jar)、[中文指南](java/securitycontext-0.3.0/docs/guide.zh-CN.md)、[English guide](java/securitycontext-0.3.0/docs/guide.en.md) |
| Node.js | `0.2.0` | [tarball](nodejs/securitycontext-0.2.0.tgz)、[中文指南](nodejs/docs/guide.zh-CN.md)、[English guide](nodejs/docs/guide.en.md) |
| Python | `0.2.0` | [sdist](python/securitycontext-0.2.0.tar.gz)、[wheel](python/securitycontext-0.2.0-py3-none-any.whl)、[中文指南](python/docs/guide.zh-CN.md)、[English guide](python/docs/guide.en.md) |

每种语言目录中的外置发行报告记录实际验收结果：[Java](java/release-validation.json)、[Node.js](nodejs/release-validation.json)、[Python](python/release-validation.json)。版本、制品和总体范围见 [`release-manifest.json`](release-manifest.json)；根目录 [`SHA256SUMS`](SHA256SUMS) 覆盖本目录交付文件，Java 归档内部另有文件清单与校验和。校验后安装：

```bash
sha256sum -c SHA256SUMS       # Linux
shasum -a 256 -c SHA256SUMS   # macOS
```

## 本地安装与启动

Node.js 使用本地 tarball：

```bash
cd nodejs
npm install ./securitycontext-0.2.0.tgz
```

Python 使用本地 wheel 或 sdist：

```bash
cd python
python -m pip install ./securitycontext-0.2.0-py3-none-any.whl
# 或 python -m pip install ./securitycontext-0.2.0.tar.gz
```

Java 使用包内匹配的 OTel Java Agent 和 JAR；先阅读 [`java/securitycontext-0.3.0/README.zh-CN.md`](java/securitycontext-0.3.0/README.zh-CN.md)，再用包内 `bin/run-demo.sh boot2|boot3` 或对应应用的 `-javaagent` 命令启动。宿主 OTel 与 SecurityContext 都需要在处理应用请求前初始化；预加载、provider 和应用模块的具体顺序以各语言指南为准。

## 共同契约

三个包使用 `SecurityContext` scope、`source=security_context` 和 schema v2 事件：统一的六个 identity 字段、runtime、source/sink/component、trace 关联、SBOM channel 和截断/交付计数规则见各包内指南。事件 source 与 OTel `source` attribute 均为 `security_context`；security JSONL 只接收 evidence/diagnostic 白名单，SBOM 不写入该通道。health/SBOM/history 是进程级快照，不强行关联请求 trace；dataflow evidence 才记录 `trace_id`、`server_span_id`、`current_span_id` 和冻结的 `trace_flags`。

跨版本升级前阅读各包的 fingerprint2 和破坏性改名说明。旧 package/import/JAR/namespace 没有自动 shim，消费者需要手动更新；历史事件 reader 需自行兼容旧 schema。停止或卸载前先停止应用进程，并按保留策略处理 output、证据和 SBOM 文件。

## 验证边界

本次发行在 OrbStack Linux/arm64 上完成各语言的运行验收，实际范围与结果记录在各语言的 `release-validation.json` 和根目录 `release-manifest.json`。x86_64 与 Windows 路径未验证；共享环境的性能测量不是 SLA，Node.js 默认输出预算下仍观察到丢弃计数。原始运行日志保留在源码工作区，报告中的 `build/validation/` 路径是工作区证据索引，未全部随发行包复制。能力边界、依赖目标、最小示例、CLI/run 流程、故障排查和停用步骤见各语言指南。本次仅生成本地发行包，未提交 Git 或发布到远程仓库。
