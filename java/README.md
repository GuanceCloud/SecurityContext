# SecurityContext Java

本目录是独立的 Gradle 多模块工程，构建版本为 0.3.4，产物保持 Java 8 字节码，目标运行时为 Java 8/11/17/21。

## 目录

```text
java/
├── security-core/            # 数据流状态、传播和证据模型
├── security-exporter/        # OTel Logs、本地账本与投递诊断
├── security-sbom/            # 运行时组件发现与 CycloneDX SBOM
├── security-otel-extension/  # Java Agent extension 和最终 JAR
├── samples/                  # Spring Boot 2/3 验证应用
├── scripts/                  # Java 构建、注入与验证脚本
├── tests/                    # Java 集成验收辅助脚本
└── release/                  # Java 发行包模板
```

跨语言 schema fixture 和 CycloneDX 官方 Schema 工具仍位于仓库根目录的 `tests/`。

## 构建与测试

```bash
cd java
./gradlew test
./gradlew :security-otel-extension:shadowJar
```

最终扩展位于 `security-otel-extension/build/libs/securitycontext.jar`。容器化构建和完整注入验证入口位于 `scripts/`；其原始结果默认写入本目录的 `build/validation/`。

架构、配置与运维文档位于仓库根目录的 [`docs/`](../docs/)。
