# SecurityContext 2026-09-11 发行说明

本次 `20260911` 发行新增：SBOM 快照 `app-dependencies-loaded` 及 `security.sbom.*` 诊断日志使用 `source=security_context_sbom`；其他安全事件继续使用 `source=security_context`。OTLP 属性与 JSON body 一致，summary/minimal 截断保留原 source。本地 CycloneDX 和历史文件的结构及 source 保持不变。升级并重启应用后生效。

本地完整发行包 `securitycontext-releases-20260911`：Java 0.3.4、Node.js/Python 0.2.5。基于当前工作区重新构建，纳入四轮 CPU/内存优化以及 SC-20260909-1/2/3 修复。安装新版本并重启应用后生效。

## 本次增量

- Python SBOM 在每轮刷新中复用安装根目录及模块匹配结果；下一轮重新检查部署与符号链接变化。
- Python/Node 按采样结果复制详细证据，继续维护发生次数、最新请求及验证任务统计。
- Python 无污点调用省去传播模型分配；标准 Path.read_text/read_bytes 不再触发未知返回值降级，文件路径 sink 观察保留。
- Java SBOM 复制缓存组件时复用不可变身份，可变集合保持独立。

前后对照的 Python 完整服务在持续 100 QPS 下 CPU 时间下降约 4.2%，RSS 峰值增加约 1.09 MiB，未证明整体内存或尾延迟下降。热点收益不能外推为生产收益。详见完整包的资源开销记录。

## 已包含的优化与修复

- Java：复用请求跟踪查询键，按 CodeSource 去重扫描，在组件 SHA-256 编码中避免逐字节格式化和临时对象。
- Node.js：缓存稳定配置，索引已加载依赖的包根目录，减少输出编码副本；SBOM 发布复用组件记录，历史对比仅保留摘要。
- Python：复用不可变标记，缓存分发包名称及环境路径索引，元数据缓存只保留必要许可证字段；SBOM 历史对比仅保留摘要，快照未变化时跳过历史复制。
- 保留 Promise 共享结果去重、Node 数值绑定工作队列及预算、Python 别名工作队列及转换上限。超过预算时执行原业务代码并记录观测缺口，对应传播不再被跟踪。
- SBOM 上报保持 `app-dependencies-loaded`，依赖项仅含 `name`、`version` 和必要时的真实制品 `hash`；本地继续保留 CycloneDX 1.7 与组件历史。分片需按同一快照完整收齐后再替换清单。

CPU 和内存收益取决于依赖规模及负载，热点基准不等于整机或生产应用收益。完整包的 `docs/resource-overhead.md` 保留四轮测量及边界。没有通过减少默认观测能力来换取本次资源优化；原有预算超限降级语义保持不变。

## 安装与验证

Java 配套 OTel Java Agent 2.31.1，扩展编译为 Java 8 字节码，目标 Java 8/11/17/21；Node.js 目标 >=22.22.3 <23 或 >=24.11.1 <25；Python 目标 CPython 3.11–3.14。Node/Python 依赖需要包源或缓存；完整包不是离线依赖镜像。各语言提供中英文完整指南、CLI、Collector 配置及样例。

实际执行的检查和未验收部分以完整包根目录 `release-validation.json`、Java 安装目录 `validation.json` 及归档外独立解包验证记录为准。历史性能记录不替代本版运行验收；OTel emit 不等于 Collector/后端收到数据。长期压力、完整数据库/进程矩阵、Collector 接收及非 root Java 权限用例不在本次完成范围内。

仅生成本地发行文件，未发布到 Maven、npm、PyPI 或远程 Git；历史发行包保持不变。修复上述三项已确认问题，不表示已证明不存在其他 P0/P1 问题。
