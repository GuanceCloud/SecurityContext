# Collector 部署示例

本目录包含两个本地 Collector 示例。它们只负责接收扩展通过 OTel 输出的 logs/traces；扩展本身的 `health.json`、`findings.json`、`runs.json` 和 SBOM 文件仍写在应用 output 目录。

## 调试 fixture

调试 fixture 使用 `debug` exporter，不落盘，适合本地验证：

```bash
docker --context orbstack compose -f deploy/docker-compose.collector.yml up -d
curl --fail http://127.0.0.1:13133/
docker --context orbstack compose -f deploy/docker-compose.collector.yml logs -f collector
```

停止：

```bash
docker --context orbstack compose -f deploy/docker-compose.collector.yml down
```

应用使用 OTLP/HTTP 时：

```text
-Dotel.exporter.otlp.endpoint=http://host.docker.internal:4318
-Dotel.exporter.otlp.protocol=http/protobuf
```

调试配置是 storage-free；Collector 日志与扩展的本地 evidence JSONL 相互独立。

## 持久化队列示例

`docker-compose.persistent.yml` 使用命名卷 `security-collector-data` 保存 Collector 的 `file_storage`，将 logs 和 traces 转发到后端 OTLP/HTTP：

```bash
export SECURITY_BACKEND_OTLP_ENDPOINT=https://collector-backend.example/v1/otlp
export SECURITY_BACKEND_AUTHORIZATION=
docker --context orbstack compose -f deploy/docker-compose.persistent.yml up -d
docker --context orbstack compose -f deploy/docker-compose.persistent.yml logs -f collector
```

停止服务但保留命名卷：

```bash
docker --context orbstack compose -f deploy/docker-compose.persistent.yml down
```

配置要点：

- `SECURITY_BACKEND_OTLP_ENDPOINT` 必须显式提供；`SECURITY_BACKEND_AUTHORIZATION` 可为空；
- `file_storage/security` 挂载到 `/var/lib/otelcol/security`，每个 pipeline 的发送队列设置为 10000 个导出请求/批次；`queue_size` 不是 10000 条日志；
- `retry_on_failure.max_elapsed_time=0s` 表示持续重试，队列容量仍受配置的 10000 个导出请求/批次限制；
- 不使用 batch processor，避免响应之后增加额外的内存 batch 窗口；
- 后端地址和认证信息由环境变量注入，compose 文件不保存凭据。

这是 Collector 侧的投递示例，不是端到端 ACK 证明。扩展 health 的 `backend_acknowledgement` 仍为 `unknown`；请结合后端自身接收指标、Collector 日志和本地 run 的 `delivery_loss`/队列计数判断投递完整性。

run06 仅验证了受控本地接收端上的 `/v1/logs`：离线请求返回 503，Collector 优雅停止并以相同 WAL 重启后该 logs 请求返回 200。logs/traces pipeline 的 WAL 文件均能创建；trace 重放、crash/SIGKILL/主机故障恢复和外部后端 ACK 未由该产物验证，详见 `build/validation/persistent-collector/run-06/summary.json`。
