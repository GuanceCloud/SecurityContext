# 跨语言脚本

本目录只存放三种实现共用的仓库工具：

- `securityctl.py`：读取和控制统一的本地运行状态；
- `package_dist.py`：组装经过验证的多语言发行包；
- `validate_persistent_collector.py`：验证共用 Collector 的持久队列。

语言专属工具分别位于 `java/scripts/`、`nodejs/scripts/` 和 `python/scripts/`。新增脚本时请按实际所有权归档，不要把语言专属验证脚本放回本目录。
