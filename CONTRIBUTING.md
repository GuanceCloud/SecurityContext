# 贡献指南

感谢参与 SecurityContext。仓库同时维护 Java、Node.js 和 Python 三套运行时实现；修改公共事件结构或安全语义时，需要同步检查三种实现。

## 开发环境

- JDK 21（构建产物仍使用 Java 8 字节码）
- Node.js 22.22.3 或 24.11.1
- CPython 3.11–3.14

仓库按语言划分为 `java/`、`nodejs/` 和 `python/`；根目录的 `deploy/`、`docs/`、`scripts/` 与 `tests/` 只存放跨语言资产。新增文件时应优先放入所属语言目录，避免重新把语言专属代码堆到仓库根目录。

安装 Node.js 和 Python 的开发依赖：

```bash
cd nodejs && npm ci && cd ..
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e "./python[test]"
```

## 验证

在仓库根目录运行全部单元与契约测试：

```bash
make test
```

也可以按语言单独运行 `make test-java`、`make test-node` 或 `make test-python`。Python 的 CycloneDX 契约测试会使用 `make schemas` 下载固定版本并校验 SHA-256 的官方 Schema。

完整的容器、框架和产品矩阵成本较高，入口及适用范围见各语言的验证文档。提交变更时请说明实际运行过的测试，不要把未运行的矩阵写成“已验证”。

## 变更原则

- 保持安全采集有界，不阻塞或改变业务函数的返回值与异常语义。
- 不在证据中新增请求原文、完整 SQL、命令、URL 或其他敏感值。
- 公共 schema、source/sink 名称或指纹算法发生变化时，同步更新共享 fixture、文档和三种语言的契约测试。
- 不提交 `build/`、`dist/`、`security-output/`、虚拟环境、依赖目录或本地验证产物。
- 依赖升级应提交对应锁文件，并说明兼容性和安全影响。

提交前请保持工作区可复现，并使用清晰、单一目的的提交说明。

除非明确另有说明，向本项目提交的贡献按项目的 [Apache License 2.0](LICENSE) 许可证提供。
