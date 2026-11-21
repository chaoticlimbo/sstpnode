# gate — SSTP 节点流水线

从 VPN Gate 节点池收集 SSTP 节点，送外部检测站逐个检测，把通过的节点整理成订阅文件。
整个流水线只有一个脚本 `pipeline.py`，由 GitHub Actions 手动触发运行，产物自动提交回仓库。

## 三步流程

1. **收集**：拉取节点池 [GeorgeXie2333/vpngate-list-mirror](https://github.com/GeorgeXie2333/vpngate-list-mirror) 的 `pool/servers.json`，取带 TCP 探测端口的节点，转成 `sstp://vpn:vpn@主机:端口`，去重后写 `node-collect.txt`。不排除任何国家。
2. **检测**：把 `node-collect.txt` 里的节点逐个请求 `https://check.socks5.lzjbaby.com/check?sstp=...` 检测，每个节点的完整检测结果（原始 JSON，一行一条、顺序与 `node-collect.txt` 一致）写 `node-tests.txt`。
3. **成品**：检测通过（`success` 为真）的节点写 `node.txt`，纯 `sstp://` 一行一个，不限数量，按检测延迟 `responseTime` 从低到高排序。

## 三个文件

| 文件 | 说明 |
| --- | --- |
| `node-collect.txt` | 每次运行的产物：第 1 步从节点池收集到的全部 TCP 节点（去重、按池子 ping 排序），第 2 步检测的就是这份名单。 |
| `node-tests.txt` | 每次运行的产物：第 2 步的完整检测结果，一行一条 JSON，含成功与失败。 |
| `node.txt` | 每次运行的产物：第 3 步的成品，通过检测的节点，按延迟升序。 |

## 如何运行

- **GitHub Actions**：仓库 Actions 页 → `SSTP Node Pipeline` → Run workflow。可填参数：最多检测多少个节点（0 = 全部）、并发数、单节点超时。跑完后三个产物文件会自动提交回仓库。
- **本地**：`pip install -r requirements.txt` 后执行 `python pipeline.py`（需能访问节点池与检测站）。

## 主要环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `POOL_URL` | 节点池 `pool/servers.json` 的 raw 地址 | 节点池来源 |
| `CHECK_BASE` | `https://check.socks5.lzjbaby.com` | 检测站地址 |
| `COLLECT_FILE` / `TESTS_FILE` / `NODE_FILE` | 仓库根同名文件 | 三个产物路径 |
| `CHECK_CONCURRENCY` | `20` | 检测并发数 |
| `CHECK_TIMEOUT` | `30` | 单节点检测超时（秒） |
| `CHECK_DEADLINE` | `3000` | 整体检测截止（秒），超时的节点在结果里标记为未检测 |
| `MAX_TEST_NODES` | `0`（全部） | 只测待测名单的前 N 个（调试用） |
| `HTTP_TIMEOUT` | `60` | 拉节点池的超时（秒） |

## 开发

- 代码检查：`ruff check .`
- 测试：`pytest`（含一个本地假服务器的端到端集成测试）
