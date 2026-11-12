# systemd 沙箱策略核查 + 配置目录完整性监测服务

面向 Linux 服务维护人员的**纯离线**工具，单进程提供两类 API：

1. **沙箱策略核查**（原有）：给定 systemd unit 的沙箱策略 JSON 与按时间排列的进程审计事件，
   逐步回放并判断守护进程的真实操作会不会被沙箱阻断，输出首个失败原因、完整判定轨迹
   和每一步命中的策略项，直接指导 unit 修改。
2. **配置目录完整性监测**（新增）：以可信清单（目录 + 文件名 -> SHA-256）为基准，
   用真实 inotify 监视配置目录，发现篡改即报异常并列出差异，
   为维护人员**是否暂停部署**提供依据。

判定引擎与监测引擎（`app/engine.py`、`app/integrity.py`、`app/linux_inotify.py`）
只依赖 Python 标准库；FastAPI 仅用于提供 HTTP 与 `/docs`。服务运行期不发起任何外部网络请求。

## 目录完整性监测

### 工作模型

- **可信启动配置**：启动时加载清单 `manifest.json`（只读挂载），固定
  `directory`（被监视目录）与 `files`（单层文件名 -> SHA-256）。
- **检查范围**：只检查目录**第一层**；最多 **100** 个普通文件，每个不超过 **1MiB**；
  **不跟随软链接**；目录本身不被替换（被替换按监视失效处理，见下）。
- **先监视后复核**：先建立真实 inotify 监视，再做全量复核；
  **文件集合与摘要全部匹配**才报 `完整`。
- **事件驱动复核**：收到原地写入、替换（移入/移出）或增删通知即标为 `待复核`，
  延迟 `INTEGRITY_RECHECK_DELAY` 秒后做全量复核；**复核期间再次变化则作废本轮结果
  并重查**（世代号保证迟到结果不得覆盖新状态）。
- **失效兜底**：inotify 队列溢出、被监视目录被删除/移动导致监视失效时报 `未知`，
  **重建监视并完成全量复核后才恢复结论**；服务启动与重启都会重新检查。

### 状态机

| 状态 | 含义 | 进入条件 |
| --- | --- | --- |
| `intact` 完整 | 文件集合与 SHA-256 摘要全部匹配 | 全量复核通过 |
| `anomaly` 异常 | 存在差异（响应中列出全部 `diffs`） | 复核发现：缺失 `missing`、新增 `added`、内容改变 `modified`、非普通文件 `not_regular`、超 1MiB `too_large`、文件数超限 `too_many_files`、目录项过多 `too_many_entries`、无法读取 `unreadable` |
| `pending` 待复核 | 收到变更通知，复核尚未完成 | inotify 变更事件 / 手动触发复核 |
| `unknown` 未知 | 监视失效，无法给出结论 | 事件队列溢出、目录被删除/移动/卸载、清单缺失、复核失败；重建监视并完成全量复核后恢复 |

### API（/docs 可直接调用）

```bash
# 查询当前完整性状态（完整/异常/待复核/未知 + 原因 + 差异明细）
curl -s http://localhost:8080/api/v1/integrity/status | jq .

# 不等变更通知，立即触发一次全量复核
curl -s -X POST http://localhost:8080/api/v1/integrity/recheck | jq .
```

异常时的响应示例：

```json
{
  "status": "anomaly",
  "status_text": "异常",
  "reason": "检测到 1 处差异，文件集合或摘要不匹配",
  "directory": "/etc/integrity-demo",
  "watch_active": true,
  "generation": 3,
  "last_change_at": "2026-11-12T08:30:00.123Z",
  "last_recheck_at": "2026-11-12T08:30:01.234Z",
  "limits": {"max_files": 100, "max_file_size_bytes": 1048576, "single_level": true, "follow_symlinks": false},
  "diffs": [
    {"type": "modified", "file": "app.conf",
     "detail": "SHA-256 不匹配：清单 efab1b68…，实际 9f2c…"}
  ]
}
```

### 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `INTEGRITY_MANIFEST_PATH` | `/etc/integrity/manifest.json` | 可信清单路径（启动时加载一次） |
| `INTEGRITY_RECHECK_DELAY` | `0.5` | 收到变更通知后延迟复核的秒数（演示可调大以观察`待复核`） |
| `INTEGRITY_REBUILD_INTERVAL` | `2.0` | 监视失效后的重建重试间隔（秒） |

> 单进程语义：监测器与 HTTP 服务同进程运行，请勿用 `--workers` 多开或 `--reload`
> 启动 uvicorn，否则每个进程会有各自独立的监视状态。

## 篡改演示（本地修改与替换，复核延迟可控）

```bash
# 1. 启动（复核延迟默认 1.0 秒，可用环境变量调大便于观察“待复核”）
INTEGRITY_RECHECK_DELAY=1.0 docker compose up --build -d

# 2. 在 /docs 或命令行确认初始状态为“完整”
curl -s http://localhost:8080/api/v1/integrity/status | jq .status

# 3. 跑演示：原地写入 -> 待复核 -> 异常；替换 -> 异常；新增 -> 异常；恢复 -> 完整
scripts/demo_tamper.sh
```

演示脚本直接修改宿主机 `deploy/config/`（bind 挂载进容器，inotify 事件实时传入），
依次演示**原地写入**、**原子替换**（写临时文件 + `mv`）、**新增清单外文件**三种篡改，
最后自动恢复原配置；脚本异常退出也会通过 `trap` 恢复。

配置合法变更的正规流程：修改 `deploy/config/` 后重新生成清单并重启服务——

```bash
python3 -I scripts/gen_manifest.py --root deploy/config \
  --directory /etc/integrity-demo --output deploy/manifest.json
docker compose up -d --force-recreate     # 重启即重新检查
```

## 支持的 systemd 策略项（沙箱核查）

| 策略 | 取值 | 判定语义 |
| --- | --- | --- |
| `ProtectSystem` | `off` / `full` / `strict`（`yes` 等同 `full`） | `full`：`/usr` `/boot` `/efi` `/etc` 只读；`strict`：除 `/proc` `/sys` `/dev` 外整文件系统只读；只限制写 |
| `ProtectHome` | `off` / `yes` / `read-only` | `yes`：`/home` `/root` `/run/user` 完全不可见（所有操作拒绝）；`read-only`：仅拒绝写 |
| `ReadWritePaths` | 绝对路径数组 | 可写白名单，以绑定挂载覆盖上面两项的只读限制 |
| `InaccessiblePaths` | 绝对路径数组 | 命名空间内挂载为空文件/目录，**拒绝优先级最高**，即使同路径在 `ReadWritePaths` 中也拒绝 |
| `PrivateTmp` | `true`/`false` | `/tmp`、`/var/tmp` 重映射到私有 tmpfs，可写且与主机隔离，轨迹中标注沙箱内路径 |

### 判定顺序（每一步轨迹都可对照）

1. **路径规范化**：相对路径按进程当前 cwd 拼接，词法折叠 `.`/`..`（不访问真实文件系统）。
2. **进程继承**：`fork` 事件让子进程继承父进程 cwd；`chdir` 需要目录可搜索（execute），成功后更新该 PID 的 cwd。
3. **InaccessiblePaths 优先**：命中即拒绝，且优先于一切可写放行。
4. **PrivateTmp**：命中 `/tmp`、`/var/tmp` 时标注私有命名空间映射并放行。
5. **ProtectHome**：`yes` 全拒绝；`read-only` 仅写拒绝。
6. **ProtectSystem**：对其余目录的写操作生效（`full` 限定前缀，`strict` 覆盖全局）。
7. **ReadWritePaths 放行**：可覆盖第 5、6 步的只读阻断，不能覆盖第 3 步。
8. 其余目录默认可写；`read`/`execute` 不受只读策略限制。

遇到首个拒绝事件即停止评估，`events_evaluated` 标明实际判定到第几个事件。

## 目录结构

```
app/
  engine.py         # 纯标准库沙箱判定引擎（路径规范化、cwd 继承、策略匹配）
  integrity.py      # 完整性监测引擎：清单、单层全量复核、inotify 监视状态机
  linux_inotify.py  # ctypes 直调 libc 的真实 inotify 封装（仅标准库）
  schemas.py        # pydantic v2 请求/响应模型（兼容 systemd 原生字段名与 snake_case）
  main.py           # FastAPI 应用：/docs、/health、/api/v1/evaluate、/api/v1/integrity/*
  cli.py            # 沙箱核查离线命令行入口（无需 FastAPI）
deploy/
  config/           # 演示用被监视配置目录（compose 挂载到 /etc/integrity-demo）
  manifest.json     # 可信清单（compose 只读挂载到 /etc/integrity/manifest.json）
scripts/
  gen_manifest.py   # 配置合法变更后重新生成清单
  demo_tamper.sh    # 篡改演示：原地写入/替换/新增 -> 异常，恢复 -> 完整
tests/
  test_engine.py    # 沙箱引擎测试，python3 -I 直接运行
  test_integrity.py # 完整性监测测试（真实 inotify），python3 -I 直接运行
  test_api_stub.py  # 无 FastAPI 环境下的 API 接线测试（内置最小 stub）
examples/request.json
Dockerfile
docker-compose.yml
requirements.txt
```

## 方式一：Docker Compose（推荐，含 /docs）

```bash
docker compose up --build -d
# 交互式文档（可直接在页面上发请求，含完整性监测入口）
xdg-open http://localhost:8080/docs      # Linux 桌面
# 健康检查（返回体含 integrity 当前状态）
curl -s http://localhost:8080/health
# 完整性状态
curl -s http://localhost:8080/api/v1/integrity/status | jq .
# 沙箱策略核查
curl -s -X POST http://localhost:8080/api/v1/evaluate \
  -H 'Content-Type: application/json' \
  --data @examples/request.json | jq .
```

容器以非 root 运行，带 `read_only` 根文件系统、`no-new-privileges`、drop 全部 capabilities。
compose 挂载两个路径：可信清单（只读）与被监视配置目录（演示篡改对象）。
端口冲突时修改 `docker-compose.yml` 左侧端口即可；SELinux 主机挂载被拒时在
volumes 行尾追加 `:z`。

## 方式二：本地 Python 运行

```bash
pip install -r requirements.txt
# 本地运行时把清单与被监视目录指到本机路径
python3 -I scripts/gen_manifest.py --root deploy/config \
  --directory "$PWD/deploy/config" --output /tmp/manifest.json
INTEGRITY_MANIFEST_PATH=/tmp/manifest.json \
  uvicorn app.main:app --host 127.0.0.1 --port 8080
# 打开 http://127.0.0.1:8080/docs
```

## 方式三：完全离线 CLI（沙箱核查，不需要安装任何依赖）

引擎与 CLI 仅用标准库，把整个目录拷到无网络的维护机即可：

```bash
# 被阻断时退出码 1，输入非法退出码 2，全通过退出码 0
python3 -I app/cli.py examples/request.json --fail-on-deny
# 也支持标准输入
cat examples/request.json | python3 -I app/cli.py -
```

## 请求格式（沙箱核查）

策略字段同时接受 systemd 原生写法（`ProtectSystem`）和 snake_case（`protect_system`）。
策略中的路径必须是绝对路径；相对路径只允许出现在审计事件中（相对当前 cwd 解析）。

```json
{
  "policy": {
    "ProtectSystem": "full",
    "ProtectHome": "read-only",
    "ReadWritePaths": ["/etc/app", "/var/lib/app"],
    "InaccessiblePaths": ["/etc/secret"],
    "PrivateTmp": true,
    "UnitName": "app.service"
  },
  "events": [
    {"type": "chdir",  "pid": 100, "path": "/var/lib/app"},
    {"type": "fork",   "pid": 100, "child_pid": 101, "ppid": 100},
    {"type": "access", "pid": 101, "operation": "write", "path": "state.db"},
    {"type": "access", "pid": 100, "operation": "write", "path": "/tmp/cache/idx"},
    {"type": "access", "pid": 100, "operation": "write", "path": "/etc/app/config.ini"},
    {"type": "chdir",  "pid": 100, "path": "/usr/local"},
    {"type": "access", "pid": 100, "operation": "write", "path": "../lib/evil.so"}
  ]
}
```

事件说明：

- `fork`：必须带 `child_pid`，子进程继承父进程当前 cwd，不做文件访问判定。
- `chdir`：带 `path`（绝对或相对），按目录搜索权限判定，成功后更新该 PID 的 cwd。
- `access`：必须带 `operation`（`read`/`write`/`execute`）与 `path`。

## 响应解读（沙箱核查，节选）

```json
{
  "allowed": false,
  "failure_event_seq": 7,
  "failure_reason": "写操作被 ProtectSystem=full 阻断：/usr/lib/evil.so 位于只读区域，且未被 ReadWritePaths 列为可写",
  "events_total": 7,
  "events_evaluated": 7,
  "policy_effective": { "...": "归一化后实际生效的策略回显" },
  "trace": [
    {
      "seq": 4,
      "event_type": "access",
      "raw_path": "/tmp/cache/idx",
      "cwd_before": "/var/lib/app",
      "normalized_path": "/tmp/cache/idx",
      "sandbox_path": "/tmp/systemd-private-app.service/tmp/cache/idx",
      "decision": "allow",
      "reason": "write /tmp/cache/idx 落入 PrivateTmp 私有命名空间……",
      "matched_policies": ["PrivateTmp=yes"],
      "notes": ["PrivateTmp=yes：宿主机 /tmp 被私有 tmpfs 遮盖……"]
    }
  ]
}
```

维护动作建议直接来自轨迹：

- 出现 `ProtectSystem`/`ProtectHome` 只读阻断 → 把目标路径加入 unit 的 `ReadWritePaths=`。
- 出现 `InaccessiblePaths` 拒绝 → 从该指令移除对应前缀（`ReadWritePaths` 无法覆盖它）。
- 出现 `ProtectHome=yes` 不可见 → 改为 `ProtectHome=read-only` 或调整程序不再访问 home。
- `sandbox_path` 非空 → 程序看到的是私有 tmp，不能用它与主机或其它服务交换文件。

## 测试

```bash
python3 -I tests/test_engine.py     # 11 组沙箱引擎语义测试，无需第三方依赖
python3 -I tests/test_integrity.py  # 15 组完整性监测测试（清单/扫描/真实 inotify 状态机）
python3 -I tests/test_api_stub.py   # 无 FastAPI 环境下的端点/别名/422 接线测试
```

## 建模边界

沙箱核查（与真实 systemd 的差异）：

- 路径为**词法规范化**，不解析符号链接；systemd 的路径单元也是基于词法前缀匹配，行为基本一致。
- 不建模 UID/GID、DAC 权限、`BindPaths`、`TemporaryFileSystem` 等本工具输入之外的指令。
- `ProtectSystem=strict` 下 `/proc`、`/sys`、`/dev` 视为虚拟文件系统例外；`PrivateTmp` 优先于 strict 判定。
- 不建模挂载传播顺序中 `InaccessiblePaths` 与 `ReadWritePaths` 的复杂叠加，统一按"拒绝优先"处理（这也是 systemd 文档对冲突指令的保守建议）。

完整性监测：

- 只监视清单固定的**单个目录的第一层**；子目录本身会作为"非普通文件"报异常，其内容不在检查范围。
- inotify 事件与全量复核之间存在固有窗口：变更先标`待复核`，结论以复核完成的快照为准；
  复核期间再次变化会作废本轮结果并重查，因此持续写入期间状态保持`待复核`，静默后才给出结论。
- 目录本身被删除/移动/替换属于"监视失效"，报`未知`并在重建监视 + 全量复核后恢复结论，
  不会把"目录暂时不存在"误报为`完整`。
- 文件内容以复核时读取到的字节计算 SHA-256；`O_NOFOLLOW` 保证软链接不会被跟随。
