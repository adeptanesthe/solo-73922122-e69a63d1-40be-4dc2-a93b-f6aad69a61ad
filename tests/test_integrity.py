"""目录完整性监测测试：纯标准库 + 真实 inotify（Linux）。

运行：python3 -I tests/test_integrity.py
无 inotify 的平台会自动跳过监视器集成测试，扫描与清单测试照常执行。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import linux_inotify  # noqa: E402
from app.integrity import (  # noqa: E402
    MAX_FILE_SIZE,
    MAX_FILES,
    STATUS_ANOMALY,
    STATUS_INTACT,
    STATUS_PENDING,
    STATUS_UNKNOWN,
    IntegrityMonitor,
    ManifestError,
    parse_manifest,
    scan_directory,
)

INOTIFY_OK = linux_inotify.available()


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        raise AssertionError(f"用例失败: {name} {detail}")
    print(f"  ok - {name}")


def wait_for(cond, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(interval)
    return False


def wait_status(mon: IntegrityMonitor, status: str, timeout: float = 5.0) -> bool:
    return wait_for(lambda: mon.get_status()["status"] == status, timeout)


def make_config_dir(root: str, files: dict[str, bytes]) -> dict[str, str]:
    """创建配置目录并返回 文件名->sha256 的清单映射。"""
    os.makedirs(root, exist_ok=True)
    manifest = {}
    for name, content in files.items():
        with open(os.path.join(root, name), "wb") as fh:
            fh.write(content)
        manifest[name] = hashlib.sha256(content).hexdigest()
    return manifest


def write_manifest(path: str, directory: str, files: dict[str, str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"directory": directory, "files": files}, fh)


# --------------------------------------------------------------------------- #
# 清单解析
# --------------------------------------------------------------------------- #
def test_manifest_parsing() -> None:
    print("test_manifest_parsing")
    digest = "A" * 64
    m = parse_manifest({"directory": "/etc/app/", "files": {"a.conf": digest}})
    check("目录规范化", m.directory == "/etc/app")
    check("摘要转小写", m.files["a.conf"] == "a" * 64)

    empty = parse_manifest({"directory": "/etc/app", "files": {}})
    check("允许空清单（目录必须为空）", empty.files == {})

    bad_inputs = [
        ({"directory": "etc/app", "files": {}}, "相对目录"),
        ({"directory": "/", "files": {}}, "根目录"),
        ({"directory": "/etc/app"}, "缺 files"),
        ({"directory": "/etc/app", "files": []}, "files 非对象"),
        ({"directory": "/etc/app", "files": {"a/b": digest}}, "文件名含斜杠"),
        ({"directory": "/etc/app", "files": {"..": digest}}, "文件名为 .."),
        ({"directory": "/etc/app", "files": {"": digest}}, "空文件名"),
        ({"directory": "/etc/app", "files": {"a": "xyz"}}, "摘要非法"),
        ({"directory": "/etc/app", "files": {"a": digest[:-1]}}, "摘要长度不足"),
    ]
    for payload, label in bad_inputs:
        try:
            parse_manifest(payload)
            check(f"拒绝{label}", False)
        except ManifestError:
            check(f"拒绝{label}", True)

    too_many = {"directory": "/etc/app", "files": {f"f{i:03d}": digest for i in range(MAX_FILES + 1)}}
    try:
        parse_manifest(too_many)
        check("拒绝超量清单", False)
    except ManifestError:
        check("拒绝超量清单（>100 个文件）", True)


# --------------------------------------------------------------------------- #
# 全量复核（扫描）
# --------------------------------------------------------------------------- #
def test_scan_intact() -> None:
    print("test_scan_intact")
    with tempfile.TemporaryDirectory() as tmp:
        manifest = make_config_dir(tmp, {"a.conf": b"alpha=1\n", "b.conf": b"beta=2\n"})
        result = scan_directory(tmp, manifest)
        check("全部匹配报完整", result is not None and result.status == STATUS_INTACT)
        check("完整时无差异", result is not None and result.diffs == [])


def test_scan_diffs() -> None:
    print("test_scan_diffs")
    with tempfile.TemporaryDirectory() as tmp:
        make_config_dir(tmp, {"a.conf": b"hacked\n", "c.conf": b"extra\n"})
        manifest = {
            "a.conf": hashlib.sha256(b"original\n").hexdigest(),
            "b.conf": hashlib.sha256(b"beta\n").hexdigest(),
        }
        result = scan_directory(tmp, manifest)
        check("有差异报异常", result is not None and result.status == STATUS_ANOMALY)
        kinds = {(d["type"], d["file"]) for d in result.diffs}
        check("内容改变差异", ("modified", "a.conf") in kinds, str(kinds))
        check("缺失差异", ("missing", "b.conf") in kinds, str(kinds))
        check("新增差异", ("added", "c.conf") in kinds, str(kinds))
        modified = next(d for d in result.diffs if d["type"] == "modified")
        check("modified 差异含摘要对比", manifest["a.conf"] in modified["detail"])


def test_scan_not_regular() -> None:
    print("test_scan_not_regular")
    with tempfile.TemporaryDirectory() as tmp:
        manifest = make_config_dir(tmp, {"real.conf": b"ok\n"})
        os.symlink("real.conf", os.path.join(tmp, "link.conf"))
        os.mkdir(os.path.join(tmp, "subdir"))
        os.mkfifo(os.path.join(tmp, "pipe"))
        result = scan_directory(tmp, manifest)
        check("非普通文件报异常", result is not None and result.status == STATUS_ANOMALY)
        kinds = {(d["type"], d["file"]) for d in result.diffs}
        check("软链接报非普通文件", ("not_regular", "link.conf") in kinds, str(kinds))
        check("子目录报非普通文件", ("not_regular", "subdir") in kinds, str(kinds))
        check("FIFO 报非普通文件", ("not_regular", "pipe") in kinds, str(kinds))
        check("正常文件不受牵连", result is not None
              and all(d["file"] != "real.conf" for d in result.diffs))


def test_scan_symlink_not_followed() -> None:
    print("test_scan_symlink_not_followed")
    with tempfile.TemporaryDirectory() as tmp:
        content = b"trusted content\n"
        # 清单固定 app.conf 的摘要，但目录里 app.conf 被换成指向相同内容的软链接
        make_config_dir(tmp, {"target.conf": content})
        os.symlink("target.conf", os.path.join(tmp, "app.conf"))
        manifest = {"app.conf": hashlib.sha256(content).hexdigest()}
        result = scan_directory(tmp, manifest)
        kinds = {(d["type"], d["file"]) for d in result.diffs}
        check("软链接即使内容相同也报非普通文件", ("not_regular", "app.conf") in kinds, str(kinds))
        check("不跟随软链接计算摘要", not any(
            d["type"] == "modified" and d["file"] == "app.conf" for d in result.diffs))


def test_scan_limits() -> None:
    print("test_scan_limits")
    with tempfile.TemporaryDirectory() as tmp:
        big = b"x" * (MAX_FILE_SIZE + 1)
        manifest = make_config_dir(tmp, {"big.conf": big})
        result = scan_directory(tmp, manifest)
        kinds = {(d["type"], d["file"]) for d in result.diffs}
        check("超过 1MiB 报超限", ("too_large", "big.conf") in kinds, str(kinds))

    with tempfile.TemporaryDirectory() as tmp:
        files = {f"f{i:03d}.conf": b"x\n" for i in range(MAX_FILES + 1)}
        manifest = make_config_dir(tmp, files)
        result = scan_directory(tmp, manifest)
        check("文件数超限报异常", result is not None and any(
            d["type"] == "too_many_files" for d in result.diffs))


def test_scan_missing_dir() -> None:
    print("test_scan_missing_dir")
    check("目录不存在返回 None（无法得出结论）",
          scan_directory("/nonexistent/integrity-test", {"a": "0" * 64}) is None)


# --------------------------------------------------------------------------- #
# inotify 封装
# --------------------------------------------------------------------------- #
def test_inotify_parse() -> None:
    print("test_inotify_parse")
    name = b"a.conf\0\0"  # 名称字段按 4 字节对齐填充
    buf = struct.pack("iIII", 1, linux_inotify.IN_CREATE, 0, len(name)) + name
    events = linux_inotify.parse_events(buf)
    check("解析单个事件", events == [(linux_inotify.IN_CREATE, 0, "a.conf")], str(events))
    check("空缓冲无事件", linux_inotify.parse_events(b"") == [])


def test_inotify_real_events() -> None:
    print("test_inotify_real_events")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    import select as _select

    with tempfile.TemporaryDirectory() as tmp:
        fd = linux_inotify.init()
        try:
            linux_inotify.add_watch(fd, tmp, linux_inotify.CHANGE_MASK)
            with open(os.path.join(tmp, "x.conf"), "wb") as fh:
                fh.write(b"1\n")
            ready, _, _ = _select.select([fd], [], [], 2.0)
            check("收到内核事件", bool(ready))
            events = linux_inotify.parse_events(os.read(fd, 65536))
            names = {(mask, n) for mask, _c, n in events}
            check("捕获新增事件", (linux_inotify.IN_CREATE, "x.conf") in names, str(names))
            check("捕获写入关闭事件", (linux_inotify.IN_CLOSE_WRITE, "x.conf") in names, str(names))
        finally:
            os.close(fd)


# --------------------------------------------------------------------------- #
# 监视器集成（真实 inotify）
# --------------------------------------------------------------------------- #
def _new_monitor(tmp: str, files: dict[str, bytes], **kw):
    cfg = os.path.join(tmp, "etc")
    manifest_files = make_config_dir(cfg, files)
    manifest_path = os.path.join(tmp, "manifest.json")
    write_manifest(manifest_path, cfg, manifest_files)
    kw.setdefault("recheck_delay", 0.2)
    kw.setdefault("rebuild_interval", 0.3)
    return IntegrityMonitor(manifest_path, **kw), cfg, files


def test_monitor_lifecycle() -> None:
    print("test_monitor_lifecycle")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        mon, cfg, files = _new_monitor(tmp, {"a.conf": b"alpha=1\n", "b.conf": b"beta=2\n"})
        try:
            mon.start()
            check("启动后复核为完整", wait_status(mon, STATUS_INTACT), mon.get_status()["reason"])
            check("监视有效", mon.get_status()["watch_active"] is True)

            # 原地写入篡改
            with open(os.path.join(cfg, "a.conf"), "ab") as fh:
                fh.write(b"evil=1\n")
            check("原地写入后报异常", wait_status(mon, STATUS_ANOMALY), mon.get_status()["reason"])
            check("差异为 modified",
                  any(d["type"] == "modified" and d["file"] == "a.conf"
                      for d in mon.get_status()["diffs"]), str(mon.get_status()["diffs"]))

            # 恢复原内容
            with open(os.path.join(cfg, "a.conf"), "wb") as fh:
                fh.write(files["a.conf"])
            check("恢复后回到完整", wait_status(mon, STATUS_INTACT))

            # 新增清单外文件
            with open(os.path.join(cfg, "c.conf"), "wb") as fh:
                fh.write(b"gamma=3\n")
            check("新增文件报异常", wait_status(mon, STATUS_ANOMALY))
            check("差异为 added",
                  any(d["type"] == "added" and d["file"] == "c.conf"
                      for d in mon.get_status()["diffs"]))
            os.unlink(os.path.join(cfg, "c.conf"))
            check("移除新增文件后恢复完整", wait_status(mon, STATUS_INTACT))

            # 删除清单内文件
            os.unlink(os.path.join(cfg, "b.conf"))
            check("删除文件报异常", wait_status(mon, STATUS_ANOMALY))
            check("差异为 missing",
                  any(d["type"] == "missing" and d["file"] == "b.conf"
                      for d in mon.get_status()["diffs"]))
            with open(os.path.join(cfg, "b.conf"), "wb") as fh:
                fh.write(files["b.conf"])
            check("补回文件后恢复完整", wait_status(mon, STATUS_INTACT))

            # 替换式篡改（写临时文件 + rename 原子替换）
            staging = os.path.join(cfg, ".b.conf.new")
            with open(staging, "wb") as fh:
                fh.write(b"beta=hacked\n")
            os.replace(staging, os.path.join(cfg, "b.conf"))
            check("替换式篡改报异常", wait_status(mon, STATUS_ANOMALY))
            check("替换差异为 modified",
                  any(d["type"] == "modified" and d["file"] == "b.conf"
                      for d in mon.get_status()["diffs"]))
        finally:
            mon.stop()


def test_monitor_pending_then_conclusion() -> None:
    print("test_monitor_pending_then_conclusion")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        mon, cfg, _files = _new_monitor(tmp, {"a.conf": b"alpha=1\n"}, recheck_delay=1.0)
        try:
            mon.start()
            check("初始完整", wait_status(mon, STATUS_INTACT))
            with open(os.path.join(cfg, "a.conf"), "ab") as fh:
                fh.write(b"evil=1\n")
            check("变更后进入待复核", wait_status(mon, STATUS_PENDING, 2.0),
                  mon.get_status()["reason"])
            check("待复核原因含变更通知", "变更通知" in mon.get_status()["reason"])
            check("复核延迟后得出异常结论", wait_status(mon, STATUS_ANOMALY, 5.0))
        finally:
            mon.stop()


def test_monitor_dir_removed_and_recreated() -> None:
    print("test_monitor_dir_removed_and_recreated")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        files = {"a.conf": b"alpha=1\n"}
        mon, cfg, _ = _new_monitor(tmp, files)
        try:
            mon.start()
            check("初始完整", wait_status(mon, STATUS_INTACT))
            shutil.rmtree(cfg)
            check("目录被删除报未知", wait_status(mon, STATUS_UNKNOWN, 5.0),
                  mon.get_status()["reason"])
            check("监视标记失效", mon.get_status()["watch_active"] is False)
            # 重建目录并恢复原内容：监视重建 + 全量复核后才恢复结论
            make_config_dir(cfg, files)
            check("目录重建后恢复完整", wait_status(mon, STATUS_INTACT, 8.0),
                  mon.get_status()["reason"])
            check("监视重新生效", mon.get_status()["watch_active"] is True)
        finally:
            mon.stop()


def test_monitor_watch_failure_recovery() -> None:
    print("test_monitor_watch_failure_recovery")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        mon, _cfg, _files = _new_monitor(tmp, {"a.conf": b"alpha=1\n"})
        try:
            mon.start()
            check("初始完整", wait_status(mon, STATUS_INTACT))
            with mon._lock:  # 注入队列溢出（等价于内核 IN_Q_OVERFLOW 的处理路径）
                generation = mon._watch_generation
            mon._on_watch_failure("inotify 事件队列溢出，变更通知可能丢失", generation)
            status = mon.get_status()
            check("队列溢出报未知", status["status"] == STATUS_UNKNOWN)
            check("未知原因说明", "队列溢出" in status["reason"])
            check("重建监视并复核后恢复完整", wait_status(mon, STATUS_INTACT, 5.0),
                  mon.get_status()["reason"])
        finally:
            mon.stop()


def test_monitor_recheck_invalidation() -> None:
    print("test_monitor_recheck_invalidation")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "etc")
        manifest_files = make_config_dir(cfg, {"a.conf": b"alpha=1\n"})
        manifest_path = os.path.join(tmp, "manifest.json")
        write_manifest(manifest_path, cfg, manifest_files)

        calls = {"n": 0}
        holder: dict[str, IntegrityMonitor] = {}

        def racy_scan(directory, expected, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                # 模拟复核期间再次变化：抬高世代号，使本轮结果成为迟到结果
                with holder["mon"]._lock:
                    holder["mon"]._epoch += 1
            return scan_directory(directory, expected, **kw)

        mon = IntegrityMonitor(manifest_path, recheck_delay=0.1, rebuild_interval=0.3,
                               scan_fn=racy_scan)
        holder["mon"] = mon
        try:
            mon.start()
            check("迟到结果作废后仍收敛到完整", wait_status(mon, STATUS_INTACT, 5.0),
                  mon.get_status()["reason"])
            check("作废后重新执行了复核", calls["n"] >= 2, str(calls))
        finally:
            mon.stop()


def test_monitor_manifest_recovery() -> None:
    print("test_monitor_manifest_recovery")
    if not INOTIFY_OK:
        print("  skip - 平台不支持 inotify")
        return
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = os.path.join(tmp, "manifest.json")  # 故意先不存在
        mon = IntegrityMonitor(manifest_path, recheck_delay=0.1, rebuild_interval=0.3)
        try:
            mon.start()
            check("清单缺失报未知", wait_status(mon, STATUS_UNKNOWN, 3.0),
                  mon.get_status()["reason"])
            check("未知原因指向清单", "清单" in mon.get_status()["reason"])
            cfg = os.path.join(tmp, "etc")
            manifest_files = make_config_dir(cfg, {"a.conf": b"alpha=1\n"})
            write_manifest(manifest_path, cfg, manifest_files)
            check("清单补齐后恢复完整", wait_status(mon, STATUS_INTACT, 8.0),
                  mon.get_status()["reason"])
        finally:
            mon.stop()


def main() -> int:
    tests = [
        test_manifest_parsing,
        test_scan_intact,
        test_scan_diffs,
        test_scan_not_regular,
        test_scan_symlink_not_followed,
        test_scan_limits,
        test_scan_missing_dir,
        test_inotify_parse,
        test_inotify_real_events,
        test_monitor_lifecycle,
        test_monitor_pending_then_conclusion,
        test_monitor_dir_removed_and_recreated,
        test_monitor_watch_failure_recovery,
        test_monitor_recheck_invalidation,
        test_monitor_manifest_recovery,
    ]
    for test in tests:
        test()
    print()
    print("全部完整性监测测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
