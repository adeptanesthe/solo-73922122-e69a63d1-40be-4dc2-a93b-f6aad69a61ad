"""配置目录完整性监测引擎（仅依赖 Python 标准库）。

面向 Linux 服务维护人员：部署前确认配置目录未被篡改。

模型
----

* **可信启动配置**：启动时加载清单 JSON，固定 ``目录 + 文件名 -> SHA-256``。
* **单层检查**：只检查目录第一层，最多 100 个普通文件，每个不超过 1MiB；
  不跟随软链接，软链接/子目录/FIFO 等非普通文件一律报异常。
* **先监视后复核**：先建立真实 inotify 监视，再做全量复核，
  文件集合与摘要全部匹配才报 ``完整``。
* **事件驱动**：收到原地写入、替换（移入/移出）或增删通知即标为 ``待复核``，
  延迟 ``recheck_delay`` 秒后复核；复核期间再次变化则作废本轮结果并重查，
  迟到结果不得覆盖新状态（世代号保证）。
* **失效兜底**：inotify 队列溢出、目录被删除/移动导致监视失效时报 ``未知``，
  必须重建监视并完成全量复核后才恢复结论；启动与重启均重新检查。

状态机：``intact(完整) / anomaly(异常) / pending(待复核) / unknown(未知)``。
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import posixpath
import re
import select
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from . import linux_inotify

logger = logging.getLogger("app.integrity")

# --------------------------------------------------------------------------- #
# 常量与限制
# --------------------------------------------------------------------------- #
MAX_FILES = 100                     # 单层最多 100 个普通文件
MAX_FILE_SIZE = 1 << 20             # 每个文件不超过 1MiB
ENTRY_SCAN_CAP = 1000               # 目录项枚举保护上限（防失控目录拖垮复核）
READ_CHUNK = 1 << 16

STATUS_INTACT = "intact"
STATUS_ANOMALY = "anomaly"
STATUS_PENDING = "pending"
STATUS_UNKNOWN = "unknown"
STATUS_TEXT = {
    STATUS_INTACT: "完整",
    STATUS_ANOMALY: "异常",
    STATUS_PENDING: "待复核",
    STATUS_UNKNOWN: "未知",
}

DEFAULT_MANIFEST_PATH = "/etc/integrity/manifest.json"
DEFAULT_RECHECK_DELAY = 0.5         # 变更通知后延迟复核的秒数（演示可调）
DEFAULT_REBUILD_INTERVAL = 2.0      # 监视失效后的重建重试间隔

# 需要建立监视的事件：变更类 + 目录自身失效类
WATCH_MASK = (
    linux_inotify.CHANGE_MASK
    | linux_inotify.IN_DELETE_SELF
    | linux_inotify.IN_MOVE_SELF
)

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# 可信清单
# --------------------------------------------------------------------------- #
class ManifestError(ValueError):
    """可信清单不合法。"""


@dataclass(frozen=True)
class Manifest:
    directory: str
    files: dict[str, str]           # 单层文件名 -> sha256 hex（小写）


def _valid_filename(name: object) -> bool:
    return (
        isinstance(name, str)
        and 0 < len(name) <= 255
        and name not in (".", "..")
        and "/" not in name
        and "\0" not in name
    )


def parse_manifest(data: object) -> Manifest:
    """校验并归一化清单对象（与文件来源解耦，便于测试）。"""
    if not isinstance(data, dict):
        raise ManifestError("清单必须是 JSON 对象")
    directory = data.get("directory")
    if not isinstance(directory, str) or not directory.startswith("/"):
        raise ManifestError("清单 directory 必须是绝对路径字符串")
    directory = posixpath.normpath(directory)
    if directory == "/":
        raise ManifestError("不允许把根目录 / 作为被监视目录")
    if "files" not in data or not isinstance(data["files"], dict):
        raise ManifestError("清单 files 必须是 文件名->SHA-256 的对象（可为空对象）")
    files_in = data["files"]
    if len(files_in) > MAX_FILES:
        raise ManifestError(f"清单文件数量 {len(files_in)} 超过上限 {MAX_FILES}")
    files: dict[str, str] = {}
    for name, digest in files_in.items():
        if not _valid_filename(name):
            raise ManifestError(
                f"非法文件名 {name!r}：只允许单层普通文件名，不得包含 '/' 或为 '.'/'..'"
            )
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest.strip()):
            raise ManifestError(f"文件 {name!r} 的 SHA-256 必须是 64 位十六进制字符串")
        files[name] = digest.strip().lower()
    return Manifest(directory=directory, files=files)


def load_manifest(path: str) -> Manifest:
    """从可信启动配置加载清单。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ManifestError(f"无法读取清单文件 {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"清单 {path} 不是合法 JSON: {exc}") from exc
    try:
        return parse_manifest(data)
    except ManifestError as exc:
        raise ManifestError(f"清单 {path} 不合法: {exc}") from exc


# --------------------------------------------------------------------------- #
# 全量复核（单层扫描 + SHA-256 比对）
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    status: str                     # STATUS_INTACT / STATUS_ANOMALY
    reason: str
    diffs: list[dict] = field(default_factory=list)


def _diff(kind: str, name: Optional[str], detail: str) -> dict:
    return {"type": kind, "file": name, "detail": detail}


def _mode_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "符号链接"
    if stat.S_ISDIR(mode):
        return "目录"
    if stat.S_ISFIFO(mode):
        return "FIFO 管道"
    if stat.S_ISSOCK(mode):
        return "套接字"
    if stat.S_ISBLK(mode):
        return "块设备"
    if stat.S_ISCHR(mode):
        return "字符设备"
    return "非常规文件"


def _hash_regular_file(path: str, name: str, max_file_size: int) -> tuple[Optional[str], Optional[dict]]:
    """对单层文件计算 SHA-256；不跟随软链接（O_NOFOLLOW）。

    返回 ``(hexdigest, None)`` 或 ``(None, 差异dict)``。
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, _diff("not_regular", name, "不是普通文件（类型：符号链接），不跟随、不予采信")
        return None, _diff("unreadable", name, f"无法打开文件：{exc.strerror or exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, _diff("not_regular", name, f"不是普通文件（类型：{_mode_kind(st.st_mode)}）")
        if st.st_size > max_file_size:
            return None, _diff(
                "too_large", name,
                f"文件大小 {st.st_size} 字节，超过 1MiB（{max_file_size} 字节）上限",
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, _diff("unreadable", name, f"读取文件失败：{exc.strerror or exc}")
    finally:
        os.close(fd)


def scan_directory(
    directory: str,
    expected_files: dict[str, str],
    *,
    max_files: int = MAX_FILES,
    max_file_size: int = MAX_FILE_SIZE,
    entry_cap: int = ENTRY_SCAN_CAP,
) -> Optional[ScanResult]:
    """对目录做单层全量复核。

    返回 ``ScanResult``；目录本身不可读/不存在时返回 ``None``（无法得出结论，
    由监视器按 ``未知`` 处理并重建监视）。
    """
    try:
        scanner = os.scandir(directory)
    except OSError as exc:
        logger.warning("integrity scan: 无法枚举目录 %s: %s", directory, exc)
        return None

    diffs: list[dict] = []
    present_regular: dict[str, int] = {}
    seen: set[str] = set()
    capped = False
    count = 0
    with scanner as it:
        for entry in it:
            count += 1
            if count > entry_cap:
                capped = True
                break
            name = entry.name
            seen.add(name)
            try:
                st = entry.stat(follow_symlinks=False)  # 不跟随软链接
            except OSError as exc:
                diffs.append(_diff("unreadable", name, f"无法读取文件状态：{exc.strerror or exc}"))
                continue
            if stat.S_ISREG(st.st_mode):
                present_regular[name] = st.st_size
            else:
                diffs.append(_diff(
                    "not_regular", name,
                    f"不是普通文件（类型：{_mode_kind(st.st_mode)}），完整性不予采信",
                ))
    if capped:
        diffs.append(_diff(
            "too_many_entries", None,
            f"目录项数量超过枚举保护上限 {entry_cap}，无法完整复核",
        ))
    if len(present_regular) > max_files:
        diffs.append(_diff(
            "too_many_files", None,
            f"普通文件数量 {len(present_regular)} 超过上限 {max_files}",
        ))

    # 缺失：清单有、目录中完全不存在
    for name in sorted(expected_files):
        if name not in seen:
            diffs.append(_diff("missing", name, "清单中的文件在目录中缺失"))
    # 新增：目录中有、清单外
    for name in sorted(present_regular):
        if name not in expected_files:
            diffs.append(_diff("added", name, "目录中出现清单外的新增文件"))
    # 大小与摘要：清单与目录都有的普通文件
    for name in sorted(expected_files):
        size = present_regular.get(name)
        if size is None:
            continue
        if size > max_file_size:
            diffs.append(_diff(
                "too_large", name,
                f"文件大小 {size} 字节，超过 1MiB（{max_file_size} 字节）上限",
            ))
            continue
        digest, err_diff = _hash_regular_file(os.path.join(directory, name), name, max_file_size)
        if err_diff is not None:
            diffs.append(err_diff)
            continue
        expected_digest = expected_files[name]
        if digest != expected_digest:
            diffs.append(_diff(
                "modified", name,
                f"SHA-256 不匹配：清单 {expected_digest}，实际 {digest}",
            ))

    diffs.sort(key=lambda d: (d["file"] is None, d["file"] or "", d["type"]))
    if diffs:
        return ScanResult(STATUS_ANOMALY, f"检测到 {len(diffs)} 处差异，文件集合或摘要不匹配", diffs)
    return ScanResult(STATUS_INTACT, f"文件集合与 SHA-256 摘要全部匹配（{len(expected_files)} 个文件）", [])


# --------------------------------------------------------------------------- #
# 监视器：inotify 事件 + 延迟复核 + 失效重建
# --------------------------------------------------------------------------- #
class IntegrityMonitor:
    """单进程目录完整性监视器（后台线程 + 定时器，线程安全）。"""

    def __init__(
        self,
        manifest_path: str,
        *,
        recheck_delay: float = DEFAULT_RECHECK_DELAY,
        rebuild_interval: float = DEFAULT_REBUILD_INTERVAL,
        scan_fn: Callable[..., Optional[ScanResult]] = scan_directory,
    ) -> None:
        self._manifest_path = manifest_path
        self._recheck_delay = max(0.0, float(recheck_delay))
        self._rebuild_interval = max(0.1, float(rebuild_interval))
        self._scan_fn = scan_fn

        self._lock = threading.Lock()
        self._epoch = 0                     # 世代号：变更/失效时递增，迟到结果据此作废
        self._status = STATUS_PENDING
        self._reason = "监测器尚未启动"
        self._diffs: list[dict] = []
        self._manifest: Optional[Manifest] = None
        self._watch_active = False
        self._watch_inode: Optional[tuple[int, int]] = None
        self._watch_generation = 0
        self._last_change_at: Optional[str] = None
        self._last_recheck_at: Optional[str] = None
        self._pending_since: Optional[str] = None

        self._started = False
        self._stop = threading.Event()
        self._recheck_timer: Optional[threading.Timer] = None
        self._rebuild_timer: Optional[threading.Timer] = None
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------ #
    # 配置
    # ------------------------------------------------------------------ #
    @classmethod
    def from_env(cls) -> "IntegrityMonitor":
        return cls(
            os.environ.get("INTEGRITY_MANIFEST_PATH", DEFAULT_MANIFEST_PATH),
            recheck_delay=_env_float("INTEGRITY_RECHECK_DELAY", DEFAULT_RECHECK_DELAY),
            rebuild_interval=_env_float("INTEGRITY_REBUILD_INTERVAL", DEFAULT_REBUILD_INTERVAL),
        )

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """启动监测：加载清单 -> 建立 inotify 监视 -> 全量复核。"""
        with self._lock:
            if self._started:
                return
            self._started = True
        logger.info("integrity monitor starting, manifest=%s", self._manifest_path)
        try:
            manifest = load_manifest(self._manifest_path)
        except ManifestError as exc:
            with self._lock:
                self._status = STATUS_UNKNOWN
                self._reason = f"清单加载失败：{exc}；{self._rebuild_interval:.1f}s 后重试"
            self._schedule_rebuild(self._rebuild_interval)
            return
        with self._lock:
            self._manifest = manifest
        err = self._establish_watch()
        if err is not None:
            with self._lock:
                self._status = STATUS_UNKNOWN
                self._reason = f"inotify 监视建立失败：{err}；{self._rebuild_interval:.1f}s 后重试"
            self._schedule_rebuild(self._rebuild_interval)
            return
        # 先建立监视，再全量复核（首次复核同步完成，启动即可给出结论）
        self._run_recheck()

    def stop(self) -> None:
        """停止监测（进程退出前调用；停止后不可再启动）。"""
        self._stop.set()
        with self._lock:
            for timer in (self._recheck_timer, self._rebuild_timer):
                if timer is not None:
                    timer.cancel()
            self._watch_generation += 1     # 让监视循环尽快退出
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=1.0)

    # ------------------------------------------------------------------ #
    # inotify 监视
    # ------------------------------------------------------------------ #
    def _establish_watch(self) -> Optional[str]:
        """建立监视并启动读取线程；成功返回 None，失败返回错误描述。"""
        assert self._manifest is not None
        directory = self._manifest.directory
        fd: Optional[int] = None
        try:
            fd = linux_inotify.init()
            linux_inotify.add_watch(fd, directory, WATCH_MASK)
            # 与 add_watch 解析到同一目录本体（跟随路径中的软链），用于检测目录被替换
            st = os.stat(directory)
        except (OSError, linux_inotify.InotifyUnavailable) as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            return str(exc)
        with self._lock:
            self._watch_generation += 1
            generation = self._watch_generation
            self._watch_inode = (st.st_dev, st.st_ino)
            self._watch_active = True
            self._threads = [t for t in self._threads if t.is_alive()]
            thread = threading.Thread(
                target=self._watch_loop,
                args=(fd, generation),
                daemon=True,
                name=f"integrity-watch-{generation}",
            )
            self._threads.append(thread)
        thread.start()
        logger.info("integrity watch established on %s (generation=%d)", directory, generation)
        return None

    def _watch_loop(self, fd: int, generation: int) -> None:
        """读取 inotify 事件；循环独占 fd，退出时负责关闭。"""
        try:
            while not self._stop.is_set():
                with self._lock:
                    stale = generation != self._watch_generation
                if stale:
                    break
                try:
                    ready, _, _ = select.select([fd], [], [], 0.25)
                except (OSError, ValueError):
                    break
                if not ready:
                    continue
                try:
                    buf = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    self._on_watch_failure(f"inotify 读取失败：{exc}", generation)
                    break
                if not buf:
                    continue
                dead: Optional[str] = None
                changes: list[str] = []
                for mask, _cookie, name in linux_inotify.parse_events(buf):
                    if mask & linux_inotify.IN_Q_OVERFLOW:
                        dead = "inotify 事件队列溢出，变更通知可能丢失"
                        break
                    if mask & linux_inotify.IN_IGNORED:
                        dead = "被监视目录的监视已失效（目录被删除、移动或文件系统被卸载）"
                        break
                    if mask & (linux_inotify.IN_DELETE_SELF | linux_inotify.IN_MOVE_SELF):
                        dead = "被监视目录本身被删除或移动"
                        break
                    if mask & linux_inotify.CHANGE_MASK:
                        changes.append(linux_inotify.describe(mask, name))
                if dead is not None:
                    self._on_watch_failure(dead, generation)
                    break
                if changes:
                    self._on_changes(changes, generation)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # 状态迁移
    # ------------------------------------------------------------------ #
    def _on_changes(self, descriptions: list[str], generation: int) -> None:
        """收到变更通知：标为待复核并（重新）安排延迟复核。"""
        with self._lock:
            if self._stop.is_set() or generation != self._watch_generation:
                return
            self._epoch += 1
            self._last_change_at = _now_iso()
            if self._status == STATUS_UNKNOWN:
                # 未知状态下由重建流程负责恢复结论
                return
            self._status = STATUS_PENDING
            summary = (
                descriptions[0]
                if len(descriptions) == 1
                else f"{descriptions[0]} 等 {len(descriptions)} 项"
            )
            self._reason = f"收到变更通知（{summary}），等待复核"
            self._pending_since = self._last_change_at
        self._schedule_recheck(self._recheck_delay)

    def _on_watch_failure(self, reason: str, generation: int) -> None:
        """队列溢出/监视失效：报未知，重建监视并复核后才可恢复结论。"""
        with self._lock:
            if self._stop.is_set() or generation != self._watch_generation:
                return
            self._epoch += 1
            self._status = STATUS_UNKNOWN
            self._reason = f"{reason}；正在重建监视并复核"
            self._watch_active = False
            self._watch_inode = None
            self._pending_since = None
        logger.warning("integrity watch lost: %s", reason)
        self._schedule_rebuild(self._rebuild_interval)

    def _run_recheck(self) -> None:
        """执行一轮全量复核；复核期间再次变化则作废本轮结果并重查。"""
        if self._stop.is_set():
            return
        action: Optional[str] = None
        try:
            with self._lock:
                manifest = self._manifest
                watch_inode = self._watch_inode
                watch_active = self._watch_active
                epoch_at_start = self._epoch
            if manifest is None or not watch_active:
                # 清单未就绪或监视不可用：走重建流程（含清单加载 + 重建监视 + 复核）
                self._schedule_rebuild(0.0)
                return

            # 目录本体校验：被替换/重指向则本轮无法得出结论
            inconclusive: Optional[str] = None
            try:
                st = os.stat(manifest.directory)
                if watch_inode is not None and (st.st_dev, st.st_ino) != watch_inode:
                    inconclusive = "被监视目录本体已变化（被删除、替换或重指向）"
            except OSError as exc:
                inconclusive = f"无法访问被监视目录：{exc.strerror or exc}"

            result: Optional[ScanResult] = None
            if inconclusive is None:
                result = self._scan_fn(manifest.directory, manifest.files)
                if result is None:
                    inconclusive = "全量复核失败：目录不可读或已不存在"

            with self._lock:
                if self._stop.is_set():
                    return
                if epoch_at_start != self._epoch:
                    # 复核期间再次变化：作废本轮结果，重新复核（迟到结果不得覆盖新状态）
                    if self._status == STATUS_PENDING:
                        self._reason = "复核期间再次发生变化，本轮结果作废，重新复核"
                    action = "recheck"
                elif inconclusive is not None:
                    self._status = STATUS_UNKNOWN
                    self._reason = f"{inconclusive}；正在重建监视并复核"
                    self._watch_active = False
                    self._watch_inode = None
                    self._pending_since = None
                    action = "rebuild"
                else:
                    assert result is not None
                    self._status = result.status
                    self._reason = result.reason
                    self._diffs = result.diffs
                    self._last_recheck_at = _now_iso()
                    self._pending_since = None
                    logger.info("integrity recheck done: %s (%s)", result.status, result.reason)
        except Exception as exc:  # 防御：定时器线程不得静默死亡
            logger.exception("integrity recheck crashed")
            with self._lock:
                self._status = STATUS_UNKNOWN
                self._reason = f"复核内部错误：{exc}"
                self._watch_active = False
                self._watch_inode = None
            action = "rebuild"

        if action == "recheck":
            self._schedule_recheck(self._recheck_delay)
        elif action == "rebuild":
            self._schedule_rebuild(self._rebuild_interval)

    def _rebuild(self) -> None:
        """失效恢复：加载清单 -> 重建监视 -> 全量复核，完成后才恢复结论。"""
        if self._stop.is_set():
            return
        try:
            if self._manifest is None:
                try:
                    manifest = load_manifest(self._manifest_path)
                except ManifestError as exc:
                    with self._lock:
                        self._status = STATUS_UNKNOWN
                        self._reason = f"清单加载失败：{exc}；{self._rebuild_interval:.1f}s 后重试"
                    self._schedule_rebuild(self._rebuild_interval)
                    return
                with self._lock:
                    self._manifest = manifest
            err = self._establish_watch()
            if err is not None:
                with self._lock:
                    self._status = STATUS_UNKNOWN
                    self._reason = f"监视重建失败：{err}；{self._rebuild_interval:.1f}s 后重试"
                self._schedule_rebuild(self._rebuild_interval)
                return
            with self._lock:
                if self._status == STATUS_UNKNOWN:
                    self._reason = "监视已重建，执行全量复核"
            self._run_recheck()
        except Exception as exc:  # 防御
            logger.exception("integrity rebuild crashed")
            with self._lock:
                self._status = STATUS_UNKNOWN
                self._reason = f"重建内部错误：{exc}"
            self._schedule_rebuild(self._rebuild_interval)

    # ------------------------------------------------------------------ #
    # 定时器
    # ------------------------------------------------------------------ #
    def _schedule_recheck(self, delay: float) -> None:
        with self._lock:
            if self._stop.is_set():
                return
            if self._recheck_timer is not None:
                self._recheck_timer.cancel()
            timer = threading.Timer(max(0.0, delay), self._run_recheck)
            timer.daemon = True
            self._recheck_timer = timer
            timer.start()

    def _schedule_rebuild(self, delay: float) -> None:
        with self._lock:
            if self._stop.is_set():
                return
            if self._rebuild_timer is not None:
                self._rebuild_timer.cancel()
            timer = threading.Timer(max(0.0, delay), self._rebuild)
            timer.daemon = True
            self._rebuild_timer = timer
            timer.start()

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #
    def request_recheck(self) -> None:
        """手动触发一次全量复核（使进行中的结果作废，以最新状态为准）。"""
        with self._lock:
            if self._stop.is_set() or not self._started:
                return
            self._epoch += 1
            need_rebuild = self._manifest is None or not self._watch_active
            if not need_rebuild and self._status != STATUS_UNKNOWN:
                self._status = STATUS_PENDING
                self._reason = "手动触发全量复核"
                self._pending_since = _now_iso()
        if need_rebuild:
            self._schedule_rebuild(0.0)
        else:
            self._schedule_recheck(0.0)

    def get_status(self) -> dict:
        """返回当前状态快照（完整/异常/待复核/未知 + 原因 + 差异）。"""
        with self._lock:
            manifest = self._manifest
            return {
                "status": self._status,
                "status_text": STATUS_TEXT[self._status],
                "reason": self._reason,
                "directory": manifest.directory if manifest else None,
                "manifest_path": self._manifest_path,
                "manifest_files": len(manifest.files) if manifest else 0,
                "watch_active": self._watch_active,
                "generation": self._epoch,
                "recheck_delay_seconds": self._recheck_delay,
                "last_change_at": self._last_change_at,
                "last_recheck_at": self._last_recheck_at,
                "pending_since": self._pending_since if self._status == STATUS_PENDING else None,
                "limits": {
                    "max_files": MAX_FILES,
                    "max_file_size_bytes": MAX_FILE_SIZE,
                    "single_level": True,
                    "follow_symlinks": False,
                },
                "diffs": list(self._diffs) if self._status == STATUS_ANOMALY else [],
            }


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("环境变量 %s=%r 不是数字，使用默认值 %s", name, raw, default)
        return default
    return max(0.0, min(value, 300.0))
