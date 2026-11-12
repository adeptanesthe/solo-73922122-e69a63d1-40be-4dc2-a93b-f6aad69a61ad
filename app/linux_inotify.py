"""Linux inotify 的最小封装（ctypes 直调 libc，仅依赖标准库）。

服务需要在不引入第三方包的前提下获得**真实**的内核文件系统事件，
这里封装 ``inotify_init1`` / ``inotify_add_watch`` 与事件解析。
仅支持 Linux；其它平台 ``available()`` 返回 False，由上层降级处理。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import sys

# --------------------------------------------------------------------------- #
# inotify 掩码（见 inotify(7)）
# --------------------------------------------------------------------------- #
IN_MODIFY = 0x00000002          # 文件内容被原地写入
IN_CLOSE_WRITE = 0x00000008     # 以写方式打开的文件被关闭（写完成）
IN_MOVED_FROM = 0x00000040      # 文件被移出目录
IN_MOVED_TO = 0x00000080        # 文件被移入目录（替换式写入的最后一步）
IN_CREATE = 0x00000100          # 目录内新建文件
IN_DELETE = 0x00000200          # 目录内文件被删除
IN_DELETE_SELF = 0x00000400     # 被监视目录本身被删除
IN_MOVE_SELF = 0x00000800       # 被监视目录本身被移动
IN_ONLYDIR = 0x01000000         # 仅允许监视目录（add_watch 用）
IN_Q_OVERFLOW = 0x00004000      # 内核事件队列溢出（事件丢失）
IN_IGNORED = 0x00008000         # 监视被内核移除（目录删除/卸载等）

IN_NONBLOCK = 0x00000800        # O_NONBLOCK（inotify_init1 标志）
IN_CLOEXEC = 0x00080000         # O_CLOEXEC（inotify_init1 标志）

# 触发“待复核”的变更事件：原地写入、写关闭、替换（移入/移出）、增删
CHANGE_MASK = (
    IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE
    | IN_MOVED_FROM | IN_MOVED_TO
)
# 监视自身失效事件：目录被删除/移动、监视被移除、队列溢出
WATCH_DEAD_MASK = IN_DELETE_SELF | IN_MOVE_SELF | IN_Q_OVERFLOW | IN_IGNORED

_EVENT_HEADER = struct.Struct("iIII")  # wd, mask, cookie, len


class InotifyUnavailable(RuntimeError):
    """当前平台/内核不支持 inotify。"""


def _load_libc():
    if not sys.platform.startswith("linux"):
        raise InotifyUnavailable(f"inotify 仅支持 Linux，当前平台为 {sys.platform}")
    path = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(path, use_errno=True)
        init1 = libc.inotify_init1
        add_watch = libc.inotify_add_watch
    except (OSError, AttributeError) as exc:  # pragma: no cover - 非 Linux 兜底
        raise InotifyUnavailable(f"无法加载 libc 的 inotify 接口: {exc}") from exc
    init1.argtypes = [ctypes.c_int]
    init1.restype = ctypes.c_int
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int
    return init1, add_watch


try:
    _inotify_init1, _inotify_add_watch = _load_libc()
except InotifyUnavailable:  # pragma: no cover - 非 Linux 平台
    _inotify_init1 = None
    _inotify_add_watch = None


def available() -> bool:
    """inotify 是否可用（真实创建一个句柄验证）。"""
    if _inotify_init1 is None:
        return False
    fd = init()
    if fd < 0:
        return False
    os.close(fd)
    return True


def init() -> int:
    """创建 inotify 实例（非阻塞 + close-on-exec），失败抛 OSError。"""
    if _inotify_init1 is None:
        raise InotifyUnavailable(f"inotify 仅支持 Linux，当前平台为 {sys.platform}")
    fd = _inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"inotify_init1 失败: {os.strerror(err)}")
    return fd


def add_watch(fd: int, directory: str, mask: int) -> int:
    """对目录建立监视，返回 watch descriptor；失败抛 OSError。"""
    wd = _inotify_add_watch(fd, os.fsencode(directory), mask | IN_ONLYDIR)
    if wd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"inotify_add_watch({directory!r}) 失败: {os.strerror(err)}")
    return wd


def parse_events(buf: bytes) -> list[tuple[int, int, str]]:
    """把 read() 返回的字节流解析为 (mask, cookie, name) 列表。

    目录自身事件（IN_DELETE_SELF 等）name 为空字符串。
    """
    events: list[tuple[int, int, str]] = []
    offset = 0
    total = len(buf)
    while offset + _EVENT_HEADER.size <= total:
        _wd, mask, cookie, name_len = _EVENT_HEADER.unpack_from(buf, offset)
        offset += _EVENT_HEADER.size
        raw = buf[offset:offset + name_len]
        offset += name_len
        name = raw.split(b"\0", 1)[0]
        events.append((mask, cookie, os.fsdecode(name) if name else ""))
    return events


def describe(mask: int, name: str) -> str:
    """把事件掩码转成人类可读描述（用于状态原因与日志）。"""
    parts: list[str] = []
    if mask & IN_MODIFY:
        parts.append("原地写入")
    if mask & IN_CLOSE_WRITE:
        parts.append("写入关闭")
    if mask & IN_CREATE:
        parts.append("新增")
    if mask & IN_DELETE:
        parts.append("删除")
    if mask & IN_MOVED_FROM:
        parts.append("移出")
    if mask & IN_MOVED_TO:
        parts.append("移入/替换")
    if mask & IN_DELETE_SELF:
        parts.append("目录被删除")
    if mask & IN_MOVE_SELF:
        parts.append("目录被移动")
    if mask & IN_Q_OVERFLOW:
        parts.append("事件队列溢出")
    if mask & IN_IGNORED:
        parts.append("监视被移除")
    label = "+".join(parts) if parts else f"mask=0x{mask:x}"
    return f"{label} {name}".strip()
