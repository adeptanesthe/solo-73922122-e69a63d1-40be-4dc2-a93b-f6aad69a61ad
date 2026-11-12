"""HTTP 层的请求/响应模型（pydantic v2）。

字段同时接受 systemd 原生写法（``ProtectSystem``）与 snake_case 写法，
策略内的路径强制要求绝对路径，相对路径只允许出现在审计事件里。
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    protect_system: Literal["off", "full", "strict", "yes", "no"] = Field(
        default="off",
        alias="ProtectSystem",
        description="off/no=不启用；full 或 yes=保护 /usr /boot /efi /etc；strict=整文件系统只读",
    )
    protect_home: Literal["off", "yes", "read-only", "no", "tmpfs"] = Field(
        default="off",
        alias="ProtectHome",
        description="off/no=不启用；yes=home 完全不可见；read-only=只读",
    )
    read_write_paths: list[str] = Field(
        default_factory=list,
        alias="ReadWritePaths",
        description="可写路径白名单（绝对路径），可覆盖只读策略，但不能覆盖 InaccessiblePaths",
    )
    inaccessible_paths: list[str] = Field(
        default_factory=list,
        alias="InaccessiblePaths",
        description="不可访问路径（绝对路径），拒绝优先级最高",
    )
    private_tmp: bool = Field(
        default=False,
        alias="PrivateTmp",
        description="yes 时 /tmp、/var/tmp 重映射到私有命名空间",
    )
    unit_name: str = Field(
        default="daemon.service",
        alias="UnitName",
        description="unit 名称，用于标注 PrivateTmp 私有目录",
    )

    @field_validator("read_write_paths", "inaccessible_paths")
    @classmethod
    def _must_be_absolute(cls, value: list[str], info) -> list[str]:
        for p in value:
            if not isinstance(p, str) or not p.strip():
                raise ValueError(f"{info.field_name} 中的路径必须是非空字符串")
            if not p.strip().startswith("/"):
                raise ValueError(
                    f"{info.field_name} 只接受绝对路径，收到相对路径: {p!r}；"
                    "相对路径只能出现在审计事件中"
                )
        return value


class AuditEventInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: Literal["fork", "chdir", "access"] = Field(description="事件类型")
    pid: int = Field(gt=0, description="发起事件的进程 PID")
    ppid: Optional[int] = Field(default=None, description="父进程 PID（可选，仅用于展示）")
    child_pid: Optional[int] = Field(default=None, gt=0, description="fork 事件的子进程 PID")
    operation: Optional[Literal["read", "write", "execute"]] = Field(
        default=None, description="access 事件的操作类型"
    )
    path: Optional[str] = Field(
        default=None, description="chdir/access 的目标路径，可为绝对路径或相对 cwd 的相对路径"
    )

    def to_engine(self) -> dict:
        return self.model_dump(exclude_none=True)


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    policy: PolicyInput = Field(description="systemd unit 沙箱策略")
    events: list[AuditEventInput] = Field(
        default_factory=list, description="按时间顺序排列的进程审计事件"
    )


class TraceEntry(BaseModel):
    seq: int
    event_type: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    operation: Optional[str] = None
    raw_path: Optional[str] = None
    cwd_before: Optional[str] = None
    cwd_after: Optional[str] = None
    normalized_path: Optional[str] = None
    sandbox_path: Optional[str] = None
    decision: str
    reason: str
    matched_policies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EffectivePolicy(BaseModel):
    ProtectSystem: str
    ProtectHome: str
    ReadWritePaths: list[str]
    InaccessiblePaths: list[str]
    PrivateTmp: bool
    unit_name: str


class EvaluateResponse(BaseModel):
    allowed: bool = Field(description="全部事件是否均未被沙箱阻断")
    failure_event_seq: Optional[int] = Field(
        default=None, description="首个失败事件序号（从 1 开始），全部通过时为 null"
    )
    failure_reason: Optional[str] = Field(default=None, description="首个失败原因")
    events_total: int
    events_evaluated: int = Field(description="实际评估的事件数；遇首个失败即停止")
    policy_effective: EffectivePolicy = Field(description="归一化后实际生效的策略")
    trace: list[TraceEntry] = Field(description="逐事件的完整判定轨迹")


# --------------------------------------------------------------------------- #
# 配置目录完整性监测
# --------------------------------------------------------------------------- #
class IntegrityDiff(BaseModel):
    type: str = Field(
        description="差异类型：missing 缺失 / added 新增 / modified 内容改变 / "
        "not_regular 非普通文件 / too_large 超过1MiB / too_many_files 文件数超限 / "
        "too_many_entries 目录项过多 / unreadable 无法读取"
    )
    file: Optional[str] = Field(default=None, description="涉及的单层文件名；目录级差异为 null")
    detail: str = Field(description="差异的具体说明")


class IntegrityLimits(BaseModel):
    max_files: int = Field(description="单层普通文件数量上限")
    max_file_size_bytes: int = Field(description="单文件大小上限（字节）")
    single_level: bool = Field(description="是否只检查目录第一层（不递归）")
    follow_symlinks: bool = Field(description="是否跟随软链接（恒为 false）")


class IntegrityStatusResponse(BaseModel):
    status: Literal["intact", "anomaly", "pending", "unknown"] = Field(
        description="intact 完整 / anomaly 异常 / pending 待复核 / unknown 未知"
    )
    status_text: str = Field(description="状态中文名：完整 / 异常 / 待复核 / 未知")
    reason: str = Field(description="当前状态的原因说明")
    directory: Optional[str] = Field(default=None, description="被监视的配置目录")
    manifest_path: str = Field(description="可信清单路径（启动时加载）")
    manifest_files: int = Field(description="清单固定的文件数量")
    watch_active: bool = Field(description="inotify 监视当前是否有效")
    generation: int = Field(description="状态世代号：每次变更通知/监视失效递增")
    recheck_delay_seconds: float = Field(description="收到变更通知后延迟复核的秒数")
    last_change_at: Optional[str] = Field(default=None, description="最近一次变更通知时间（UTC）")
    last_recheck_at: Optional[str] = Field(default=None, description="最近一次全量复核完成时间（UTC）")
    pending_since: Optional[str] = Field(default=None, description="进入待复核状态的时间（UTC）")
    limits: IntegrityLimits = Field(description="完整性检查的限制参数")
    diffs: list[IntegrityDiff] = Field(
        default_factory=list, description="状态为异常时的全部差异明细，其余状态为空"
    )
