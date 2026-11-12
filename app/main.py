"""FastAPI 应用：systemd 沙箱策略离线核查 + 配置目录完整性监测。

所有计算均在本地完成，不发起任何外部网络请求，适合离线维护终端部署。
完整性监测与 HTTP 服务同进程运行（单进程）：启动时加载可信清单，
先建立真实 inotify 监视，再做全量复核。
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from . import __version__
from .engine import PolicyError, evaluate
from .integrity import IntegrityMonitor
from .schemas import (
    EvaluateRequest,
    EvaluateResponse,
    IntegrityStatusResponse,
)

# 单进程监视器：与 HTTP 服务同生共死；启动/重启都会重新检查
monitor = IntegrityMonitor.from_env()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 启动：加载清单 -> 建立 inotify 监视 -> 全量复核
    monitor.start()
    yield
    monitor.stop()


app = FastAPI(
    title="systemd 沙箱策略核查与配置完整性监测 API",
    version=__version__,
    description=(
        "1) 离线核对 systemd 沙箱指令（ProtectSystem / ProtectHome / ReadWritePaths / "
        "InaccessiblePaths / PrivateTmp）是否会阻断守护进程的真实文件操作；"
        "2) 基于可信清单（目录 + 文件名 -> SHA-256）与真实 inotify 监视，"
        "持续核查配置目录完整性，返回 完整/异常/待复核/未知 及原因，"
        "供维护人员决定是否暂停部署。"
    ),
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"], summary="健康检查")
def health() -> dict:
    return {
        "status": "ok",
        "service": "systemd-sandbox-checker",
        "version": __version__,
        "integrity": monitor.get_status()["status"],
    }


@app.post(
    "/api/v1/evaluate",
    response_model=EvaluateResponse,
    tags=["evaluate"],
    summary="回放审计事件并核对沙箱策略",
    responses={
        422: {"description": "策略或事件字段不合法（含相对路径出现在策略中等）"},
    },
)
def evaluate_events(req: EvaluateRequest) -> EvaluateResponse:
    """按进程继承与路径规范化逐步判定；拒绝路径优先于可写路径。"""
    try:
        result = evaluate(
            req.policy.model_dump(by_alias=False, exclude_none=False),
            [e.to_engine() for e in req.events],
        )
    except PolicyError as exc:
        # 引擎侧的语义校验错误统一转 422
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return EvaluateResponse(**result)


@app.get(
    "/api/v1/integrity/status",
    response_model=IntegrityStatusResponse,
    tags=["integrity"],
    summary="查询配置目录完整性状态",
)
def integrity_status() -> IntegrityStatusResponse:
    """返回 完整/异常/待复核/未知 及原因；异常时列出全部差异明细。

    - **完整**：文件集合与 SHA-256 摘要全部匹配，可继续部署；
    - **异常**：存在缺失/新增/内容改变/非普通文件/超限，响应中列出差异，应暂停部署；
    - **待复核**：收到变更通知，复核进行中，稍后再查；
    - **未知**：监视失效（队列溢出/目录被删除移动等），重建与复核完成前不下结论。
    """
    return IntegrityStatusResponse(**monitor.get_status())


@app.post(
    "/api/v1/integrity/recheck",
    response_model=IntegrityStatusResponse,
    tags=["integrity"],
    summary="立即触发一次全量复核",
)
def integrity_recheck() -> IntegrityStatusResponse:
    """不等变更通知，立即重新全量复核（进行中的复核结果作废，以最新为准）。"""
    monitor.request_recheck()
    return IntegrityStatusResponse(**monitor.get_status())
