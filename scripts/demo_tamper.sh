#!/usr/bin/env bash
# 配置目录完整性监测演示：本地篡改 -> 待复核 -> 异常；恢复 -> 完整。
#
# 前置：docker compose up --build -d（服务已在本机 8080 端口）
# 用法：scripts/demo_tamper.sh
# 可调环境变量：
#   BASE_URL                服务地址（默认 http://localhost:8080）
#   WAIT                    每次篡改后等待复核的秒数（默认 2，需大于 INTEGRITY_RECHECK_DELAY）
#   INTEGRITY_RECHECK_DELAY 复核延迟本身在 docker-compose.yml 中配置（默认 1.0 秒）
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
WAIT="${WAIT:-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "${SCRIPT_DIR}/../deploy/config" && pwd)"
BACKUP_DIR="$(mktemp -d)"

cleanup() {
    # 无论演示是否成功，都把配置目录恢复原样
    cp -a "${BACKUP_DIR}/." "${CONFIG_DIR}/" 2>/dev/null || true
    rm -rf "${BACKUP_DIR}"
}
trap cleanup EXIT
cp -a "${CONFIG_DIR}/." "${BACKUP_DIR}/"

show() {  # 打印当前完整性状态
    curl -fsS "${BASE_URL}/api/v1/integrity/status" | python3 -m json.tool --no-ensure-ascii 2>/dev/null \
        || curl -fsS "${BASE_URL}/api/v1/integrity/status"
    echo
}

field() { # 从状态 JSON 中提取字段
    curl -fsS "${BASE_URL}/api/v1/integrity/status" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"
}

echo "==================================================================="
echo " 配置目录完整性监测演示（被监视目录：${CONFIG_DIR}）"
echo " 复核延迟由 INTEGRITY_RECHECK_DELAY 控制（compose 默认 1.0 秒）"
echo "==================================================================="

echo ">>> [0] 初始状态（预期：完整 intact）"
show

echo ">>> [1] 原地写入篡改：向 app.conf 追加恶意配置"
echo "malicious_option = 1" >> "${CONFIG_DIR}/app.conf"
sleep 0.2   # 小于复核延迟，应能观察到“待复核”
echo "    变更后立即查询（预期：待复核 pending）：status=$(field status)"
sleep "${WAIT}"
echo "    复核完成后（预期：异常 anomaly，差异类型 modified）："
show

echo ">>> [2] 替换式篡改：写临时文件后 mv 原子替换 logging.conf"
printf '# hacked\n[loggers]\nkeys=root\n' > "${CONFIG_DIR}/.logging.conf.new"
mv -f "${CONFIG_DIR}/.logging.conf.new" "${CONFIG_DIR}/logging.conf"
sleep "${WAIT}"
echo "    复核完成后（预期：异常 anomaly，差异类型 modified）："
show

echo ">>> [3] 新增清单外文件：放入后门配置 backdoor.conf"
printf 'backdoor = on\n' > "${CONFIG_DIR}/backdoor.conf"
sleep "${WAIT}"
echo "    复核完成后（预期：异常 anomaly，差异类型 added）："
show

echo ">>> [4] 删除文件后恢复全部原始配置"
rm -f "${CONFIG_DIR}/backdoor.conf"
cp -a "${BACKUP_DIR}/." "${CONFIG_DIR}/"
sleep "${WAIT}"
echo "    复核完成后（预期：完整 intact）："
show

echo "==================================================================="
echo " 演示结束：配置目录已恢复原样，监测状态回到“完整”。"
echo " 提示：INTEGRITY_RECHECK_DELAY=5 docker compose up -d 可放慢复核，"
echo "       便于在 /docs 页面观察“待复核”中间状态。"
echo "==================================================================="
