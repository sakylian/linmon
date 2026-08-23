#!/bin/bash
# ============================================================
# linmon 一键部署脚本
# 支持 Debian 系 (Ubuntu/Debian/LinuxMint) 和 CentOS 系 (RHEL/CentOS/Rocky/AlmaLinux)
# 用法:
#   sudo ./deploy.sh           # 安装到 /opt/linmon
#   sudo ./deploy.sh /custom   # 安装到自定义目录
#   ./deploy.sh --user         # 用户级安装 (~/linmon, 无需 sudo)
# ============================================================

set -e

# ---------- 颜色 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "${CYAN}>>> $1${NC}"; }

# ---------- 变量 ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_MIN="3.8"

# pip 国内镜像
PIP_INDEX="https://pypi.tuna.tsinghua.edu.cn/simple"
PIP_TRUSTED="pypi.tuna.tsinghua.edu.cn"

# 解析参数
INSTALL_DIR="/opt/linmon"
USER_INSTALL=false

for arg in "$@"; do
    case "$arg" in
        --user)  USER_INSTALL=true; INSTALL_DIR="$HOME/linmon" ;;
        -h|--help)
            echo "用法: sudo ./deploy.sh [安装目录|--user]"
            echo "  无参数      安装到 /opt/linmon (系统级, 需 sudo)"
            echo "  /custom     安装到指定目录"
            echo "  --user      用户级安装到 ~/linmon (无需 sudo)"
            exit 0 ;;
        /*)  INSTALL_DIR="$arg" ;;
        *)  warn "忽略未知参数: $arg" ;;
    esac
done

# ---------- 检测发行版 ----------
detect_distro() {
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "macos"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)

# ---------- 检测包管理器 ----------
if [ "$DISTRO" = "macos" ]; then
    if command -v brew &>/dev/null; then
        PKG_MGR="brew"
    else
        error "macOS 需要 Homebrew 安装系统依赖，请先安装: https://brew.sh"
        # 允许跳过，后续 python3 已存在则继续
        PKG_MGR="brew"
    fi
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    error "未检测到支持的包管理器 (apt/dnf/yum/pacman/brew)"
    exit 1
fi

echo ""
echo "============================================================"
echo "  linmon 一键部署"
if [ "$DISTRO" = "macos" ]; then
    echo "  系统:     macOS ($(sw_vers -productVersion 2>/dev/null || echo '未知'))"
else
    echo "  发行版:  $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "$DISTRO")"
fi
echo "  包管理:  $PKG_MGR"
echo "  安装目录: $INSTALL_DIR"
echo "============================================================"
echo ""

# ---------- Step 1: 检查权限 ----------
step "1/7 检查权限"
if [ "$USER_INSTALL" = false ] && [ "$EUID" -ne 0 ]; then
    warn "系统级安装需要 root 权限, 切换到用户级安装"
    USER_INSTALL=true
    INSTALL_DIR="$HOME/linmon"
    info "安装目录改为: $INSTALL_DIR"
fi
if [ "$USER_INSTALL" = false ]; then
    info "root 权限确认"
else
    info "用户级安装模式"
fi

# ---------- Step 2: 安装系统依赖 ----------
step "2/7 安装系统依赖 (iproute2/traceroute/python3)"

SYS_PKGS=""
case "$PKG_MGR" in
    brew)
        # macOS: traceroute 系统自带；tcpdump 需安装或使用自带；netstat/route 自带
        SYS_PKGS="python3 traceroute tcpdump"
        ;;
    apt-get)
        SYS_PKGS="python3 python3-pip iproute2 traceroute net-tools"
        $PKG_MGR update -qq 2>/dev/null || true
        ;;
    dnf|yum)
        SYS_PKGS="python3 python3-pip iproute traceroute net-tools"
        ;;
    pacman)
        SYS_PKGS="python python-pip iproute2 traceroute net-tools"
        ;;
esac

# 用户级安装不做 apt install (无权限), 只检查是否已有
if [ "$USER_INSTALL" = true ]; then
    MISSING=""
    for pkg_check in python3 traceroute; do
        command -v $pkg_check &>/dev/null || MISSING="$MISSING $pkg_check"
    done
    # macOS 没有 ss 命令，改查 netstat；Linux 查 ss
    if [ "$DISTRO" = "macos" ]; then
        command -v netstat &>/dev/null || MISSING="$MISSING netstat"
    else
        command -v ss &>/dev/null || MISSING="$MISSING ss"
    fi
    if [ -n "$MISSING" ]; then
        warn "缺少系统命令:$MISSING, 请联系管理员安装: $PKG_MGR install$MISSING"
    else
        info "系统依赖已就绪"
    fi
else
    if ! $PKG_MGR install -y $SYS_PKGS 2>/dev/null; then
        warn "部分系统包安装失败, 尝试逐个安装..."
        for pkg in $SYS_PKGS; do
            $PKG_MGR install -y "$pkg" 2>/dev/null && info "已安装 $pkg" || warn "安装 $pkg 失败 (可跳过)"
        done
    else
        info "系统依赖安装完成"
    fi
fi

# ---------- Step 3: 检查 Python ----------
step "3/7 检查 Python 版本"

if command -v python3 &>/dev/null; then
    PY_BIN=$(command -v python3)
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
        info "Python $PY_VER ($PY_BIN)"
    else
        error "Python $PY_VER 版本过低, 需要 >= $PYTHON_MIN"
        exit 1
    fi
else
    error "未找到 python3, 请先安装: $PKG_MGR install python3"
    exit 1
fi

# ---------- Step 4: 创建虚拟环境 ----------
step "4/7 创建 Python 虚拟环境"

VENV_DIR="$INSTALL_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    info "虚拟环境已存在, 跳过创建"
else
    if ! $PY_BIN -m venv "$VENV_DIR" 2>/dev/null; then
        warn "venv 模块不可用, 尝试安装 python3-venv..."
        if [ "$USER_INSTALL" = false ]; then
            case "$PKG_MGR" in
                apt-get) $PKG_MGR install -y python3-venv 2>/dev/null || true ;;
                dnf|yum) $PKG_MGR install -y python3-virtualenv 2>/dev/null || true ;;
            esac
        fi
        if ! $PY_BIN -m venv "$VENV_DIR"; then
            warn "venv 创建失败, 将使用系统 Python 直接安装"
            VENV_DIR=""
        fi
    fi
    [ -n "$VENV_DIR" ] && info "虚拟环境创建完成: $VENV_DIR"
fi

# 确定 pip 路径
if [ -n "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/pip" ]; then
    PIP_BIN="$VENV_DIR/bin/pip"
    PY_RUN="$VENV_DIR/bin/python3"
else
    PIP_BIN="pip3"
    PY_RUN="python3"
fi

# ---------- Step 5: 安装 Python 依赖 ----------
step "5/7 安装 Python 依赖 (国内镜像加速)"

# 升级 pip
$PIP_BIN install --upgrade pip \
    -i "$PIP_INDEX" --trusted-host "$PIP_TRUSTED" \
    -q 2>/dev/null && info "pip 已升级" || warn "pip 升级失败 (不影响安装)"

# 安装项目依赖
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    if $PIP_BIN install -r "$SCRIPT_DIR/requirements.txt" \
        -i "$PIP_INDEX" --trusted-host "$PIP_TRUSTED"; then
        info "Python 依赖安装完成"
    else
        error "Python 依赖安装失败"
        exit 1
    fi
else
    $PIP_BIN install psutil flask \
        -i "$PIP_INDEX" --trusted-host "$PIP_TRUSTED" \
        && info "Python 依赖安装完成" \
        || { error "Python 依赖安装失败"; exit 1; }
fi

# ---------- Step 6: 部署项目文件 ----------
step "6/7 部署项目文件"

# 如果脚本就在项目目录里, 直接复制; 否则提示
if [ "$SCRIPT_DIR" = "$INSTALL_DIR" ]; then
    info "安装目录与源目录相同, 跳过复制"
else
    mkdir -p "$INSTALL_DIR"

    # 复制核心文件
    cp -r "$SCRIPT_DIR"/linmon.py "$INSTALL_DIR"/
    cp -r "$SCRIPT_DIR"/webserver.py "$INSTALL_DIR"/
    cp -r "$SCRIPT_DIR"/requirements.txt "$INSTALL_DIR"/ 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/modules "$INSTALL_DIR"/ 2>/dev/null || warn "modules 目录未找到"
    cp -r "$SCRIPT_DIR"/templates "$INSTALL_DIR"/ 2>/dev/null || warn "templates 目录未找到"

    # 数据文件
    if [ -d "$SCRIPT_DIR/data" ]; then
        cp -r "$SCRIPT_DIR/data" "$INSTALL_DIR/"
        # qqwry.dat 为第三方授权数据(纯真IP库)，不随项目再分发；若本地存在则一并复制，
        # 但部署包不应包含它，需使用者自行获取授权后放置于 <INSTALL_DIR>/data/qqwry.dat
        if [ -f "$INSTALL_DIR/data/qqwry.dat" ]; then
            warn "已复制本地 qqwry.dat（第三方授权数据，分发给他人前请确认已获纯真IP库授权）"
        else
            warn "未包含 qqwry.dat：IP归属地查询将不可用（请自行获取授权后放置于 $INSTALL_DIR/data/qqwry.dat）"
        fi
        info "数据文件已复制 (echarts/world.json)"
    else
        warn "data/ 目录未找到, IP归属地等功能将不可用"
    fi

    # AI 配置
    if [ -d "$SCRIPT_DIR/config" ]; then
        cp -r "$SCRIPT_DIR/config" "$INSTALL_DIR/"
    else
        mkdir -p "$INSTALL_DIR/config"
        cat > "$INSTALL_DIR/config/ai_config.json" <<'CONF'
{
    "endpoint": "https://ai.ctaigw.cn/v1/chat/completions",
    "model_name": "glm-5.3",
    "model_id": "e8e2511658054053a7e56e950d80f0e4",
    "app_id": "",
    "app_key": "",
    "max_tokens": 8192,
    "temperature": 0.3,
    "timeout": 60,
    "enabled": false,
    "allow_external_ai": true,
    "redact_sensitive": true,
    "send_internal_ips": false,
    "send_listening_ports": false,
    "geo_risk_enabled": false,
    "high_risk_regions": []
}
CONF
    fi
    # Web 面板配置（默认仅本机监听 + 令牌鉴权，令牌启动时自动生成）
    cat > "$INSTALL_DIR/config/web_config.json" <<'CONF'
{
    "host": "127.0.0.1",
    "port": 8765,
    "auth_enabled": true,
    "auth_token": ""
}
CONF
    # 含密钥的配置文件限定为 0600
    chmod 600 "$INSTALL_DIR/config/ai_config.json" "$INSTALL_DIR/config/web_config.json" 2>/dev/null || true

    # 清理 __pycache__
    find "$INSTALL_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    info "项目文件已部署到: $INSTALL_DIR"
fi

# ---------- Step 7: 创建启动脚本 ----------
step "7/7 创建启动脚本"

LINMON_BIN="$INSTALL_DIR/linmon"
WEBMON_BIN="$INSTALL_DIR/linmon-web"

# linmon 命令行启动脚本
cat > "$LINMON_BIN" <<EOF
#!/bin/bash
# linmon CLI 启动脚本 (自动生成)
cd "$INSTALL_DIR"
if [ -f "$VENV_DIR/bin/python3" ]; then
    "$VENV_DIR/bin/python3" "$INSTALL_DIR/linmon.py" "\$@"
else
    python3 "$INSTALL_DIR/linmon.py" "\$@"
fi
EOF
chmod +x "$LINMON_BIN"

# web 启动脚本
cat > "$WEBMON_BIN" <<EOF
#!/bin/bash
# linmon Web 服务启动脚本 (自动生成)
cd "$INSTALL_DIR"
if [ -f "$VENV_DIR/bin/python3" ]; then
    "$VENV_DIR/bin/python3" "$INSTALL_DIR/webserver.py" "\$@"
else
    python3 "$INSTALL_DIR/webserver.py" "\$@"
fi
EOF
chmod +x "$WEBMON_BIN"

info "启动脚本已创建"

# ---------- Step 8: 安装 systemd 单元（仅系统级安装且存在 systemctl 时） ----------
if [ "$USER_INSTALL" = false ] && command -v systemctl &>/dev/null; then
    UNIT_SRC="$SCRIPT_DIR/systemd/linmon-web.service"
    if [ -f "$UNIT_SRC" ]; then
        UNIT_DST="/etc/systemd/system/linmon-web.service"
        sed -e "s#^WorkingDirectory=.*#WorkingDirectory=$INSTALL_DIR#" \
            -e "s#^ExecStart=.*#ExecStart=$INSTALL_DIR/linmon-web#" \
            "$UNIT_SRC" > "$UNIT_DST"
        systemctl daemon-reload 2>/dev/null || true
        info "已安装 systemd 单元: $UNIT_DST (systemctl start linmon-web 启动)"
        warn "请将 $UNIT_DST 的 User 改为专用低权限用户，并确认 web_config.json 已启用鉴权"
    fi
fi

# ---------- 创建符号链接 ----------
if [ "$USER_INSTALL" = false ]; then
    ln -sf "$LINMON_BIN" /usr/local/bin/linmon 2>/dev/null && info "全局命令已创建: linmon" || warn "创建 /usr/local/bin/linmon 失败"
    ln -sf "$WEBMON_BIN" /usr/local/bin/linmon-web 2>/dev/null && info "全局命令已创建: linmon-web" || true
else
    # 用户级: 加入 ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$LINMON_BIN" "$HOME/.local/bin/linmon" 2>/dev/null && info "用户命令已创建: ~/.local/bin/linmon" || true
    ln -sf "$WEBMON_BIN" "$HOME/.local/bin/linmon-web" 2>/dev/null || true

    # 提示 PATH
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) warn "建议将 ~/.local/bin 加入 PATH: echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc" ;;
    esac
fi

# ---------- 验证安装 ----------
echo ""
step "验证安装"

VERIFY_OK=true

# 验证 Python 导入
if cd "$INSTALL_DIR" && $PY_RUN -c "
import sys; sys.path.insert(0, '.')
from modules.proc_monitor import get_all_processes
from modules.net_monitor import get_all_connections
from modules.ai_analyzer import get_analyzer
from modules.sys_diag import generate_text_report
from modules.distro_helper import get_distro
from modules.geo_locator import find_qqwry_dat
print('模块导入: OK')
" 2>/dev/null; then
    info "模块验证通过"
else
    warn "模块导入验证失败, 请检查错误信息"
    VERIFY_OK=false
fi

# 验证 qqwry.dat
QQWRY=$(cd "$INSTALL_DIR" && $PY_RUN -c "
import sys; sys.path.insert(0, '.')
from modules.geo_locator import find_qqwry_dat
print(find_qqwry_dat() or '')
" 2>/dev/null)
if [ -n "$QQWRY" ]; then
    info "IP库: $QQWRY"
else
    warn "未找到 qqwry.dat, IP归属地查询不可用"
fi

# 快速冒烟测试
if [ "$VERIFY_OK" = true ]; then
    if $LINMON_BIN proc --no-network --no-schedule 2>/dev/null | grep -q "进程总数"; then
        info "冒烟测试通过"
    else
        warn "冒烟测试未通过 (可能需要 sudo 权限读取部分进程信息)"
    fi
fi

# ---------- 完成提示 ----------
echo ""
echo "============================================================"
echo -e "${GREEN}  linmon 部署完成!${NC}"
echo "============================================================"
echo ""
echo "  安装目录:  $INSTALL_DIR"
echo "  虚拟环境:  ${VENV_DIR:-无(使用系统Python)}"
echo ""
echo "  常用命令:"
echo "    linmon boot              # 查看开机信息"
echo "    linmon proc              # 进程监控"
echo "    linmon net               # 网络连接监控"
echo "    linmon proc --ai         # 进程监控 + AI分析"
echo "    linmon net --ai          # 网络监控 + AI分析"
echo "    linmon diag              # 系统全面诊断"
echo "    linmon diag --ai         # 诊断 + AI安全分析"
echo "    linmon trace 8.8.8.8     # 路由跟踪"
echo "    linmon-web               # 启动 Web 监控面板 (端口8765)"
echo "    linmon ai-config --show  # 查看 AI 配置"
echo ""
echo "  AI 配置 (可选):"
echo "    linmon ai-config --set app_key=你的AppKey"
echo "    linmon ai-config --enable"
echo "    linmon ai-config --test"
echo ""

if [ "$USER_INSTALL" = true ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) echo -e "${YELLOW}  提示: 请执行以下命令让 linmon 命令生效:${NC}"
           echo "    export PATH=\$HOME/.local/bin:\$PATH"
           echo "    (或加入 ~/.bashrc 永久生效)"
           echo "" ;;
    esac
fi

echo "  Web 面板启动后访问: http://localhost:8765"
echo ""
