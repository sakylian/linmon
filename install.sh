#!/bin/bash
# ============================================================
# linmon 命令安装脚本
# 创建全局命令 linmon / linmon-web，指向当前项目目录
# 用法:
#   ./install.sh           # 安装全局命令（需 sudo）
#   ./install.sh --user    # 用户级安装到 ~/.local/bin（无需 sudo）
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

# 解析项目真实路径（处理软链接情况）
if command -v realpath >/dev/null 2>&1; then
    PROJECT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
else
    PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

# 安装模式
USER_INSTALL=false
for arg in "$@"; do
    case "$arg" in
        --user) USER_INSTALL=true ;;
        -h|--help)
            echo "用法: ./install.sh [--user]"
            echo "  无参数    安装到 /usr/local/bin（需 sudo）"
            echo "  --user    安装到 ~/.local/bin（无需 sudo）"
            exit 0 ;;
    esac
done

# 创建 linmon-web 启动脚本（如果不存在）
LINMON_WEB="$PROJECT_DIR/linmon-web"
if [ ! -f "$LINMON_WEB" ]; then
    cat > "$LINMON_WEB" <<EOF
#!/bin/bash
# linmon-web 命令包装脚本
if command -v realpath >/dev/null 2>&1; then
    SCRIPT_PATH="\$(realpath "\$0")"
else
    SCRIPT_PATH="\$(cd "\$(dirname "\$0")" && pwd)/\$(basename "\$0")"
fi
SCRIPT_DIR="\$(dirname "\$SCRIPT_PATH")"

if [ -f "\$SCRIPT_DIR/venv/bin/python3" ]; then
    exec "\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/webserver.py" "\$@"
else
    exec python3 "\$SCRIPT_DIR/webserver.py" "\$@"
EOF
    chmod +x "$LINMON_WEB"
    info "已生成 linmon-web 启动脚本"
fi

echo ""
echo "============================================================"
echo "  linmon 命令安装"
echo "  项目目录: $PROJECT_DIR"
if [ "$USER_INSTALL" = true ]; then
    echo "  安装模式:  用户级 (~/.local/bin)"
else
    echo "  安装模式:  系统级 (/usr/local/bin)"
fi
echo "============================================================"
echo ""

# 安装
if [ "$USER_INSTALL" = true ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$PROJECT_DIR/linmon" "$HOME/.local/bin/linmon"
    ln -sf "$LINMON_WEB" "$HOME/.local/bin/linmon-web"
    info "已创建: ~/.local/bin/linmon → $PROJECT_DIR/linmon"
    info "已创建: ~/.local/bin/linmon-web → $LINMON_WEB"

    # 检查 PATH
    case ":$PATH:" in
        *":$HOME/.local/bin:"*)
            info "PATH 已包含 ~/.local/bin" ;;
        *)
            echo -e "${YELLOW}[!]${NC} 请将 ~/.local/bin 加入 PATH："
            echo "    echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc"
            echo "    source ~/.bashrc" ;;
    esac
else
    if [ "$EUID" -ne 0 ]; then
        error "系统级安装需要 sudo，请执行: sudo ./install.sh"
        exit 1
    fi
    ln -sf "$PROJECT_DIR/linmon" /usr/local/bin/linmon
    ln -sf "$LINMON_WEB" /usr/local/bin/linmon-web
    info "已创建: /usr/local/bin/linmon → $PROJECT_DIR/linmon"
    info "已创建: /usr/local/bin/linmon-web → $LINMON_WEB"
fi

# 验证
echo ""
if command -v linmon &>/dev/null; then
    info "验证: $(which linmon)"
else
    echo -e "${YELLOW}[!]${NC} 命令暂未生效，请重新打开终端或执行 source ~/.bashrc"
fi

echo ""
echo "现在可以直接使用："
echo "  linmon proc              # 进程监控"
echo "  linmon net               # 网络连接监控"
echo "  linmon diag              # 系统全面诊断"
echo "  linmon trace 8.8.8.8     # 路由跟踪"
echo "  linmon-web               # 启动 Web 监控面板"
echo ""
