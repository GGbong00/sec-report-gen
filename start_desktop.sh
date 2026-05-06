#!/bin/bash
# 安全报告生成器 - 桌面版启动脚本 (macOS/Linux)

set -e

echo "============================================================"
echo "  🔒 安全报告生成器 - 桌面版启动器"
echo "============================================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查 Python
echo -n "检查 Python... "
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
    echo -e "${GREEN}✅ $(python3 --version)${NC}"
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
    echo -e "${GREEN}✅ $(python --version)${NC}"
else
    echo -e "${RED}❌ 未安装 Python${NC}"
    echo "请安装 Python 3.8+: https://www.python.org/downloads/"
    exit 1
fi

# 检查 Node.js
echo -n "检查 Node.js... "
if command -v node &> /dev/null; then
    echo -e "${GREEN}✅ $(node --version)${NC}"
else
    echo -e "${RED}❌ 未安装 Node.js${NC}"
    echo "请安装 Node.js 18+: https://nodejs.org/"
    exit 1
fi

# 检查 npm
echo -n "检查 npm... "
if command -v npm &> /dev/null; then
    echo -e "${GREEN}✅ $(npm --version)${NC}"
else
    echo -e "${RED}❌ 未安装 npm${NC}"
    exit 1
fi

# 检查 Python 依赖
echo ""
echo -n "检查 Flask... "
if $PYTHON_CMD -c "import flask" 2> /dev/null; then
    echo -e "${GREEN}✅ 已安装${NC}"
else
    echo -e "${YELLOW}⏳ 安装中...${NC}"
    $PYTHON_CMD -m pip install -r requirements.txt --break-system-packages 2> /dev/null || \
    $PYTHON_CMD -m pip install -r requirements.txt
    echo -e "${GREEN}✅ 安装完成${NC}"
fi

# 检查 Electron 依赖
echo -n "检查 Electron... "
if [ -d "node_modules/electron" ]; then
    echo -e "${GREEN}✅ 已安装${NC}"
else
    echo -e "${YELLOW}⏳ 安装中（首次可能需要几分钟）...${NC}"
    npm install
    echo -e "${GREEN}✅ 安装完成${NC}"
fi

# 启动应用
echo ""
echo "🚀 启动桌面应用..."
echo ""
npx electron .
