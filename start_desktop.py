#!/usr/bin/env python3
"""
安全报告生成器 - 桌面版启动脚本
自动启动 Flask 后端 + Electron 前端
"""

import subprocess
import sys
import os
import time
import socket
import signal

# 项目根目录
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT_DIR)

# 配置
FLASK_PORT = 53789
FLASK_HOST = '127.0.0.1'


def is_port_available(port):
    """检查端口是否可用"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((FLASK_HOST, port))
            return True
    except OSError:
        return False


def find_available_port(start=53789):
    """查找可用端口"""
    port = start
    while port < start + 100:
        if is_port_available(port):
            return port
        port += 1
    raise RuntimeError("无法找到可用端口")


def check_node():
    """检查 Node.js 是否安装"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  ✅ Node.js: {version}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print("  ❌ Node.js 未安装")
    return False


def check_npm():
    """检查 npm 是否安装"""
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  ✅ npm: {version}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print("  ❌ npm 未安装")
    return False


def check_python():
    """检查 Python 是否安装"""
    try:
        result = subprocess.run([sys.executable, '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  ✅ Python: {version}")
            return True
    except Exception:
        pass
    print("  ❌ Python 未安装")
    return False


def check_flask_deps():
    """检查 Flask 依赖是否安装"""
    try:
        import flask
        print(f"  ✅ Flask: {flask.__version__}")
        return True
    except ImportError:
        print("  ❌ Flask 未安装")
        return False


def check_electron_deps():
    """检查 Electron 依赖是否安装"""
    node_modules = os.path.join(ROOT_DIR, 'node_modules', 'electron')
    if os.path.exists(node_modules):
        print("  ✅ Electron: 已安装")
        return True
    print("  ❌ Electron 未安装 (运行 npm install)")
    return False


def install_python_deps():
    """安装 Python 依赖"""
    print("\n📦 安装 Python 依赖...")
    req_file = os.path.join(ROOT_DIR, 'requirements.txt')
    if os.path.exists(req_file):
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', req_file],
                       capture_output=True)
        print("  ✅ Python 依赖安装完成")
    else:
        print("  ❌ 未找到 requirements.txt")


def install_electron_deps():
    """安装 Electron 依赖"""
    print("\n📦 安装 Electron 依赖...")
    subprocess.run(['npm', 'install'], cwd=ROOT_DIR, capture_output=True, shell=True)
    print("  ✅ Electron 依赖安装完成")


def main():
    print("=" * 50)
    print("  🔒 安全报告生成器 - 桌面版启动器")
    print("=" * 50)

    # 环境检查
    print("\n🔍 环境检查:")
    python_ok = check_python()
    flask_ok = check_flask_deps() if python_ok else False
    node_ok = check_node()
    npm_ok = check_npm() if node_ok else False
    electron_ok = check_electron_deps() if npm_ok else False

    if not python_ok or not node_ok:
        print("\n❌ 缺少必要环境:")
        if not python_ok:
            print("   请安装 Python 3.8+: https://www.python.org/downloads/")
        if not node_ok:
            print("   请安装 Node.js 18+: https://nodejs.org/")
        print("\n按回车键退出...")
        input()
        return

    # 自动安装缺失依赖
    if not flask_ok:
        install_python_deps()
    if not electron_ok:
        install_electron_deps()

    # 查找可用端口
    port = find_available_port(FLASK_PORT)
    os.environ['FLASK_PORT'] = str(port)
    os.environ['FLASK_HOST'] = FLASK_HOST
    os.environ['FLASK_DEBUG'] = 'false'

    print(f"\n🚀 启动桌面应用 (端口: {port})...")
    print("   首次启动可能需要几秒钟...\n")

    # 启动 Electron（它会自动管理 Flask 进程）
    try:
        if sys.platform == 'win32':
            subprocess.run(['npx', 'electron', '.'], cwd=ROOT_DIR, shell=True)
        else:
            subprocess.run(['npx', 'electron', '.'], cwd=ROOT_DIR)
    except KeyboardInterrupt:
        print("\n\n👋 应用已退出")
    except FileNotFoundError:
        print("\n❌ 启动失败: 无法找到 electron")
        print("   请运行: npm install")
        print("\n按回车键退出...")
        input()


if __name__ == '__main__':
    main()
