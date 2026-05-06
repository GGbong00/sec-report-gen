@echo off
chcp 65001 >nul
echo ========================================
echo   打包 Python 依赖到 python_libs 目录
echo ========================================

set LIB_DIR=%~dp0python_libs

:: 清理旧目录
if exist "%LIB_DIR%" rmdir /s /q "%LIB_DIR%"
mkdir "%LIB_DIR%"

:: 获取当前 Python 的 site-packages 路径
for /f "delims=" %%i in ('python -c "import site; print(site.getsitepackages()[0])"') do set SITE_PKG=%%i

echo [1/3] 复制 site-packages 到 python_libs ...
xcopy "%SITE_PKG%" "%LIB_DIR%" /E /I /Q /Y >nul 2>&1

echo [2/3] 清理不需要的文件 ...
:: 删除缓存和编译文件
del /s /q "%LIB_DIR%\__pycache__\*" 2>nul
del /s /q "%LIB_DIR%\*.pyc" 2>nul
rmdir /s /q "%LIB_DIR%\__pycache__" 2>nul
for /d %%d in ("%LIB_DIR%\*.dist-info") do rmdir /s /q "%%d" 2>nul
:: 删除测试文件（节省空间）
for /d %%d in ("%LIB_DIR%\tests") do rmdir /s /q "%%d" 2>nul
for /d %%d in ("%LIB_DIR%\test") do rmdir /s /q "%%d" 2>nul
del /s /q "%LIB_DIR%\*.exe" 2>nul

echo [3/3] 完成!
echo.
echo 打包大小:
for /f "tokens=3" %%a in ('dir /s "%LIB_DIR%" ^| findstr "个文件"') do echo   %%a 字节
echo.
echo 现在可以运行 npm run build:win 打包 exe
pause
