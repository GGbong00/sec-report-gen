"""
路由蓝图包。

导出所有蓝图供应用工厂注册使用。
"""

from app.routes.main import main_bp
from app.routes.import_route import import_bp
from app.routes.vuln import vuln_bp
from app.routes.report import report_bp
from app.routes.settings import settings_bp
from app.routes.log import log_bp

__all__ = [
    'main_bp',
    'import_bp',
    'vuln_bp',
    'report_bp',
    'settings_bp',
    'log_bp',
]
