"""
Nmap XML 报告解析器

解析 Nmap 扫描工具生成的 XML 格式报告，提取主机、端口、服务和脚本信息。
"""

import logging
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from . import BaseParser

logger = logging.getLogger(__name__)


class NmapParser(BaseParser):
    """Nmap XML 报告解析器"""

    # Nmap 端口状态到标准严重程度的映射
    SEVERITY_MAP = {
        'open': 'info',
        'filtered': 'low',
        'open|filtered': 'medium',
        'closed': 'info',
        'closed|filtered': 'low',
    }

    def parse(self, file_path: str) -> List[Dict]:
        """
        解析 Nmap XML 报告文件。

        Args:
            file_path: Nmap XML 报告文件路径

        Returns:
            漏洞字典列表
        """
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"解析 Nmap XML 文件失败 (XML格式错误): {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Nmap XML 文件不存在: {file_path}")
            return []
        except Exception as e:
            logger.error(f"解析 Nmap XML 文件时发生未知错误: {e}")
            return []

        try:
            # 查找所有 host 节点
            hosts = root.findall('.//host')
            if not hosts:
                # 尝试直接在根节点下查找
                if root.tag == 'host':
                    hosts = [root]
                else:
                    logger.warning("Nmap XML 中未找到 host 节点")
                    return []

            for host in hosts:
                host_vulns = self._parse_host(host)
                vulnerabilities.extend(host_vulns)

        except Exception as e:
            logger.error(f"解析 Nmap host 节点时发生错误: {e}")
            return []

        logger.info(f"Nmap 解析完成，共提取 {len(vulnerabilities)} 条记录")
        return vulnerabilities

    def _parse_host(self, host_node) -> List[Dict]:
        """
        解析单个 host 节点。

        Args:
            host_node: XML host 节点

        Returns:
            该主机相关的漏洞/发现列表
        """
        results = []

        # 提取主机名
        hostnames = []
        hostnames_node = host_node.find('hostnames')
        if hostnames_node is not None:
            for hostname_node in hostnames_node.findall('hostname'):
                name = hostname_node.get('name', '').strip()
                if name and name != '':
                    hostnames.append(name)

        # 提取 IP 地址
        ip_address = ''
        status_reason = ''
        for addr_node in host_node.findall('address'):
            addr_type = addr_node.get('addrtype', '')
            if addr_type == 'ipv4' or addr_type == 'ipv6':
                ip_address = addr_node.get('addr', '')

        # 如果没有找到 IP，取第一个 address
        if not ip_address:
            first_addr = host_node.find('address')
            if first_addr is not None:
                ip_address = first_addr.get('addr', '')

        # 提取主机状态
        status_node = host_node.find('status')
        host_state = ''
        if status_node is not None:
            host_state = status_node.get('state', '')
            status_reason = status_node.get('reason', '')

        # 主机名显示文本
        hostname_display = ', '.join(hostnames) if hostnames else ip_address

        # 提取操作系统信息
        os_info = ''
        os_node = host_node.find('os')
        if os_node is not None:
            osmatch_nodes = os_node.findall('osmatch')
            if osmatch_nodes:
                os_name = osmatch_nodes[0].get('name', '')
                os_accuracy = osmatch_nodes[0].get('accuracy', '')
                os_info = f"{os_name} (accuracy: {os_accuracy}%)"

        # 解析端口信息
        ports_node = host_node.find('ports')
        if ports_node is not None:
            for port_node in ports_node.findall('port'):
                port_results = self._parse_port(port_node, ip_address, hostname_display, os_info)
                results.extend(port_results)

        # 如果没有端口信息但有主机信息，记录主机发现
        if not results and (ip_address or hostnames):
            results.append({
                'title': f"Host Discovery: {hostname_display}",
                'severity': 'info',
                'host': ip_address,
                'port': '',
                'protocol': '',
                'url': '',
                'description': f"主机状态: {host_state}" + (f", 原因: {status_reason}" if status_reason else ""),
                'solution': '',
                'cve': '',
                'extra': {
                    'scanner': 'nmap',
                    'hostnames': hostnames,
                    'os_info': os_info,
                    'state': host_state,
                },
            })

        return results

    def _parse_port(self, port_node, ip_address: str, hostname_display: str, os_info: str) -> List[Dict]:
        """
        解析单个端口节点。

        Args:
            port_node: XML port 节点
            ip_address: 主机 IP 地址
            hostname_display: 主机名显示文本
            os_info: 操作系统信息

        Returns:
            该端口相关的发现列表
        """
        results = []

        port_id = port_node.get('portid', '')
        protocol = port_node.get('protocol', '')

        # 解析端口状态
        state_node = port_node.find('state')
        state = ''
        state_reason = ''
        if state_node is not None:
            state = state_node.get('state', '')
            state_reason = state_node.get('reason', '')

        # 解析服务信息
        service_name = ''
        service_product = ''
        service_version = ''
        service_extrainfo = ''
        service_fp = ''
        service_node = port_node.find('service')
        if service_node is not None:
            service_name = service_node.get('name', '')
            service_product = service_node.get('product', '')
            service_version = service_node.get('version', '')
            service_extrainfo = service_node.get('extrainfo', '')
            service_fp = service_node.get('servicefp', '')

        # 构建服务描述
        service_desc_parts = []
        if service_name:
            service_desc_parts.append(service_name)
        if service_product:
            service_desc_parts.append(service_product)
        if service_version:
            service_desc_parts.append(service_version)
        if service_extrainfo:
            service_desc_parts.append(service_extrainfo)
        service_desc = ' '.join(service_desc_parts) if service_desc_parts else 'unknown'

        # 映射严重程度
        severity = self.SEVERITY_MAP.get(state, 'info')

        # 构建描述
        description_parts = [f"端口 {port_id}/{protocol} 状态: {state}"]
        if state_reason:
            description_parts.append(f"({state_reason})")
        if service_name:
            description_parts.append(f"\n服务: {service_desc}")
        if os_info:
            description_parts.append(f"\n操作系统: {os_info}")
        description = ''.join(description_parts)

        # 构建标题
        title_parts = [f"Port {port_id}/{protocol}"]
        if service_name:
            title_parts.append(f" - {service_name}")
        if state != 'open':
            title_parts.append(f" [{state}]")
        title = ''.join(title_parts)

        # 基本端口发现记录
        vuln = {
            'title': title,
            'severity': severity,
            'host': ip_address,
            'port': port_id,
            'protocol': protocol,
            'url': '',
            'description': description,
            'solution': '',
            'cve': '',
            'extra': {
                'scanner': 'nmap',
                'hostname': hostname_display,
                'state': state,
                'state_reason': state_reason,
                'service_name': service_name,
                'service_product': service_product,
                'service_version': service_version,
                'service_extrainfo': service_extrainfo,
                'os_info': os_info,
            },
        }
        results.append(vuln)

        # 解析脚本输出（NSE scripts）
        script_nodes = port_node.findall('script')
        for script_node in script_nodes:
            script_result = self._parse_script(
                script_node, ip_address, hostname_display,
                port_id, protocol, service_name
            )
            if script_result:
                results.append(script_result)

        return results

    def _parse_script(self, script_node, ip_address: str, hostname_display: str,
                      port_id: str, protocol: str, service_name: str) -> Optional[Dict]:
        """
        解析 NSE 脚本输出节点。

        Args:
            script_node: XML script 节点
            ip_address: 主机 IP 地址
            hostname_display: 主机名
            port_id: 端口号
            protocol: 协议
            service_name: 服务名称

        Returns:
            漏洞字典，解析失败返回 None
        """
        script_id = script_node.get('id', '')
        script_output = script_node.get('output', '').strip()

        if not script_id and not script_output:
            return None

        # 根据脚本 ID 判断严重程度
        severity = 'info'
        script_id_lower = script_id.lower()
        if any(kw in script_id_lower for kw in ['vuln', 'exploit', 'exploitable', 'auth', 'brute']):
            severity = 'high'
        elif any(kw in script_id_lower for kw in ['auth-bypass', 'backdoor', 'malware', 'rootkit']):
            severity = 'critical'
        elif any(kw in script_id_lower for kw in ['banner', 'info', 'finger', 'dns', 'whois']):
            severity = 'info'
        elif any(kw in script_id_lower for kw in ['ssl', 'tls', 'cert']):
            severity = 'medium'
        elif any(kw in script_id_lower for kw in ['http', 'web', 'cgi']):
            severity = 'medium'

        # 构建标题
        title = f"NSE Script: {script_id}" if script_id else "NSE Script Output"
        if service_name:
            title += f" ({service_name})"

        # 构建描述
        description_parts = []
        if port_id:
            description_parts.append(f"端口: {port_id}/{protocol}")
        if service_name:
            description_parts.append(f"服务: {service_name}")
        if script_id:
            description_parts.append(f"脚本: {script_id}")
        description_parts.append(f"\n输出:\n{script_output}")
        description = '\n'.join(description_parts)

        return {
            'title': title,
            'severity': severity,
            'host': ip_address,
            'port': port_id,
            'protocol': protocol,
            'url': '',
            'description': description,
            'solution': '',
            'cve': '',
            'extra': {
                'scanner': 'nmap',
                'hostname': hostname_display,
                'script_id': script_id,
                'script_output': script_output,
                'service_name': service_name,
            },
        }
