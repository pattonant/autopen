#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import json
import time
import random
import logging
import traceback
import socket
import ssl
import argparse
from datetime import datetime
from colorama import init, Fore, Style
import requests
from bs4 import BeautifulSoup
import urllib3
import nmap
import dns.resolver
import aiodns
import asyncio
import aiohttp
from ftplib import FTP
import paramiko
import pymysql
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import OpenSSL

# 初始化colorama
init(autoreset=True)

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AutoPen:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {
            'basic_info': {},
            'vulnerabilities': [],
            'exploits': [],
            'ports': [],
            'directories': [],
            'subdomains': []
        }
        self.start_time = datetime.now()
        self.output = None
        self.target = None
        self.mode = None
        self.ports = None
        
    def print_banner(self):
        banner = """
        ╔═══════════════════════════════════════╗
        ║             AutoPen Tool              ║
        ║      自动化渗透测试工具 v2.0          ║
        ╚═══════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)

    def run(self, args):
        """运行主程序"""
        self.print_banner()
        
        if args.target:
            print(f"{Fore.YELLOW}[*] 目标URL: {args.target}{Style.RESET_ALL}")
            self.target = args.target
            self.mode = args.mode
            self.ports = args.ports
            
            # 基础信息收集
            if args.mode in ['all', 'info']:
                self.basic_info_gather()
            
            # 端口扫描
            if args.mode in ['all', 'port']:
                self.advanced_port_scan()
            
            # 目录扫描
            if args.mode in ['all', 'dir']:
                self.dir_scan()
            
            # 子域名枚举
            if args.mode in ['all', 'subdomain']:
                asyncio.run(self.subdomain_enum())
            
            # WAF检测
            if args.mode in ['all', 'waf']:
                self.waf_detect()
            
            # 漏洞扫描
            if args.mode in ['all', 'vuln']:
                self.vuln_scan()
            
            # 保存结果
            self.save_results()
            
        else:
            print(f"{Fore.RED}[-] 请提供目标URL{Style.RESET_ALL}")
            sys.exit(1)

    def advanced_port_scan(self):
        """高级端口扫描"""
        print(f"{Fore.YELLOW}[*] 开始端口扫描...{Style.RESET_ALL}")
        
        try:
            # 使用更快的扫描策略
            print(f"{Fore.YELLOW}[*] 扫描常用端口...{Style.RESET_ALL}")
            nm = nmap.PortScanner()
            
            # 1. 快速扫描最常见的端口
            common_ports = "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            nm.scan(self.target, ports=common_ports, arguments='-sS -sV -T4 --version-intensity 2')
            
            for host in nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] 主机: {host}{Style.RESET_ALL}")
                
                for proto in nm[host].all_protocols():
                    print(f"\n协议: {proto}")
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        version = nm[host][proto][port].get('version', '')
                        
                        print(f"{Fore.GREEN}[+] 端口 {port}/{proto}: {state}{Style.RESET_ALL}")
                        print(f"    服务: {service}")
                        if version:
                            print(f"    版本: {version}")
                            
                        # 保存结果
                        self.results.setdefault('ports', []).append({
                            'port': port,
                            'protocol': proto,
                            'state': state,
                            'service': service,
                            'version': version
                        })
            
            # 2. 快速UDP扫描
            print(f"\n{Fore.YELLOW}[*] 扫描常用UDP端口...{Style.RESET_ALL}")
            common_udp_ports = "53,67-68,69,123,161-162,500,514,520,1900,4500,5353"
            nm.scan(self.target, ports=common_udp_ports, arguments='-sU -T4 --version-intensity 2')
            
            for host in nm.all_hosts():
                if 'udp' in nm[host].all_protocols():
                    for port in nm[host]['udp'].keys():
                        state = nm[host]['udp'][port]['state']
                        service = nm[host]['udp'][port]['name']
                        
                        if state == 'open':
                            print(f"{Fore.GREEN}[+] UDP端口 {port}: {service}{Style.RESET_ALL}")
                            self.results.setdefault('udp_ports', []).append({
                                'port': port,
                                'service': service
                            })
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] 端口扫描出错: {str(e)}{Style.RESET_ALL}")
            return False

    def vuln_scan(self):
        """漏洞扫描功能"""
        print(f"{Fore.YELLOW}[*] 开始漏洞扫描...{Style.RESET_ALL}")
        
        try:
            # 1. SQL注入检测
            print(f"{Fore.YELLOW}[*] 检测SQL注入漏洞...{Style.RESET_ALL}")
            sql_payloads = [
                "' OR '1'='1",
                "' OR 1=1 -- -",
                "admin' -- -",
                "1' OR '1'='1",
                "1 UNION SELECT null,null,null-- -"
            ]
            
            # 检查URL参数
            parsed_url = urlparse(self.target)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param, value in params.items():
                    for payload in sql_payloads:
                        test_url = self.target.replace(f"{param}={value[0]}", f"{param}={payload}")
                        try:
                            response = requests.get(test_url, headers=self.headers, verify=False, timeout=10)
                            if any(keyword in response.text.lower() for keyword in ['sql', 'mysql', 'error', 'syntax']):
                                print(f"{Fore.RED}[!] 可能存在SQL注入: {test_url}{Style.RESET_ALL}")
                                self.results['vulnerabilities'].append({
                                    'type': 'SQL注入',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'severity': '高危'
                                })
                        except:
                            continue

            # 2. XSS检测
            print(f"{Fore.YELLOW}[*] 检测XSS漏洞...{Style.RESET_ALL}")
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)"
            ]
            
            # 检查URL参数和表单
            try:
                response = requests.get(self.target, headers=self.headers, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 检查表单
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    if not action.startswith('http'):
                        action = urljoin(self.target, action)
                    
                    for payload in xss_payloads:
                        data = {}
                        for input_tag in form.find_all(['input', 'textarea']):
                            input_name = input_tag.get('name')
                            if input_name:
                                data[input_name] = payload
                        
                        try:
                            if form.get('method', '').lower() == 'post':
                                response = requests.post(action, data=data, headers=self.headers, verify=False)
                            else:
                                response = requests.get(action, params=data, headers=self.headers, verify=False)
                                
                            if payload in response.text:
                                print(f"{Fore.RED}[!] 可能存在XSS漏洞: {action}{Style.RESET_ALL}")
                                self.results['vulnerabilities'].append({
                                    'type': 'XSS',
                                    'url': action,
                                    'payload': payload,
                                    'severity': '中危'
                                })
                        except:
                            continue
            except:
                pass

            # 3. 目录遍历检测
            print(f"{Fore.YELLOW}[*] 检测目录遍历漏洞...{Style.RESET_ALL}")
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd"
            ]
            
            for payload in traversal_payloads:
                test_url = urljoin(self.target, payload)
                try:
                    response = requests.get(test_url, headers=self.headers, verify=False, timeout=10)
                    if any(keyword in response.text.lower() for keyword in ['root:', 'bin:', '[extensions]']):
                        print(f"{Fore.RED}[!] 可能存在目录遍历漏洞: {test_url}{Style.RESET_ALL}")
                        self.results['vulnerabilities'].append({
                            'type': '目录遍历',
                            'url': test_url,
                            'payload': payload,
                            'severity': '高危'
                        })
                except:
                    continue

            # 4. 敏感文件检测
            print(f"{Fore.YELLOW}[*] 检测敏感文件...{Style.RESET_ALL}")
            sensitive_files = [
                "robots.txt",
                ".git/config",
                ".svn/entries",
                ".env",
                "wp-config.php.bak",
                "config.php.bak",
                ".htaccess",
                "web.config",
                "phpinfo.php"
            ]
            
            for file in sensitive_files:
                test_url = urljoin(self.target, file)
                try:
                    response = requests.get(test_url, headers=self.headers, verify=False, timeout=10)
                    if response.status_code == 200:
                        print(f"{Fore.RED}[!] 发现敏感文件: {test_url}{Style.RESET_ALL}")
                        self.results['vulnerabilities'].append({
                            'type': '敏感文件泄露',
                            'url': test_url,
                            'description': f'发现敏感文件: {file}',
                            'severity': '中危'
                        })
                except:
                    continue

            # 5. CORS配置检测
            print(f"{Fore.YELLOW}[*] 检测CORS配置...{Style.RESET_ALL}")
            try:
                headers = {
                    **self.headers,
                    'Origin': 'https://evil.com'
                }
                response = requests.get(self.target, headers=headers, verify=False)
                acao = response.headers.get('Access-Control-Allow-Origin')
                if acao == '*' or acao == 'https://evil.com':
                    print(f"{Fore.RED}[!] 发现CORS配置不当{Style.RESET_ALL}")
                    self.results['vulnerabilities'].append({
                        'type': 'CORS配置不当',
                        'url': self.target,
                        'description': f'Access-Control-Allow-Origin: {acao}',
                        'severity': '中危'
                    })
            except:
                pass

            # 总结扫描结果
            vuln_count = len(self.results['vulnerabilities'])
            if vuln_count > 0:
                print(f"\n{Fore.RED}[!] 共发现 {vuln_count} 个潜在漏洞{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[+] 未发现明显漏洞{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] 漏洞扫描出错: {str(e)}{Style.RESET_ALL}")
            return False
        
        return True

    def save_results(self):
        """保存扫描结果"""
        try:
            if not self.output:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                self.output = f"scan_report_{timestamp}.md"
            
            with open(self.output, 'w', encoding='utf-8') as f:
                f.write("# 自动化渗透测试报告\n\n")
                f.write("## 目标信息\n")
                f.write(f"- 目标: {self.target}\n")
                f.write(f"- 扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- 扫描模式: {self.mode}\n\n")
                
                # 基本信息
                if 'basic_info' in self.results:
                    f.write("## 基本信息\n")
                    basic_info = self.results['basic_info']
                    if 'server' in basic_info:
                        f.write(f"- 服务器: {basic_info['server']}\n")
                    if 'tech_stack' in basic_info:
                        f.write(f"- 技术栈: {', '.join(basic_info['tech_stack'])}\n")
                    if 'cms' in basic_info:
                        f.write(f"- CMS系统: {basic_info['cms']}\n")
                    if 'frameworks' in basic_info:
                        f.write(f"- Web框架: {', '.join(basic_info['frameworks'])}\n")
                    f.write("\n")
                
                # 端口扫描结果
                if 'ports' in self.results:
                    f.write("## 端口扫描结果\n")
                    for port_info in self.results['ports']:
                        f.write(f"- 端口 {port_info['port']}/{port_info['protocol']}: {port_info['state']}\n")
                        f.write(f"  - 服务: {port_info['service']}\n")
                        if port_info['version']:
                            f.write(f"  - 版本: {port_info['version']}\n")
                    f.write("\n")
                
                # UDP端口
                if 'udp_ports' in self.results:
                    f.write("## UDP端口扫描结果\n")
                    for port_info in self.results['udp_ports']:
                        f.write(f"- 端口 {port_info['port']}/udp\n")
                        f.write(f"  - 服务: {port_info['service']}\n")
                    f.write("\n")
                
                # 漏洞信息
                if 'vulnerabilities' in self.results:
                    f.write("## 发现的漏洞\n")
                    for vuln in self.results['vulnerabilities']:
                        f.write(f"### {vuln.get('type', '未知类型')}\n")
                        if 'description' in vuln:
                            f.write(f"- 描述: {vuln['description']}\n")
                        if 'severity' in vuln:
                            f.write(f"- 严重程度: {vuln['severity']}\n")
                        if 'solution' in vuln:
                            f.write(f"- 修复建议: {vuln['solution']}\n")
                        f.write("\n")
            
            print(f"{Fore.GREEN}[+] 扫描报告已保存到: {self.output}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] 保存报告失败: {str(e)}{Style.RESET_ALL}")
            return False
        
        return True

def main():
    parser = argparse.ArgumentParser(description='AutoPen - 自动化渗透测试工具')
    parser.add_argument('-t', '--target', required=True, help='目标URL')
    parser.add_argument('-p', '--ports', default='1-1000', help='端口范围 (默认: 1-1000)')
    parser.add_argument('-m', '--mode', 
                       choices=['port', 'dir', 'info', 'subdomain', 'waf', 'vuln', 'all'], 
                       default='all', help='扫描模式')
    parser.add_argument('-o', '--output', help='输出文件路径')
    
    args = parser.parse_args()
    
    try:
        scanner = AutoPen()
        scanner.run(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户中断扫描{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] 发生错误: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()