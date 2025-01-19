# AutoPen - 自动化渗透测试工具 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Version](https://img.shields.io/badge/version-2.0-green.svg)
![Stars](https://img.shields.io/github/stars/yourusername/autopen?style=social)

## 📖 项目介绍

AutoPen是一款功能强大的自动化渗透测试工具，专为安全研究人员、渗透测试工程师和网络安全爱好者设计。它集成了多种高级安全测试功能，能够自动化完成信息收集、漏洞扫描、安全评估等任务，帮助用户快速发现目标系统中的潜在安全隐患。

### 🌟 特色优势

- 🚀 **高效自动化**: 自动完成繁琐的渗透测试流程
- 🎯 **精准检测**: 采用多种检测技术，提高漏洞发现率
- 📊 **专业报告**: 自动生成详细的安全评估报告
- 🔧 **易于使用**: 简单的命令行界面，快速上手
- 🔄 **持续更新**: 定期更新漏洞库和检测规则

## 🚀 核心功能

### 1. 信息收集
- 🔍 **端口扫描**
  - TCP/UDP端口检测
  - 服务版本识别
  - 快速扫描模式
  - 自定义端口范围
  - 服务指纹识别

- 🌐 **Web应用分析**
  - Web服务器识别
  - Web应用框架检测
  - CMS系统识别
  - 网站目录扫描
  - WAF检测

### 2. 漏洞扫描
- 🎯 **Web漏洞检测**
  - SQL注入漏洞
  - XSS跨站脚本
  - 目录遍历漏洞
  - 文件包含漏洞
  - 命令注入漏洞
  - CORS配置错误
  
- 📁 **敏感信息检测**
  - 配置文件泄露
  - 备份文件扫描
  - 敏感目录探测
  - 版本控制文件
  - 开发调试文件

### 3. 安全评估
- 📊 **漏洞评估**
  - 风险等级划分
  - 威胁程度分析
  - 修复建议生成
  
- 📝 **报告生成**
  - markdown格式报告
  - 详细扫描结果
  - 漏洞复现步骤
  - 安全加固建议

## 🔧 环境要求

### 系统要求
- Python 3.8+
- 操作系统：Windows/Linux/MacOS
- 内存：≥4GB（推荐8GB以上）
- 磁盘空间：≥1GB

### 依赖工具
- Nmap：用于端口扫描
- Python依赖包：详见requirements.txt

## 📦 安装配置

### 1. 基础环境配置
```bash
# 安装Python 3.8+
# Windows: 从Python官网下载安装包
# Linux:
sudo apt update
sudo apt install python3 python3-pip python3-venv

# 安装Nmap
# Windows: 从Nmap官网下载安装包
# Linux:
sudo apt install nmap
```

### 2. 项目安装
```bash
# 克隆项目
git clone https://github.com/yourusername/autopen.git
cd autopen

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/MacOS:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

## 🚀 使用指南

### 基本用法
```bash
python autopen.py -t <target> -m <mode> -p <ports> -o <output>
```

### 参数说明
- `-t, --target`：目标URL（必需）
- `-m, --mode`：扫描模式
  - `all`: 完整扫描
  - `port`: 端口扫描
  - `dir`: 目录扫描
  - `info`: 信息收集
  - `subdomain`: 子域名枚举
  - `waf`: WAF检测
  - `vuln`: 漏洞扫描
- `-p, --ports`：端口范围（默认1-1000）
- `-o, --output`：报告输出路径

### 使用示例
```bash
# 完整扫描示例
python autopen.py -t example.com -m all

# 自定义端口扫描
python autopen.py -t example.com -m port -p 1-65535

# 仅进行漏洞扫描
python autopen.py -t example.com -m vuln

# 指定输出报告路径
python autopen.py -t example.com -o report.md
```

## 📝 扫描报告

### 报告内容
- 扫描概述
  - 目标信息
  - 扫描时间
  - 扫描范围
  - 扫描模式
  
- 详细结果
  - 端口扫描结果
  - 服务识别结果
  - 发现的漏洞
  - 风险等级评估
  
- 安全建议
  - 漏洞修复方案
  - 安全加固建议
  - 最佳实践推荐

## ⚠️ 免责声明

1. 本工具仅供安全研究和授权测试使用
2. 使用本工具进行未授权测试属于非法行为
3. 用户需自行承担使用本工具的所有风险和法律责任
4. 开发者不对任何非法使用导致的后果负责

## 🤝 参与贡献

### 贡献方式
1. Fork本项目
2. 创建新特性分支
3. 提交代码更改
4. 发起Pull Request

### 贡献要求
- 遵循Python PEP 8编码规范
- 添加必要的注释和文档
- 确保所有测试用例通过
- 更新相关文档说明

## 📄 开源协议

本项目采用MIT协议开源，详见 [LICENSE](LICENSE) 文件。

## 📞 联系方式

- 作者：Your Name
- 邮箱：your.email@example.com
- 项目地址：https://github.com/yourusername/autopen
- 问题反馈：https://github.com/yourusername/autopen/issues

## 🌟 致谢

感谢以下开源项目和工具：
- Nmap
- Python Requests
- BeautifulSoup4
- 以及其他所有贡献者

---
**注意**：使用本工具前，请确保已仔细阅读使用说明和免责声明。 