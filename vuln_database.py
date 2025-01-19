import json
import os
from dataclasses import dataclass
from typing import List, Dict, Optional
import difflib

@dataclass
class Vulnerability:
    id: str
    name: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    type: str
    subtype: Optional[str]
    cve: Optional[str]
    payloads: List[str]
    patterns: List[str]
    remediation: str
    references: List[str]

class VulnDatabase:
    def __init__(self, db_path: str = "database/vulns.json"):
        self.db_path = db_path
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self._load_database()

    def _load_database(self):
        """从JSON文件加载漏洞库"""
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for vuln_id, vuln_data in data.items():
                    self.vulnerabilities[vuln_id] = Vulnerability(**vuln_data)

    def save_database(self):
        """保存漏洞库到JSON文件"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump({k: vars(v) for k, v in self.vulnerabilities.items()}, 
                     f, indent=4, ensure_ascii=False)

    def add_vulnerability(self, vulnerability: Vulnerability):
        """添加新的漏洞"""
        self.vulnerabilities[vulnerability.id] = vulnerability
        self.save_database()

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """根据ID获取漏洞信息"""
        return self.vulnerabilities.get(vuln_id)

    def find_similar_vulnerabilities(self, description: str, threshold: float = 0.8) -> List[Vulnerability]:
        """查找相似的漏洞"""
        similar_vulns = []
        for vuln in self.vulnerabilities.values():
            similarity = difflib.SequenceMatcher(None, description.lower(), 
                                               vuln.description.lower()).ratio()
            if similarity >= threshold:
                similar_vulns.append(vuln)
        return similar_vulns

    def get_payloads(self, vuln_type: str, subtype: Optional[str] = None) -> List[Vulnerability]:
        """获取特定类型漏洞的Vulnerability对象列表"""
        vulns = []
        for vuln in self.vulnerabilities.values():
            if vuln.type == vuln_type and (subtype is None or vuln.subtype == subtype):
                vulns.append(vuln)
        return vulns

    def get_remediation(self, vuln_id: str) -> Optional[str]:
        """获取漏洞的修复建议"""
        vuln = self.get_vulnerability(vuln_id)
        return vuln.remediation if vuln else None

    def generate_report(self, vuln_ids: List[str]) -> str:
        """生成漏洞报告"""
        report = []
        report.append("# 漏洞分析报告")
        report.append("\n## 发现的漏洞")
        
        for vuln_id in vuln_ids:
            vuln = self.get_vulnerability(vuln_id)
            if vuln:
                report.append(f"\n### {vuln.name}")
                report.append(f"- 严重程度: {vuln.severity}")
                report.append(f"- 漏洞类型: {vuln.type}")
                if vuln.subtype:
                    report.append(f"- 子类型: {vuln.subtype}")
                report.append(f"- 描述: {vuln.description}")
                report.append(f"- 修复建议: {vuln.remediation}")
                if vuln.references:
                    report.append("- 参考链接:")
                    for ref in vuln.references:
                        report.append(f"  * {ref}")
        
        return "\n".join(report) 