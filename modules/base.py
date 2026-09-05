"""
Shared base module for standardized output and common utilities.
All modules must use this for consistent JSON output format.
"""
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional

class Finding:
    """Standardized finding format"""
    
    def __init__(
        self,
        title: str,
        severity: str,  # critical, high, medium, low, info
        category: str,
        target: str,
        description: str,
        evidence: Optional[str] = None,
        impact: Optional[str] = None,
        remediation: Optional[str] = None,
        confidence: str = "high",  # high, medium, low
        source: str = "unknown",
        cwe: Optional[str] = None,
        cvss: Optional[float] = None,
        metadata: Optional[Dict] = None
    ):
        self.id = self._generate_id(target, title, category)
        self.title = title
        self.severity = severity.lower()
        self.category = category
        self.target = target
        self.description = description
        self.evidence = evidence
        self.impact = impact
        self.remediation = remediation
        self.confidence = confidence
        self.source = source
        self.cwe = cwe
        self.cvss = cvss
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()
        self.verified = False
    
    def _generate_id(self, target: str, title: str, category: str) -> str:
        """Generate unique finding ID"""
        data = f"{target}:{title}:{category}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        """Convert to standardized dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "source": self.source,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "verified": self.verified
        }

class ResultWriter:
    """Unified result writer for all modules"""
    
    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }
    
    def __init__(self, output_dir: str, module_name: str):
        self.output_dir = output_dir
        self.module_name = module_name
        self.findings: List[Finding] = []
        
        import os
        from pathlib import Path
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the result set"""
        self.findings.append(finding)
    
    def save(self) -> str:
        """Save findings to standardized JSON file"""
        # Sort by severity
        self.findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity, 5))
        
        output = {
            "module": self.module_name,
            "generated_at": datetime.utcnow().isoformat(),
            "total_findings": len(self.findings),
            "summary": self._generate_summary(),
            "findings": [f.to_dict() for f in self.findings]
        }
        
        filename = f"{self.output_dir}/{self.module_name}.json"
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] {self.module_name}: {len(self.findings)} findings saved to {filename}")
        return filename
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            "by_severity": {},
            "by_category": {},
            "by_confidence": {}
        }
        
        for f in self.findings:
            summary["by_severity"][f.severity] = summary["by_severity"].get(f.severity, 0) + 1
            summary["by_category"][f.category] = summary["by_category"].get(f.category, 0) + 1
            summary["by_confidence"][f.confidence] = summary["by_confidence"].get(f.confidence, 0) + 1
        
        return summary

def load_config(config_name: str) -> Dict:
    """Load configuration from YAML file"""
    import yaml
    import os
    
    config_paths = [
        f"config/{config_name}.yml",
        f"config/{config_name}.yaml",
        f"config/{config_name}.json"
    ]
    
    for path in config_paths:
        if os.path.exists(path):
            with open(path) as f:
                if path.endswith(".json"):
                    return json.load(f)
                else:
                    return yaml.safe_load(f)
    
    return {}
