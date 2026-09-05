#!/usr/bin/env python3
"""Template Engine - Phase C.3"""
import sys, os, json, yaml
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class TemplateEngine:
    def __init__(self, templates_dir="templates/custom"):
        self.templates_dir = templates_dir
        Path(templates_dir).mkdir(parents=True, exist_ok=True)
    
    def create_template(self, name, finding_type, pattern):
        template = {
            "id": f"custom-{name}",
            "info": {"name": name, "severity": "medium"},
            "http": [{"method": "GET", "path": ["{{BaseURL}}"], "matchers": [{"type": "word", "words": [pattern]}]}]
        }
        with open(f"{self.templates_dir}/{name}.yaml", "w") as f:
            yaml.dump(template, f)
        return f"{self.templates_dir}/{name}.yaml"
    
    def run(self, findings=None):
        print("Template Engine")
        return []

if __name__ == "__main__":
    TemplateEngine().run()
