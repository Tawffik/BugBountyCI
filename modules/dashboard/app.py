#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
import json
from pathlib import Path

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/findings")
def api_findings():
    findings = []
    for json_file in Path("results").rglob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
                findings.extend(data.get("findings", []))
        except:
            pass
    return jsonify(findings)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
