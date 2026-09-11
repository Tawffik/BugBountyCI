#!/usr/bin/env python3
"""Add findomain as optional passive subdomain source (soft-fail).

Does not touch uro/asnmap/cariddi. Auto-merges via subdomains/*.txt glob.
"""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

if "findomain" in c and "subdomains/findomain.txt" in c:
    print("findomain already present")
    raise SystemExit(0)

# 1) install after assetfinder line
install_marker = (
    "          install_if_missing assetfinder go install github.com/tomnomnom/assetfinder@v0.1.1\n"
)
install_add = install_marker + (
    "          # findomain: passive CT/OSINT (optional binary; never fails the step)\n"
    "          if ! command -v findomain >/dev/null 2>&1; then\n"
    "            curl -sL --max-time 40 -o /tmp/findomain.zip \"https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip\" 2>>\"$RD/logs/tool_install.log\" || true\n"
    "            if [ -s /tmp/findomain.zip ]; then\n"
    "              unzip -qo /tmp/findomain.zip -d /tmp/findomain_bin 2>>\"$RD/logs/tool_install.log\" || true\n"
    "              FIND_BIN=$(find /tmp/findomain_bin -type f -name findomain 2>/dev/null | head -1)\n"
    "              if [ -n \"$FIND_BIN\" ]; then\n"
    "                sudo install -m 755 \"$FIND_BIN\" /usr/local/bin/findomain 2>>\"$RD/logs/tool_install.log\" ||\n"
    "                  install -m 755 \"$FIND_BIN\" \"$HOME/go/bin/findomain\" 2>>\"$RD/logs/tool_install.log\" || true\n"
    "                export PATH=\"$HOME/go/bin:$PATH\"\n"
    "              fi\n"
    "            fi\n"
    "          fi\n"
)

# Install step uses tool_install.log but RD may not exist yet at install time.
# Use logs path relative to workspace instead during install.
install_add = install_marker + (
    "          # findomain: passive CT/OSINT (optional; soft-fail)\n"
    "          if ! command -v findomain >/dev/null 2>&1; then\n"
    "            mkdir -p logs\n"
    "            curl -sL --max-time 40 -o /tmp/findomain.zip \"https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip\" 2>>logs/tool_install.log || true\n"
    "            if [ -s /tmp/findomain.zip ]; then\n"
    "              unzip -qo /tmp/findomain.zip -d /tmp/findomain_bin 2>>logs/tool_install.log || true\n"
    "              FIND_BIN=$(find /tmp/findomain_bin -type f -name findomain 2>/dev/null | head -1)\n"
    "              if [ -n \"$FIND_BIN\" ]; then\n"
    "                (sudo install -m 755 \"$FIND_BIN\" /usr/local/bin/findomain || install -m 755 \"$FIND_BIN\" \"$HOME/go/bin/findomain\") 2>>logs/tool_install.log || true\n"
    "                export PATH=\"$HOME/go/bin:$PATH\"\n"
    "              fi\n"
    "            fi\n"
    "          fi\n"
)

if install_marker not in c:
    raise SystemExit("install marker not found")
c = c.replace(install_marker, install_add, 1)
print("OK: findomain install")

# 2) run after crt.sh block
run_marker = (
    '          echo "🔍 crt.sh..."\n'
    '          curl -s --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r \'.[].name_value\' 2>/dev/null | tr \',\' \'\n\' | sed \'s/^\\*\.//\' | sort -u > "$RD/subdomains/crtsh.txt" 2>/dev/null || true\n'
)
# Exact from file without over-escaping
run_marker = (
    "          echo \"🔍 crt.sh...\"\n"
    "          curl -s --max-time 30 \"https://crt.sh/?q=%25.${TARGET}&output=json\" | jq -r '.[].name_value' 2>/dev/null | tr ',' '\\n' | sed 's/^\\*\\.//' | sort -u > \"$RD/subdomains/crtsh.txt\" 2>/dev/null || true\n"
)
run_add = run_marker + (
    "          echo \"🔍 Findomain (passive)...\"\n"
    "          : > \"$RD/subdomains/findomain.txt\"\n"
    "          if command -v findomain >/dev/null 2>&1; then\n"
    "            timeout 120 findomain -t \"$TARGET\" -q -u \"$RD/subdomains/findomain.txt\" 2>>\"$RD/logs/findomain.log\" || true\n"
    "          else\n"
    "            echo \"⚠️ findomain not installed - skipping\"\n"
    "          fi\n"
    "          echo \"ℹ️ findomain: $(wc -l < \\\"$RD/subdomains/findomain.txt\\\" 2>/dev/null || echo 0)\"\n"
)

# Fix the echo line escaping - write carefully
run_add = (
    run_marker
    + '          echo "🔍 Findomain (passive)..."\n'
    + '          : > "$RD/subdomains/findomain.txt"\n'
    + '          if command -v findomain >/dev/null 2>&1; then\n'
    + '            timeout 120 findomain -t "$TARGET" -q -u "$RD/subdomains/findomain.txt" 2>>"$RD/logs/findomain.log" || true\n'
    + '          else\n'
    + '            echo "⚠️ findomain not installed - skipping"\n'
    + '          fi\n'
    + '          echo "ℹ️ findomain: $(wc -l < "$RD/subdomains/findomain.txt" 2>/dev/null || echo 0)"\n'
)

if run_marker not in c:
    # debug: find crt.sh line
    idx = c.find('echo "🔍 crt.sh')
    print("crt idx", idx)
    print(repr(c[idx:idx+200]) if idx >= 0 else "not found")
    raise SystemExit("run marker not found")
c = c.replace(run_marker, run_add, 1)
print("OK: findomain run")

yaml.safe_load(c)
p.write_text(c)
print("DONE lines", len(c.splitlines()))
