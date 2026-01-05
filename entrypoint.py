import os
import sys
import re

SCAN_PATTERNS = {
    "HARDCODED_PROMPT": re.compile(r'prompt\s*=\s*["\'].*["\']', re.IGNORECASE),
    "OPENAI_NO_GUARD": re.compile(r'openai\.ChatCompletion\.create', re.IGNORECASE),
    "LLM_DIRECT_EXEC": re.compile(r'(exec|eval)\s*\(', re.IGNORECASE),
}

def scan_file(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for name, pattern in SCAN_PATTERNS.items():
                if pattern.search(content):
                    findings.append(name)
    except Exception:
        pass
    return findings

def main():
    scan_path = os.getenv("INPUT_SCAN-PATH", ".")

    print(f"🔍 AIFoundary scanning: {scan_path}")

    risks = []

    for root, _, files in os.walk(scan_path):
        for file in files:
            if file.endswith((".py", ".js", ".ts")):
                full_path = os.path.join(root, file)
                findings = scan_file(full_path)
                if findings:
                    risks.append((full_path, findings))

    if risks:
        print("\n🚨 AI RISK DETECTED")
        for path, findings in risks:
            print(f"- {path}: {', '.join(findings)}")

        print("\n❌ Build failed due to unsafe AI patterns.")
        sys.exit(1)

    print("✅ No AI guardrail violations found.")
    sys.exit(0)

if __name__ == "__main__":
    main()
