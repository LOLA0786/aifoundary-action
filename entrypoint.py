import os
import sys
import re
import json
import urllib.request

SCAN_PATTERNS = {
    "HARDCODED_PROMPT": re.compile(r'prompt\\s*=\\s*["\\\'].*["\\\']', re.IGNORECASE),
    "OPENAI_NO_GUARD": re.compile(r'openai\\.ChatCompletion\\.create', re.IGNORECASE),
    "LLM_DIRECT_EXEC": re.compile(r'(exec|eval)\\s*\\(', re.IGNORECASE),
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

def write_sarif(risks):
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AIFoundary Guardrail Scan",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    for path, findings in risks:
        for finding in findings:
            sarif["runs"][0]["results"].append({
                "ruleId": finding,
                "level": "warning",
                "message": {
                    "text": f"AI risk detected: {finding}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": path
                        }
                    }
                }]
            })

    with open("aifoundary.sarif", "w") as f:
        json.dump(sarif, f, indent=2)

def post_pr_comment(token, message):
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path or not token:
        return

    with open(event_path) as f:
        event = json.load(f)

    comments_url = event.get("pull_request", {}).get("comments_url")
    if not comments_url:
        return

    req = urllib.request.Request(
        comments_url,
        data=json.dumps({"body": message}).encode("utf-8"),
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json"
        }
    )
    urllib.request.urlopen(req)

def send_to_galani(endpoint, payload):
    if not endpoint:
        return

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)

def main():
    scan_path = os.getenv("INPUT_SCAN-PATH", ".")
    mode = os.getenv("INPUT_MODE", "warn").lower()
    enable_galani = os.getenv("INPUT_ENABLE-GALANI", "false").lower() == "true"
    galani_endpoint = os.getenv("INPUT_GALANI-ENDPOINT", "")
    github_token = os.getenv("INPUT_GITHUB-TOKEN", "")

    risks = []

    for root, _, files in os.walk(scan_path):
        for file in files:
            if file.endswith((".py", ".js", ".ts")):
                full_path = os.path.join(root, file)
                findings = scan_file(full_path)
                if findings:
                    risks.append((full_path, findings))

    if risks:
        write_sarif(risks)

        summary = ["🚨 **AI Risk Detected by AIFoundary**"]
        for path, findings in risks:
            summary.append(f"- `{path}` → {', '.join(findings)}")
        summary.append("\nWhy this matters: AI execution errors are irreversible.")
        summary.append("Consider adding guardrails or switching to enforce mode.")

        post_pr_comment(github_token, "\n".join(summary))

        if enable_galani:
            send_to_galani(galani_endpoint, {
                "repo": os.getenv("GITHUB_REPOSITORY"),
                "risks": risks,
                "mode": mode
            })

        if mode == "enforce":
            sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
